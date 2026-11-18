package naive

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	naivepb "github.com/eika123/ifrit/reconcile/naive/proto"
	"github.com/eika123/ifrit/reconcile/transfer"
	transferpb "github.com/eika123/ifrit/reconcile/transfer/proto"
	"google.golang.org/grpc"
)

const digestBatchSize = 32768

type digestSymbol = digestmaps.DigestSymbol

// Reconciler implements full-digest-exchange Phase 1 + shared ItemTransfer Phase 2.
type Reconciler[T any] struct {
	naivepb.UnimplementedNaiveReconcilerServer
	store      digestmaps.ReverseIndexStore[T, digestSymbol]
	syncer     *transfer.PeerSyncer[T]
	auth       reconcile.PeerAuthenticator
	detector   reconcile.TamperDetector[T]
	timeout    time.Duration
	sessionSeq atomic.Uint64
}

// NewReconciler constructs a naive Reconciler wrapping store with cfg.
func NewReconciler[T any](
	store digestmaps.ReverseIndexStore[T, digestSymbol],
	cfg reconcile.Config[T],
) *Reconciler[T] {
	detector := cfg.Detector
	if detector == nil {
		detector = reconcile.NoopTamperDetector[T]{}
	}
	return &Reconciler[T]{
		store:    store,
		syncer:   transfer.NewPeerSyncer(store, cfg),
		auth:     cfg.Auth,
		detector: detector,
		timeout:  cfg.Timeout,
	}
}

// SyncHandler returns the Phase 2 ItemTransferServer for this Reconciler.
func (r *Reconciler[T]) SyncHandler() transferpb.ItemTransferServer {
	return r.syncer
}

// ReconcilerMux multiplexes incoming Phase 1 ExchangeDigests and Phase 2 ItemTransfer.Sync
// streams across multiple stores using the "store-id" gRPC metadata key.
type ReconcilerMux struct {
	naivepb.UnimplementedNaiveReconcilerServer
	phase1   *transfer.StoreMux[naivepb.NaiveReconcilerServer]
	transfer *transfer.ItemTransferMux
	guard    transfer.StreamGuard
}

// NewReconcilerMux creates a store-routing naive ReconcilerMux with an optional StreamGuard.
func NewReconcilerMux(guard ...transfer.StreamGuard) *ReconcilerMux {
	var g transfer.StreamGuard
	if len(guard) > 0 {
		g = guard[0]
	}
	return &ReconcilerMux{
		phase1:   transfer.NewStoreMux[naivepb.NaiveReconcilerServer](),
		transfer: transfer.NewItemTransferMux(g),
		guard:    g,
	}
}

// RegisterStore binds storeID to handler.
func (m *ReconcilerMux) RegisterStore(storeID string, handler any) {
	if h1, ok := handler.(naivepb.NaiveReconcilerServer); ok {
		m.phase1.Register(storeID, h1)
	}
	if sp, ok := handler.(interface {
		SyncHandler() transferpb.ItemTransferServer
	}); ok {
		m.transfer.RegisterStore(storeID, sp.SyncHandler())
	} else if h2, ok := handler.(transferpb.ItemTransferServer); ok {
		m.transfer.RegisterStore(storeID, h2)
	}
}

// RegisterGRPC registers both Phase 1 NaiveReconciler and Phase 2 ItemTransfer services on s.
func (m *ReconcilerMux) RegisterGRPC(s *grpc.Server) {
	naivepb.RegisterNaiveReconcilerServer(s, m)
	transferpb.RegisterItemTransferServer(s, m.transfer)
}

// ExchangeDigests routes the Phase 1 stream to the handler matching "store-id".
func (m *ReconcilerMux) ExchangeDigests(stream naivepb.NaiveReconciler_ExchangeDigestsServer) error {
	h, err := m.phase1.Resolve(stream.Context())
	if err != nil {
		return err
	}
	if m.guard != nil {
		return m.guard(stream.Context(), func() error {
			return h.ExchangeDigests(stream)
		})
	}
	return h.ExchangeDigests(stream)
}

// ExchangeDigests implements the naive Phase 1 server handler.
func (r *Reconciler[T]) ExchangeDigests(stream naivepb.NaiveReconciler_ExchangeDigestsServer) error {
	ctx := stream.Context()
	if r.auth != nil {
		if err := r.auth(ctx); err != nil {
			r.detector.OnMisbehavior(ctx, err, nil)
			return err
		}
	}

	callerDigests := make(map[digestSymbol]struct{})
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			r.detector.OnMisbehavior(ctx, err, nil)
			return err
		}
		if batch == nil {
			continue
		}
		for _, raw := range batch.GetDigests() {
			d, decErr := digestmaps.DecodeDigestSymbol(raw)
			if decErr != nil {
				r.detector.OnMisbehavior(ctx, decErr, raw)
				return decErr
			}
			callerDigests[d] = struct{}{}
		}
	}

	localDigests := r.store.DigestsCopy()
	localSet := make(map[digestSymbol]struct{}, len(localDigests))
	for _, d := range localDigests {
		localSet[d] = struct{}{}
	}

	// A \ B: digests caller has that responder lacks (requested from caller)
	var requested []digestSymbol
	for d := range callerDigests {
		if _, ok := localSet[d]; !ok {
			requested = append(requested, d)
		}
	}

	// B \ A: digests responder has that caller lacks (available to caller)
	var available []digestSymbol
	for _, d := range localDigests {
		if _, ok := callerDigests[d]; !ok {
			available = append(available, d)
		}
	}

	sessionID := transfer.SessionIDFromIncoming(ctx)
	if len(requested) > 0 {
		r.syncer.RecordExpected(sessionID, requested)
	}

	fp := digestmaps.EncodeDigestSymbol(r.store.Fingerprint())
	if len(requested) == 0 && len(available) == 0 {
		return stream.Send(&naivepb.DigestDiffBatch{Fingerprint: fp})
	}

	maxLen := max(len(requested), len(available))
	for i := 0; i < maxLen; i += digestBatchSize {
		var reqEnc [][]byte
		if i < len(requested) {
			end := min(i+digestBatchSize, len(requested))
			reqEnc = make([][]byte, end-i)
			for j, d := range requested[i:end] {
				reqEnc[j] = digestmaps.EncodeDigestSymbol(d)
			}
		}
		var availEnc [][]byte
		if i < len(available) {
			end := min(i+digestBatchSize, len(available))
			availEnc = make([][]byte, end-i)
			for j, d := range available[i:end] {
				availEnc[j] = digestmaps.EncodeDigestSymbol(d)
			}
		}
		var batchFP []byte
		if i == 0 {
			batchFP = fp
		}
		if err := stream.Send(&naivepb.DigestDiffBatch{
			Fingerprint:      batchFP,
			RequestedDigests: reqEnc,
			AvailableDigests: availEnc,
		}); err != nil {
			r.syncer.PopExpected(sessionID)
			return err
		}
	}
	return nil
}

func (r *Reconciler[T]) exchangeDigestsWithPeer(
	ctx context.Context,
	addr string,
	sessionID string,
) (requested, available []digestSymbol, remoteFP []byte, err error) {
	cc, closeFn, err := r.syncer.ConnFor(ctx, addr)
	if err != nil {
		return nil, nil, nil, err
	}
	defer closeFn()

	ctx, cancel := context.WithCancel(r.syncer.OutgoingContext(ctx, sessionID))
	defer cancel()

	stream, err := naivepb.NewNaiveReconcilerClient(cc).ExchangeDigests(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	localDigests := r.store.DigestsCopy()
	fp := digestmaps.EncodeDigestSymbol(r.store.Fingerprint())

	if len(localDigests) == 0 {
		if err := stream.Send(&naivepb.DigestBatch{Fingerprint: fp}); err != nil {
			return nil, nil, nil, err
		}
	} else {
		for i := 0; i < len(localDigests); i += digestBatchSize {
			end := min(i+digestBatchSize, len(localDigests))
			enc := make([][]byte, end-i)
			for j, d := range localDigests[i:end] {
				enc[j] = digestmaps.EncodeDigestSymbol(d)
			}
			var batchFP []byte
			if i == 0 {
				batchFP = fp
			}
			if err := stream.Send(&naivepb.DigestBatch{
				Fingerprint: batchFP,
				Digests:     enc,
			}); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	if err := stream.CloseSend(); err != nil {
		return nil, nil, nil, err
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			r.detector.OnMisbehavior(ctx, err, nil)
			return nil, nil, nil, err
		}
		if resp == nil {
			continue
		}
		if len(resp.GetFingerprint()) > 0 {
			remoteFP = resp.GetFingerprint()
		}
		for _, raw := range resp.GetRequestedDigests() {
			d, decErr := digestmaps.DecodeDigestSymbol(raw)
			if decErr != nil {
				r.detector.OnMisbehavior(ctx, decErr, raw)
				return nil, nil, nil, decErr
			}
			requested = append(requested, d)
		}
		for _, raw := range resp.GetAvailableDigests() {
			d, decErr := digestmaps.DecodeDigestSymbol(raw)
			if decErr != nil {
				r.detector.OnMisbehavior(ctx, decErr, raw)
				return nil, nil, nil, decErr
			}
			available = append(available, d)
		}
	}

	return requested, available, remoteFP, nil
}

// ReconcileWithPeer runs Phase 1 (ExchangeDigests) and, if diffs exist, Phase 2 (ItemTransfer.Sync) against addr.
func (r *Reconciler[T]) ReconcileWithPeer(ctx context.Context, addr string) (reconcile.Summary, error) {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	summary := reconcile.Summary{Peer: addr}
	sessionID := fmt.Sprintf("nsess-%d", r.sessionSeq.Add(1))

	requested, available, remoteFP, err := r.exchangeDigestsWithPeer(ctx, addr, sessionID)
	if err != nil {
		return summary, fmt.Errorf("exchange digests with %s: %w", addr, err)
	}

	summary.DigestsRequested = len(requested)
	summary.DigestsAvailable = len(available)
	summary.RemoteFingerprint = remoteFP
	if summary.DigestsRequested == 0 && summary.DigestsAvailable == 0 {
		return summary, nil
	}

	sent, received, postFP, err := r.syncer.SyncWithPeer(ctx, addr, sessionID, requested, available)
	summary.ItemsSent = sent
	summary.ItemsReceived = received
	if len(postFP) > 0 {
		summary.RemoteFingerprint = postFP
	}
	if err != nil {
		return summary, fmt.Errorf("sync with %s: %w", addr, err)
	}
	return summary, nil
}
