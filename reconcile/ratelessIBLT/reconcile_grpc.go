package ratelessIBLT

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	reconpb_riblt "github.com/eika123/ifrit/reconcile/ratelessIBLT/proto"
	"github.com/eika123/ifrit/reconcile/transfer"
	transferpb "github.com/eika123/ifrit/reconcile/transfer/proto"
	"github.com/yangl1996/riblt"
	"google.golang.org/grpc"
)

var (
	ErrFramingViolation      = transfer.ErrFramingViolation
	ErrUnexpectedDigest      = transfer.ErrUnexpectedDigest
	ErrUnexpectedSyncFrame   = transfer.ErrUnexpectedSyncFrame
	ErrItemSizeLimitExceeded = transfer.ErrItemSizeLimitExceeded
)

type digestSymbol = digestmaps.DigestSymbol

// Type aliases preserving ratelessIBLT API compatibility while implementing reconcile.StoreReconciler.
type (
	ItemCodec[T any]      = reconcile.ItemCodec[T]
	ReconcileSummary      = reconcile.Summary
	ConnProvider          = reconcile.ConnProvider
	PeerAuthenticator     = reconcile.PeerAuthenticator
	ItemApplier[T any]    = reconcile.ItemApplier[T]
	TamperDetector[T any] = reconcile.TamperDetector[T]
	Config[T any]         = reconcile.Config[T]
)

// Reconciler implements the two-phase RIBLT + shared ItemTransfer Sync service for a Store[T, digestSymbol].
type Reconciler[T any] struct {
	reconpb_riblt.UnimplementedReconcilerServer
	store           *Store[T, digestSymbol]
	syncer          *transfer.PeerSyncer[T]
	auth            PeerAuthenticator
	detector        TamperDetector[T]
	symbolBatchSize int
	timeout         time.Duration
	sessionSeq      atomic.Uint64
}

// NewReconciler constructs a Reconciler wrapping store with the provided configuration.
func NewReconciler[T any](store *Store[T, digestSymbol], cfg Config[T]) *Reconciler[T] {
	detector := cfg.Detector
	if detector == nil {
		detector = reconcile.NoopTamperDetector[T]{}
	}
	batchSize := cfg.SymbolBatchSize
	if batchSize <= 0 {
		batchSize = DefaultSymbolBatchSize
	}
	return &Reconciler[T]{
		store:           store,
		syncer:          transfer.NewPeerSyncer(store, cfg),
		auth:            cfg.Auth,
		detector:        detector,
		symbolBatchSize: batchSize,
		timeout:         cfg.Timeout,
	}
}

// SyncHandler returns the Phase 2 ItemTransferServer for this Reconciler.
func (r *Reconciler[T]) SyncHandler() transferpb.ItemTransferServer {
	return r.syncer
}

// ReconcilerMux multiplexes incoming Phase 1 ReconcileDigests and Phase 2 ItemTransfer.Sync
// streams across multiple stores using the "store-id" gRPC metadata key.
type ReconcilerMux struct {
	reconpb_riblt.UnimplementedReconcilerServer
	phase1   *transfer.StoreMux[reconpb_riblt.ReconcilerServer]
	transfer *transfer.ItemTransferMux
	guard    transfer.StreamGuard
}

// NewReconcilerMux creates a store-routing ReconcilerMux with an optional StreamGuard.
func NewReconcilerMux(guard ...transfer.StreamGuard) *ReconcilerMux {
	var g transfer.StreamGuard
	if len(guard) > 0 {
		g = guard[0]
	}
	return &ReconcilerMux{
		phase1:   transfer.NewStoreMux[reconpb_riblt.ReconcilerServer](),
		transfer: transfer.NewItemTransferMux(g),
		guard:    g,
	}
}

// RegisterStore binds storeID to handler (supporting *Reconciler[T] or any ReconcilerServer).
func (m *ReconcilerMux) RegisterStore(storeID string, handler any) {
	if h1, ok := handler.(reconpb_riblt.ReconcilerServer); ok {
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

// RegisterGRPC registers both Phase 1 Reconciler and Phase 2 ItemTransfer services on s.
func (m *ReconcilerMux) RegisterGRPC(s *grpc.Server) {
	reconpb_riblt.RegisterReconcilerServer(s, m)
	transferpb.RegisterItemTransferServer(s, m.transfer)
}

// ReconcileDigests routes the Phase 1 stream to the handler matching "store-id".
func (m *ReconcilerMux) ReconcileDigests(stream reconpb_riblt.Reconciler_ReconcileDigestsServer) error {
	h, err := m.phase1.Resolve(stream.Context())
	if err != nil {
		return err
	}
	if m.guard != nil {
		return m.guard(stream.Context(), func() error {
			return h.ReconcileDigests(stream)
		})
	}
	return h.ReconcileDigests(stream)
}

// --- Phase 1: gRPC transport adapters over ReconcileClient / ReconcileServer ---

type grpcReconcileClientTransport struct {
	stream reconpb_riblt.Reconciler_ReconcileDigestsClient
}

func (t grpcReconcileClientTransport) SendCoded(batch []riblt.CodedSymbol[digestSymbol]) error {
	pb := make([]*reconpb_riblt.CodedSymbol, len(batch))
	for i, cs := range batch {
		pb[i] = &reconpb_riblt.CodedSymbol{
			HashedSymbol: encodeHashedSymbol(cs.HashedSymbol),
			Count:        cs.Count,
		}
	}
	return t.stream.Send(&reconpb_riblt.ReconcileRequest{Symbols: pb})
}

func (t grpcReconcileClientTransport) RecvResponse() (bool, []digestSymbol, []digestSymbol, []byte, bool, error) {
	resp, err := t.stream.Recv()
	if err == io.EOF {
		return false, nil, nil, nil, true, nil
	}
	if err != nil {
		return false, nil, nil, nil, false, err
	}
	req, err := digestmaps.DecodeSymbols(resp.RequestedDigests, digestmaps.DecodeDigestSymbol)
	if err != nil {
		return false, nil, nil, nil, false, err
	}
	avail, err := digestmaps.DecodeSymbols(resp.AvailableDigests, digestmaps.DecodeDigestSymbol)
	if err != nil {
		return false, nil, nil, nil, false, err
	}
	return resp.Decoded, req, avail, resp.GetFingerprint(), false, nil
}

func (t grpcReconcileClientTransport) CloseSend() error {
	return t.stream.CloseSend()
}

type grpcReconcileServerTransport struct {
	stream       reconpb_riblt.Reconciler_ReconcileDigestsServer
	fingerprint  func() []byte
	onRequestSet func(req []riblt.HashedSymbol[digestSymbol])
}

func (t grpcReconcileServerTransport) RecvCoded() ([]riblt.CodedSymbol[digestSymbol], bool, error) {
	req, err := t.stream.Recv()
	if err == io.EOF {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	syms, err := digestmaps.DecodeCodedSymbols(req.Symbols, digestmaps.DecodeDigestSymbol)
	if err != nil {
		return nil, false, err
	}
	return syms, false, nil
}

func (t grpcReconcileServerTransport) SendNeedMore() error {
	return t.stream.Send(&reconpb_riblt.ReconcileResponse{Decoded: false})
}

func (t grpcReconcileServerTransport) SendDiffPage(req, avail []riblt.HashedSymbol[digestSymbol]) error {
	if t.onRequestSet != nil && len(req) > 0 {
		t.onRequestSet(req)
	}
	var fp []byte
	if t.fingerprint != nil {
		fp = t.fingerprint()
	}
	return t.stream.Send(&reconpb_riblt.ReconcileResponse{
		Decoded:          true,
		RequestedDigests: encodeHashedSymbols(req),
		AvailableDigests: encodeHashedSymbols(avail),
		Fingerprint:      fp,
	})
}

func (r *Reconciler[T]) reconcileDigestsWithPeer(
	ctx context.Context,
	addr string,
	sessionID string,
) (ReconcileDiff[digestSymbol], error) {
	cc, closeFn, err := r.syncer.ConnFor(ctx, addr)
	if err != nil {
		return ReconcileDiff[digestSymbol]{}, err
	}
	defer closeFn()

	ctx, cancel := context.WithCancel(r.syncer.OutgoingContext(ctx, sessionID))
	defer cancel()

	stream, err := reconpb_riblt.NewReconcilerClient(cc).ReconcileDigests(ctx)
	if err != nil {
		return ReconcileDiff[digestSymbol]{}, err
	}
	diff, err := ReconcileClient(grpcReconcileClientTransport{stream: stream}, r.store, r.symbolBatchSize)
	if err != nil {
		r.detector.OnMisbehavior(stream.Context(), err, nil)
	}
	return diff, err
}

// ReconcileDigests implements the Phase 1 gRPC server handler.
func (r *Reconciler[T]) ReconcileDigests(stream reconpb_riblt.Reconciler_ReconcileDigestsServer) error {
	if r.auth != nil {
		if err := r.auth(stream.Context()); err != nil {
			r.detector.OnMisbehavior(stream.Context(), err, nil)
			return err
		}
	}
	sessionID := transfer.SessionIDFromIncoming(stream.Context())
	var requested []digestSymbol
	tr := grpcReconcileServerTransport{
		stream: stream,
		fingerprint: func() []byte {
			return digestmaps.EncodeDigestSymbol(r.store.Fingerprint())
		},
		onRequestSet: func(req []riblt.HashedSymbol[digestSymbol]) {
			for _, hs := range req {
				requested = append(requested, hs.Symbol)
			}
		},
	}
	err := ReconcileServer(tr, r.store)
	if err != nil {
		r.syncer.PopExpected(sessionID)
		r.detector.OnMisbehavior(stream.Context(), err, nil)
		return err
	}
	if len(requested) > 0 {
		r.syncer.RecordExpected(sessionID, requested)
	}
	return nil
}

// ReconcileWithPeer runs Phase 1 (ReconcileDigests) and, if diffs exist, Phase 2 (ItemTransfer.Sync) against addr.
func (r *Reconciler[T]) ReconcileWithPeer(ctx context.Context, addr string) (ReconcileSummary, error) {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	summary := ReconcileSummary{Peer: addr}
	sessionID := fmt.Sprintf("rsess-%d", r.sessionSeq.Add(1))

	diff, err := r.reconcileDigestsWithPeer(ctx, addr, sessionID)
	if err != nil {
		return summary, fmt.Errorf("reconcile digests with %s: %w", addr, err)
	}

	summary.UsedFallback = diff.UsedFallback
	summary.DigestsRequested = len(diff.Requested)
	summary.DigestsAvailable = len(diff.Available)
	summary.RemoteFingerprint = diff.RemoteFingerprint
	if summary.DigestsRequested == 0 && summary.DigestsAvailable == 0 {
		return summary, nil
	}

	sent, received, remoteFP, err := r.syncer.SyncWithPeer(ctx, addr, sessionID, diff.Requested, diff.Available)
	summary.ItemsSent = sent
	summary.ItemsReceived = received
	if len(remoteFP) > 0 {
		summary.RemoteFingerprint = remoteFP
	}
	if err != nil {
		return summary, fmt.Errorf("sync with %s: %w", addr, err)
	}
	return summary, nil
}

func buildHashedSymProto(b []byte, h uint64) *reconpb_riblt.HashedSymbol {
	return &reconpb_riblt.HashedSymbol{Symbol: b, Hash: h}
}

func encodeHashedSymbol(sym riblt.HashedSymbol[digestSymbol]) *reconpb_riblt.HashedSymbol {
	return digestmaps.EncodeHashedSymbol(sym, digestmaps.EncodeDigestSymbol, buildHashedSymProto)
}

func encodeHashedSymbols(syms []riblt.HashedSymbol[digestSymbol]) []*reconpb_riblt.HashedSymbol {
	return digestmaps.EncodeHashedSymbols(syms, digestmaps.EncodeDigestSymbol, buildHashedSymProto)
}
