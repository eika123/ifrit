package ratelessIBLT

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joonnna/ifrit/digestmaps"
	reconpb_riblt "github.com/joonnna/ifrit/reconcile/ratelessIBLT/proto"
	"github.com/yangl1996/riblt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	storeIDMetadataKey   = "store-id"
	sessionIDMetadataKey = "reconcile-session-id"
)

var (
	ErrFramingViolation      = errors.New("reconcile: stream framing violation")
	ErrUnexpectedDigest      = errors.New("reconcile: received unexpected digest not in allowlist")
	ErrUnexpectedSyncFrame   = errors.New("reconcile: received unexpected data frame when zero items expected")
	ErrItemSizeLimitExceeded = errors.New("reconcile: item size exceeds configured maximum")
)

// ItemCodec serializes and deserializes application items during Phase 2 Sync.
type ItemCodec[T any] interface {
	Encode(item T) ([]byte, error)
	Decode(data []byte) (T, error)
}

type jsonItemCodec[T any] struct{}

func (jsonItemCodec[T]) Encode(item T) ([]byte, error) {
	return json.Marshal(item)
}

func (jsonItemCodec[T]) Decode(data []byte) (T, error) {
	var item T
	err := json.Unmarshal(data, &item)
	return item, err
}

type ReconcileSummary struct {
	Peer             string `json:"peer"`
	DigestsRequested int    `json:"digests_requested"` // A \ B sent to peer
	DigestsAvailable int    `json:"digests_available"` // B \ A fetched from peer
	ItemsSent        int    `json:"items_sent"`
	ItemsReceived    int    `json:"items_received"`
	UsedFallback     bool   `json:"used_fallback"`
}

type digestSymbol = digestmaps.DigestSymbol

// ConnProvider returns a gRPC ClientConnInterface for the given peer address.
// Pooled connections returned by a ConnProvider are NOT closed by Reconciler.
type ConnProvider func(ctx context.Context, addr string) (grpc.ClientConnInterface, error)

// PeerAuthenticator validates an incoming gRPC stream context (e.g. mTLS cert / view admission).
type PeerAuthenticator func(ctx context.Context) error

// ItemApplier applies a decoded, validated item into local storage.
// When nil, Reconciler defaults to store.Insert(item).
type ItemApplier[T any] func(ctx context.Context, item T) error

// TamperDetector provides injectable Byzantine item validation and misbehavior reporting hooks.
type TamperDetector[T any] interface {
	ValidateItem(ctx context.Context, item T) error
	OnMisbehavior(ctx context.Context, err error, evidence []byte)
}

type noopTamperDetector[T any] struct{}

func (noopTamperDetector[T]) ValidateItem(context.Context, T) error        { return nil }
func (noopTamperDetector[T]) OnMisbehavior(context.Context, error, []byte) {}

// Config configures a Reconciler instance for a single Store.
type Config[T any] struct {
	Codec           ItemCodec[T]
	ConnProvider    ConnProvider
	Auth            PeerAuthenticator
	Detector        TamperDetector[T]
	Applier         ItemApplier[T]
	SymbolBatchSize int
	MaxItemBytes    int64
	Timeout         time.Duration
	StoreID         string
}

// Reconciler implements the two-phase RIBLT + gRPC Sync service for a Store[T, digestSymbol].
type Reconciler[T any] struct {
	reconpb_riblt.UnimplementedReconcilerServer
	store           *Store[T, digestSymbol]
	codec           ItemCodec[T]
	connProvider    ConnProvider
	auth            PeerAuthenticator
	detector        TamperDetector[T]
	applier         ItemApplier[T]
	symbolBatchSize int
	maxItemBytes    int64
	timeout         time.Duration
	storeID         string

	sessionSeq      atomic.Uint64
	pendingMu       sync.Mutex
	pendingExpected map[string]map[digestSymbol]struct{}
}

// NewReconciler constructs a Reconciler wrapping store with the provided configuration.
func NewReconciler[T any](store *Store[T, digestSymbol], cfg Config[T]) *Reconciler[T] {
	codec := cfg.Codec
	if codec == nil {
		codec = jsonItemCodec[T]{}
	}
	detector := cfg.Detector
	if detector == nil {
		detector = noopTamperDetector[T]{}
	}
	applier := cfg.Applier
	if applier == nil {
		applier = func(_ context.Context, item T) error {
			store.Insert(item)
			return nil
		}
	}
	batchSize := cfg.SymbolBatchSize
	if batchSize <= 0 {
		batchSize = DefaultSymbolBatchSize
	}

	return &Reconciler[T]{
		store:           store,
		codec:           codec,
		connProvider:    cfg.ConnProvider,
		auth:            cfg.Auth,
		detector:        detector,
		applier:         applier,
		symbolBatchSize: batchSize,
		maxItemBytes:    cfg.MaxItemBytes,
		timeout:         cfg.Timeout,
		storeID:         cfg.StoreID,
		pendingExpected: make(map[string]map[digestSymbol]struct{}),
	}
}

// ReconcilerMux multiplexes incoming ReconcileDigests and Sync streams across
// multiple stores using the "store-id" gRPC metadata key.
type ReconcilerMux struct {
	reconpb_riblt.UnimplementedReconcilerServer
	mu       sync.RWMutex
	handlers map[string]reconpb_riblt.ReconcilerServer
}

// NewReconcilerMux creates an empty store-routing ReconcilerMux.
func NewReconcilerMux() *ReconcilerMux {
	return &ReconcilerMux{
		handlers: make(map[string]reconpb_riblt.ReconcilerServer),
	}
}

// RegisterStore binds storeID to handler.
func (m *ReconcilerMux) RegisterStore(storeID string, handler reconpb_riblt.ReconcilerServer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[storeID] = handler
}

func (m *ReconcilerMux) resolve(ctx context.Context) (reconpb_riblt.ReconcilerServer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	md, hasMD := metadata.FromIncomingContext(ctx)
	var vals []string
	if hasMD {
		vals = md.Get(storeIDMetadataKey)
	}

	if len(vals) == 0 {
		if len(m.handlers) == 1 {
			for _, h := range m.handlers {
				return h, nil
			}
		}
		return nil, status.Error(codes.InvalidArgument, "missing store-id metadata")
	}
	if len(vals) > 1 || vals[0] == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid store-id metadata")
	}

	h, ok := m.handlers[vals[0]]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown store-id %q", vals[0])
	}
	return h, nil
}

// ReconcileDigests routes the Phase 1 stream to the handler matching "store-id".
func (m *ReconcilerMux) ReconcileDigests(stream reconpb_riblt.Reconciler_ReconcileDigestsServer) error {
	h, err := m.resolve(stream.Context())
	if err != nil {
		return err
	}
	return h.ReconcileDigests(stream)
}

// Sync routes the Phase 2 stream to the handler matching "store-id".
func (m *ReconcilerMux) Sync(stream reconpb_riblt.Reconciler_SyncServer) error {
	h, err := m.resolve(stream.Context())
	if err != nil {
		return err
	}
	return h.Sync(stream)
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

func (t grpcReconcileClientTransport) RecvResponse() (bool, []digestSymbol, []digestSymbol, bool, error) {
	resp, err := t.stream.Recv()
	if err == io.EOF {
		return false, nil, nil, true, nil
	}
	if err != nil {
		return false, nil, nil, false, err
	}
	req, err := digestmaps.DecodeSymbols(resp.RequestedDigests, digestmaps.DecodeDigestSymbol)
	if err != nil {
		return false, nil, nil, false, err
	}
	avail, err := digestmaps.DecodeSymbols(resp.AvailableDigests, digestmaps.DecodeDigestSymbol)
	if err != nil {
		return false, nil, nil, false, err
	}
	return resp.Decoded, req, avail, false, nil
}

func (t grpcReconcileClientTransport) CloseSend() error {
	return t.stream.CloseSend()
}

type grpcReconcileServerTransport struct {
	stream       reconpb_riblt.Reconciler_ReconcileDigestsServer
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
	return t.stream.Send(&reconpb_riblt.ReconcileResponse{
		Decoded:          true,
		RequestedDigests: encodeHashedSymbols(req),
		AvailableDigests: encodeHashedSymbols(avail),
	})
}

func (r *Reconciler[T]) connFor(ctx context.Context, addr string) (grpc.ClientConnInterface, func(), error) {
	if r.connProvider != nil {
		cc, err := r.connProvider(ctx, addr)
		return cc, func() {}, err
	}
	cc, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
	if err != nil {
		return nil, func() {}, err
	}
	return cc, func() { _ = cc.Close() }, nil
}

func (r *Reconciler[T]) outgoingCtx(ctx context.Context, sessionID string) context.Context {
	pairs := []string{sessionIDMetadataKey, sessionID}
	if r.storeID != "" {
		pairs = append(pairs, storeIDMetadataKey, r.storeID)
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

func sessionIDFromIncoming(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(sessionIDMetadataKey)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (r *Reconciler[T]) recordExpected(sessionID string, req []riblt.HashedSymbol[digestSymbol]) {
	if sessionID == "" || len(req) == 0 {
		return
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	set := r.pendingExpected[sessionID]
	if set == nil {
		set = make(map[digestSymbol]struct{}, len(req))
		r.pendingExpected[sessionID] = set
	}
	for _, hs := range req {
		set[hs.Symbol] = struct{}{}
	}
}

func (r *Reconciler[T]) popExpected(sessionID string) map[digestSymbol]struct{} {
	if sessionID == "" {
		return nil
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()

	set := r.pendingExpected[sessionID]
	delete(r.pendingExpected, sessionID)
	return set
}

func (r *Reconciler[T]) reconcileDigestsWithPeer(
	ctx context.Context,
	addr string,
	sessionID string,
) (ReconcileDiff[digestSymbol], error) {
	cc, closeFn, err := r.connFor(ctx, addr)
	if err != nil {
		return ReconcileDiff[digestSymbol]{}, err
	}
	defer closeFn()

	ctx, cancel := context.WithCancel(r.outgoingCtx(ctx, sessionID))
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
	sessionID := sessionIDFromIncoming(stream.Context())
	tr := grpcReconcileServerTransport{
		stream: stream,
		onRequestSet: func(req []riblt.HashedSymbol[digestSymbol]) {
			r.recordExpected(sessionID, req)
		},
	}
	err := ReconcileServer(tr, r.store)
	if err != nil {
		r.popExpected(sessionID)
		r.detector.OnMisbehavior(stream.Context(), err, nil)
	}
	return err
}

// ReconcileWithPeer runs Phase 1 (ReconcileDigests) and, if diffs exist, Phase 2 (Sync) against addr.
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
	if summary.DigestsRequested == 0 && summary.DigestsAvailable == 0 {
		return summary, nil
	}

	sent, received, err := r.syncWithPeer(ctx, addr, sessionID, diff.Requested, diff.Available)
	summary.ItemsSent = sent
	summary.ItemsReceived = received
	if err != nil {
		return summary, fmt.Errorf("sync with %s: %w", addr, err)
	}
	return summary, nil
}

// --- Phase 2: Bidirectional chunked item transfer ---

type syncStream interface {
	Context() context.Context
	Send(*reconpb_riblt.SyncFrame) error
	Recv() (*reconpb_riblt.SyncFrame, error)
}

func (r *Reconciler[T]) syncWithPeer(
	ctx context.Context,
	addr string,
	sessionID string,
	requested, available []digestSymbol,
) (sent, received int, err error) {
	cc, closeFn, err := r.connFor(ctx, addr)
	if err != nil {
		return 0, 0, err
	}
	defer closeFn()

	ctx, cancel := context.WithCancel(r.outgoingCtx(ctx, sessionID))
	defer cancel()

	stream, err := reconpb_riblt.NewReconcilerClient(cc).Sync(ctx)
	if err != nil {
		return 0, 0, err
	}

	expected := make(map[digestSymbol]struct{}, len(available))
	for _, d := range available {
		expected[d] = struct{}{}
	}

	type recvRes struct {
		count int
		err   error
	}
	recvCh := make(chan recvRes, 1)
	go func() {
		n, err := r.recvSyncFrames(stream, expected, nil)
		recvCh <- recvRes{count: n, err: err}
	}()

	const wantBatchSize = 32768
	for i := 0; i < len(available); i += wantBatchSize {
		end := min(i+wantBatchSize, len(available))
		want := make([][]byte, end-i)
		for j, d := range available[i:end] {
			want[j] = digestmaps.EncodeDigestSymbol(d)
		}
		if err := stream.Send(&reconpb_riblt.SyncFrame{
			Payload: &reconpb_riblt.SyncFrame_WantDigests{
				WantDigests: &reconpb_riblt.WantDigests{Digests: want},
			},
		}); err != nil {
			cancel()
			<-recvCh
			return 0, 0, err
		}
	}

	sent, err = r.sendSyncItems(stream, requested)
	if err != nil {
		cancel()
		<-recvCh
		return sent, 0, err
	}
	if err := stream.Send(&reconpb_riblt.SyncFrame{
		Payload: &reconpb_riblt.SyncFrame_Complete{
			Complete: &reconpb_riblt.SyncComplete{Fingerprint: digestmaps.EncodeDigestSymbol(r.store.Fingerprint())},
		},
	}); err != nil {
		cancel()
		<-recvCh
		return sent, 0, err
	}
	_ = stream.CloseSend()

	res := <-recvCh
	return sent, res.count, res.err
}

// Sync implements the Phase 2 bidirectional item-transfer RPC.
func (r *Reconciler[T]) Sync(stream reconpb_riblt.Reconciler_SyncServer) error {
	if r.auth != nil {
		if err := r.auth(stream.Context()); err != nil {
			r.detector.OnMisbehavior(stream.Context(), err, nil)
			return err
		}
	}

	expected := r.popExpected(sessionIDFromIncoming(stream.Context()))

	var sendMu sync.Mutex
	var sendWG sync.WaitGroup
	sendErrCh := make(chan error, 1)

	onWant := func(digests []digestSymbol) {
		sendWG.Go(func() {
			sendMu.Lock()
			defer sendMu.Unlock()
			if _, err := r.sendSyncItems(stream, digests); err != nil {
				select {
				case sendErrCh <- err:
				default:
				}
			}
		})
	}

	if _, err := r.recvSyncFrames(stream, expected, onWant); err != nil {
		sendWG.Wait()
		return err
	}
	sendWG.Wait()

	select {
	case err := <-sendErrCh:
		return err
	default:
	}

	return stream.Send(&reconpb_riblt.SyncFrame{
		Payload: &reconpb_riblt.SyncFrame_Complete{
			Complete: &reconpb_riblt.SyncComplete{Fingerprint: digestmaps.EncodeDigestSymbol(r.store.Fingerprint())},
		},
	})
}

func (r *Reconciler[T]) sendSyncItems(stream syncStream, digests []digestSymbol) (int, error) {
	const syncChunkBytes = 128 * 1024
	sent := 0
	ctx := stream.Context()

	for _, d := range digests {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		item, found := r.store.GetByDigest(d)
		if !found {
			continue
		}
		raw, err := r.codec.Encode(item)
		if err != nil {
			return sent, err
		}
		rawDigest := digestmaps.EncodeDigestSymbol(d)

		if err := stream.Send(&reconpb_riblt.SyncFrame{
			Payload: &reconpb_riblt.SyncFrame_DataHeader{
				DataHeader: &reconpb_riblt.DataItemHeader{
					Digest:    rawDigest,
					TotalSize: int64(len(raw)),
				},
			},
		}); err != nil {
			return sent, err
		}

		for off := 0; off < len(raw); off += syncChunkBytes {
			end := min(off+syncChunkBytes, len(raw))
			if err := stream.Send(&reconpb_riblt.SyncFrame{
				Payload: &reconpb_riblt.SyncFrame_DataChunk{
					DataChunk: &reconpb_riblt.DataItemChunk{Data: raw[off:end]},
				},
			}); err != nil {
				return sent, err
			}
		}

		if err := stream.Send(&reconpb_riblt.SyncFrame{
			Payload: &reconpb_riblt.SyncFrame_DataEnd{
				DataEnd: &reconpb_riblt.DataItemEnd{Digest: rawDigest},
			},
		}); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (r *Reconciler[T]) recvSyncFrames(
	stream syncStream,
	expectedData map[digestSymbol]struct{},
	onWant func([]digestSymbol),
) (int, error) {
	var buf bytes.Buffer
	var curDigest digestSymbol
	var hasActiveData bool
	var gotComplete bool
	received := 0
	ctx := stream.Context()

	for {
		if err := ctx.Err(); err != nil {
			return received, err
		}

		frame, err := stream.Recv()
		if err == io.EOF {
			if hasActiveData {
				truncErr := fmt.Errorf("%w: stream closed mid-item %d", io.ErrUnexpectedEOF, curDigest)
				r.detector.OnMisbehavior(ctx, truncErr, nil)
				return received, truncErr
			}
			if !gotComplete {
				truncErr := fmt.Errorf("%w: stream closed before SyncComplete", io.ErrUnexpectedEOF)
				r.detector.OnMisbehavior(ctx, truncErr, nil)
				return received, truncErr
			}
			return received, nil
		}
		if err != nil {
			return received, err
		}
		if frame == nil {
			continue
		}

		switch p := frame.Payload.(type) {
		case *reconpb_riblt.SyncFrame_WantDigests:
			if onWant != nil && p.WantDigests != nil {
				digests := make([]digestSymbol, len(p.WantDigests.Digests))
				for i, raw := range p.WantDigests.Digests {
					d, err := digestmaps.DecodeDigestSymbol(raw)
					if err != nil {
						r.detector.OnMisbehavior(ctx, err, raw)
						return received, err
					}
					digests[i] = d
				}
				onWant(digests)
			}
		case *reconpb_riblt.SyncFrame_DataHeader:
			if hasActiveData {
				frameErr := fmt.Errorf("%w: received DataHeader while item %d is active", ErrFramingViolation, curDigest)
				r.detector.OnMisbehavior(ctx, frameErr, p.DataHeader.GetDigest())
				return received, frameErr
			}
			if p.DataHeader == nil {
				continue
			}
			d, err := digestmaps.DecodeDigestSymbol(p.DataHeader.GetDigest())
			if err != nil {
				r.detector.OnMisbehavior(ctx, err, p.DataHeader.GetDigest())
				return received, err
			}
			if len(expectedData) == 0 {
				unsolErr := fmt.Errorf("%w: digest %d", ErrUnexpectedSyncFrame, d)
				r.detector.OnMisbehavior(ctx, unsolErr, p.DataHeader.GetDigest())
				return received, unsolErr
			}
			if _, ok := expectedData[d]; !ok {
				unexpErr := fmt.Errorf("%w: %d", ErrUnexpectedDigest, d)
				r.detector.OnMisbehavior(ctx, unexpErr, p.DataHeader.GetDigest())
				return received, unexpErr
			}
			if r.maxItemBytes > 0 && p.DataHeader.GetTotalSize() > r.maxItemBytes {
				sizeErr := fmt.Errorf("%w: header size %d > %d", ErrItemSizeLimitExceeded, p.DataHeader.GetTotalSize(), r.maxItemBytes)
				r.detector.OnMisbehavior(ctx, sizeErr, p.DataHeader.GetDigest())
				return received, sizeErr
			}
			curDigest = d
			buf.Reset()
			hasActiveData = true
		case *reconpb_riblt.SyncFrame_DataChunk:
			if !hasActiveData {
				frameErr := fmt.Errorf("%w: received DataChunk without active DataHeader", ErrFramingViolation)
				r.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, frameErr
			}
			if p.DataChunk != nil && len(p.DataChunk.GetData()) > 0 {
				if r.maxItemBytes > 0 && int64(buf.Len()+len(p.DataChunk.GetData())) > r.maxItemBytes {
					sizeErr := fmt.Errorf("%w: accumulated item size exceeds %d", ErrItemSizeLimitExceeded, r.maxItemBytes)
					r.detector.OnMisbehavior(ctx, sizeErr, nil)
					return received, sizeErr
				}
				buf.Write(p.DataChunk.GetData())
			}
		case *reconpb_riblt.SyncFrame_DataEnd:
			if !hasActiveData {
				frameErr := fmt.Errorf("%w: received DataEnd without active DataHeader", ErrFramingViolation)
				r.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, frameErr
			}
			expected, err := digestmaps.DecodeDigestSymbol(p.DataEnd.GetDigest())
			if err != nil {
				r.detector.OnMisbehavior(ctx, err, p.DataEnd.GetDigest())
				return received, err
			}
			if expected != curDigest {
				frameErr := fmt.Errorf("%w: DataEnd digest %d != DataHeader digest %d", ErrFramingViolation, expected, curDigest)
				r.detector.OnMisbehavior(ctx, frameErr, p.DataEnd.GetDigest())
				return received, frameErr
			}
			item, err := r.codec.Decode(buf.Bytes())
			if err != nil {
				r.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, fmt.Errorf("decode synced item: %w", err)
			}
			if got := r.store.Digest(item); got != expected {
				mismatchErr := fmt.Errorf("digest mismatch: got %d, want %d", got, expected)
				r.detector.OnMisbehavior(ctx, mismatchErr, buf.Bytes())
				return received, mismatchErr
			}
			if err := r.detector.ValidateItem(ctx, item); err != nil {
				r.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, err
			}
			if err := r.applier(ctx, item); err != nil {
				r.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, err
			}
			delete(expectedData, curDigest)
			hasActiveData = false
			buf.Reset()
			received++
		case *reconpb_riblt.SyncFrame_Complete:
			if p.Complete != nil {
				gotComplete = true
				return received, nil
			}
		}
	}
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
