package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	transferpb "github.com/eika123/ifrit/reconcile/transfer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// StoreIDMetadataKey is the gRPC metadata key used to route multiplexed reconciliation streams.
	StoreIDMetadataKey = "store-id"
	// SessionIDMetadataKey is the gRPC metadata key binding Phase 1 diff negotiation to Phase 2 Sync.
	SessionIDMetadataKey = "reconcile-session-id"
)

var (
	ErrFramingViolation      = errors.New("reconcile: stream framing violation")
	ErrUnexpectedDigest      = errors.New("reconcile: received unexpected digest not in allowlist")
	ErrUnexpectedSyncFrame   = errors.New("reconcile: received unexpected data frame when zero items expected")
	ErrItemSizeLimitExceeded = errors.New("reconcile: item size exceeds configured maximum")
)

// StreamGuard optionally wraps inbound Phase 1 and Phase 2 reconciliation streams
// (e.g. for crossed-wires tie-breaking and per-peer concurrency gating).
type StreamGuard func(ctx context.Context, next func() error) error

// StoreMux resolves store handlers by the "store-id" gRPC metadata key.
type StoreMux[H any] struct {
	mu       sync.RWMutex
	handlers map[string]H
}

// NewStoreMux creates an empty StoreMux.
func NewStoreMux[H any]() *StoreMux[H] {
	return &StoreMux[H]{
		handlers: make(map[string]H),
	}
}

// Register binds storeID to handler.
func (m *StoreMux[H]) Register(storeID string, handler H) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[storeID] = handler
}

// Resolve selects the handler matching the incoming "store-id" metadata header
// (with a single-handler fallback when only one store is registered).
func (m *StoreMux[H]) Resolve(ctx context.Context) (H, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var zero H
	md, hasMD := metadata.FromIncomingContext(ctx)
	var vals []string
	if hasMD {
		vals = md.Get(StoreIDMetadataKey)
	}

	if len(vals) == 0 {
		if len(m.handlers) == 1 {
			for _, h := range m.handlers {
				return h, nil
			}
		}
		return zero, status.Error(codes.InvalidArgument, "missing store-id metadata")
	}
	if len(vals) > 1 || vals[0] == "" {
		return zero, status.Error(codes.InvalidArgument, "invalid store-id metadata")
	}

	h, ok := m.handlers[vals[0]]
	if !ok {
		return zero, status.Errorf(codes.NotFound, "unknown store-id %q", vals[0])
	}
	return h, nil
}

// ItemTransferMux multiplexes incoming ItemTransfer.Sync streams across stores by "store-id".
type ItemTransferMux struct {
	transferpb.UnimplementedItemTransferServer
	stores *StoreMux[transferpb.ItemTransferServer]
	guard  StreamGuard
}

// NewItemTransferMux creates an ItemTransferMux with an optional StreamGuard.
func NewItemTransferMux(guard StreamGuard) *ItemTransferMux {
	return &ItemTransferMux{
		stores: NewStoreMux[transferpb.ItemTransferServer](),
		guard:  guard,
	}
}

// RegisterStore binds storeID to handler.
func (m *ItemTransferMux) RegisterStore(storeID string, handler transferpb.ItemTransferServer) {
	m.stores.Register(storeID, handler)
}

// Sync routes the Phase 2 stream to the handler matching "store-id".
func (m *ItemTransferMux) Sync(stream transferpb.ItemTransfer_SyncServer) error {
	h, err := m.stores.Resolve(stream.Context())
	if err != nil {
		return err
	}
	if m.guard != nil {
		return m.guard(stream.Context(), func() error {
			return h.Sync(stream)
		})
	}
	return h.Sync(stream)
}

// SessionIDFromIncoming extracts the reconcile session ID from incoming gRPC metadata.
func SessionIDFromIncoming(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(SessionIDMetadataKey)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// PeerSyncer implements protocol-agnostic Phase 2 bidirectional item transfer
// (allowlists, framing validation, MaxItemBytes, TamperDetector, ItemApplier).
type PeerSyncer[T any] struct {
	transferpb.UnimplementedItemTransferServer
	store        digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]
	codec        reconcile.ItemCodec[T]
	connProvider reconcile.ConnProvider
	auth         reconcile.PeerAuthenticator
	detector     reconcile.TamperDetector[T]
	applier      reconcile.ItemApplier[T]
	maxItemBytes int64
	storeID      string

	pendingMu       sync.Mutex
	pendingExpected map[string]map[digestmaps.DigestSymbol]struct{}
}

// NewPeerSyncer constructs a PeerSyncer bound to store and cfg.
func NewPeerSyncer[T any](
	store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol],
	cfg reconcile.Config[T],
) *PeerSyncer[T] {
	codec := cfg.Codec
	if codec == nil {
		codec = reconcile.JSONCodec[T]{}
	}
	detector := cfg.Detector
	if detector == nil {
		detector = reconcile.NoopTamperDetector[T]{}
	}
	applier := cfg.Applier
	if applier == nil {
		applier = func(_ context.Context, item T) error {
			store.Insert(item)
			return nil
		}
	}
	return &PeerSyncer[T]{
		store:           store,
		codec:           codec,
		connProvider:    cfg.ConnProvider,
		auth:            cfg.Auth,
		detector:        detector,
		applier:         applier,
		maxItemBytes:    cfg.MaxItemBytes,
		storeID:         cfg.StoreID,
		pendingExpected: make(map[string]map[digestmaps.DigestSymbol]struct{}),
	}
}

// OutgoingContext attaches store-id and reconcile-session-id metadata to ctx.
func (s *PeerSyncer[T]) OutgoingContext(ctx context.Context, sessionID string) context.Context {
	pairs := make([]string, 0, 4)
	if s.storeID != "" {
		pairs = append(pairs, StoreIDMetadataKey, s.storeID)
	}
	if sessionID != "" {
		pairs = append(pairs, SessionIDMetadataKey, sessionID)
	}
	if len(pairs) == 0 {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(pairs...))
}

// ConnFor borrows a pooled connection from ConnProvider or dials insecurely for standalone use.
func (s *PeerSyncer[T]) ConnFor(ctx context.Context, addr string) (grpc.ClientConnInterface, func(), error) {
	if s.connProvider != nil {
		cc, err := s.connProvider(ctx, addr)
		return cc, func() {}, err
	}
	cc, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}
	return cc, func() { _ = cc.Close() }, nil
}

// RecordExpected stores the responder's allowlist of expected item digests for sessionID.
func (s *PeerSyncer[T]) RecordExpected(sessionID string, digests []digestmaps.DigestSymbol) {
	if sessionID == "" {
		return
	}
	expected := make(map[digestmaps.DigestSymbol]struct{}, len(digests))
	for _, d := range digests {
		expected[d] = struct{}{}
	}
	s.pendingMu.Lock()
	s.pendingExpected[sessionID] = expected
	s.pendingMu.Unlock()
}

// PopExpected retrieves and removes the expected item digest allowlist for sessionID.
func (s *PeerSyncer[T]) PopExpected(sessionID string) map[digestmaps.DigestSymbol]struct{} {
	if sessionID == "" {
		return nil
	}
	s.pendingMu.Lock()
	expected := s.pendingExpected[sessionID]
	delete(s.pendingExpected, sessionID)
	s.pendingMu.Unlock()
	return expected
}

type syncStream interface {
	Context() context.Context
	Send(*transferpb.SyncFrame) error
	Recv() (*transferpb.SyncFrame, error)
}

// SyncWithPeer executes Phase 2 bidirectional chunked item transfer against addr.
func (s *PeerSyncer[T]) SyncWithPeer(
	ctx context.Context,
	addr string,
	sessionID string,
	requested, available []digestmaps.DigestSymbol,
) (sent, received int, remoteFP []byte, err error) {
	cc, closeFn, err := s.ConnFor(ctx, addr)
	if err != nil {
		return 0, 0, nil, err
	}
	defer closeFn()

	ctx, cancel := context.WithCancel(s.OutgoingContext(ctx, sessionID))
	defer cancel()

	stream, err := transferpb.NewItemTransferClient(cc).Sync(ctx)
	if err != nil {
		return 0, 0, nil, err
	}

	expected := make(map[digestmaps.DigestSymbol]struct{}, len(available))
	for _, d := range available {
		expected[d] = struct{}{}
	}

	type recvRes struct {
		count    int
		remoteFP []byte
		err      error
	}
	recvCh := make(chan recvRes, 1)
	go func() {
		n, fp, err := s.recvSyncFrames(stream, expected, nil)
		recvCh <- recvRes{count: n, remoteFP: fp, err: err}
	}()

	const wantBatchSize = 32768
	for i := 0; i < len(available); i += wantBatchSize {
		end := min(i+wantBatchSize, len(available))
		want := make([][]byte, end-i)
		for j, d := range available[i:end] {
			want[j] = digestmaps.EncodeDigestSymbol(d)
		}
		if err := stream.Send(&transferpb.SyncFrame{
			Payload: &transferpb.SyncFrame_WantDigests{
				WantDigests: &transferpb.WantDigests{Digests: want},
			},
		}); err != nil {
			cancel()
			<-recvCh
			return 0, 0, nil, err
		}
	}

	sent, err = s.sendSyncItems(stream, requested)
	if err != nil {
		cancel()
		<-recvCh
		return sent, 0, nil, err
	}
	if err := stream.Send(&transferpb.SyncFrame{
		Payload: &transferpb.SyncFrame_Complete{
			Complete: &transferpb.SyncComplete{Fingerprint: digestmaps.EncodeDigestSymbol(s.store.Fingerprint())},
		},
	}); err != nil {
		cancel()
		<-recvCh
		return sent, 0, nil, err
	}
	_ = stream.CloseSend()

	res := <-recvCh
	return sent, res.count, res.remoteFP, res.err
}

// Sync implements transferpb.ItemTransferServer for inbound Phase 2 streams.
func (s *PeerSyncer[T]) Sync(stream transferpb.ItemTransfer_SyncServer) error {
	if s.auth != nil {
		if err := s.auth(stream.Context()); err != nil {
			s.detector.OnMisbehavior(stream.Context(), err, nil)
			return err
		}
	}

	expected := s.PopExpected(SessionIDFromIncoming(stream.Context()))

	var sendMu sync.Mutex
	var sendWG sync.WaitGroup
	sendErrCh := make(chan error, 1)

	onWant := func(digests []digestmaps.DigestSymbol) {
		sendWG.Go(func() {
			sendMu.Lock()
			defer sendMu.Unlock()
			if _, err := s.sendSyncItems(stream, digests); err != nil {
				select {
				case sendErrCh <- err:
				default:
				}
			}
		})
	}

	if _, _, err := s.recvSyncFrames(stream, expected, onWant); err != nil {
		sendWG.Wait()
		return err
	}
	sendWG.Wait()

	select {
	case err := <-sendErrCh:
		return err
	default:
	}

	return stream.Send(&transferpb.SyncFrame{
		Payload: &transferpb.SyncFrame_Complete{
			Complete: &transferpb.SyncComplete{Fingerprint: digestmaps.EncodeDigestSymbol(s.store.Fingerprint())},
		},
	})
}

func (s *PeerSyncer[T]) sendSyncItems(stream syncStream, digests []digestmaps.DigestSymbol) (int, error) {
	const syncChunkBytes = 128 * 1024
	sent := 0
	ctx := stream.Context()

	for _, d := range digests {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		item, found := s.store.GetByDigest(d)
		if !found {
			continue
		}
		raw, err := s.codec.Encode(item)
		if err != nil {
			return sent, err
		}
		rawDigest := digestmaps.EncodeDigestSymbol(d)

		if err := stream.Send(&transferpb.SyncFrame{
			Payload: &transferpb.SyncFrame_DataHeader{
				DataHeader: &transferpb.DataItemHeader{
					Digest:    rawDigest,
					TotalSize: int64(len(raw)),
				},
			},
		}); err != nil {
			return sent, err
		}

		for off := 0; off < len(raw); off += syncChunkBytes {
			end := min(off+syncChunkBytes, len(raw))
			if err := stream.Send(&transferpb.SyncFrame{
				Payload: &transferpb.SyncFrame_DataChunk{
					DataChunk: &transferpb.DataItemChunk{Data: raw[off:end]},
				},
			}); err != nil {
				return sent, err
			}
		}

		if err := stream.Send(&transferpb.SyncFrame{
			Payload: &transferpb.SyncFrame_DataEnd{
				DataEnd: &transferpb.DataItemEnd{Digest: rawDigest},
			},
		}); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (s *PeerSyncer[T]) recvSyncFrames(
	stream syncStream,
	expectedData map[digestmaps.DigestSymbol]struct{},
	onWant func([]digestmaps.DigestSymbol),
) (int, []byte, error) {
	var buf bytes.Buffer
	var curDigest digestmaps.DigestSymbol
	var hasActiveData bool
	var gotComplete bool
	var remoteFP []byte
	received := 0
	ctx := stream.Context()

	for {
		if err := ctx.Err(); err != nil {
			return received, remoteFP, err
		}

		frame, err := stream.Recv()
		if err == io.EOF {
			if hasActiveData {
				truncErr := fmt.Errorf("%w: stream closed mid-item %d", io.ErrUnexpectedEOF, curDigest)
				s.detector.OnMisbehavior(ctx, truncErr, nil)
				return received, remoteFP, truncErr
			}
			if !gotComplete {
				truncErr := fmt.Errorf("%w: stream closed before SyncComplete", io.ErrUnexpectedEOF)
				s.detector.OnMisbehavior(ctx, truncErr, nil)
				return received, remoteFP, truncErr
			}
			return received, remoteFP, nil
		}
		if err != nil {
			return received, remoteFP, err
		}
		if frame == nil {
			continue
		}

		switch p := frame.Payload.(type) {
		case *transferpb.SyncFrame_WantDigests:
			if onWant != nil && p.WantDigests != nil {
				digests := make([]digestmaps.DigestSymbol, len(p.WantDigests.Digests))
				for i, raw := range p.WantDigests.Digests {
					d, err := digestmaps.DecodeDigestSymbol(raw)
					if err != nil {
						s.detector.OnMisbehavior(ctx, err, raw)
						return received, remoteFP, err
					}
					digests[i] = d
				}
				onWant(digests)
			}
		case *transferpb.SyncFrame_DataHeader:
			if hasActiveData {
				frameErr := fmt.Errorf("%w: received DataHeader while item %d is active", ErrFramingViolation, curDigest)
				s.detector.OnMisbehavior(ctx, frameErr, p.DataHeader.GetDigest())
				return received, remoteFP, frameErr
			}
			if p.DataHeader == nil {
				continue
			}
			d, err := digestmaps.DecodeDigestSymbol(p.DataHeader.GetDigest())
			if err != nil {
				s.detector.OnMisbehavior(ctx, err, p.DataHeader.GetDigest())
				return received, remoteFP, err
			}
			if len(expectedData) == 0 {
				unsolErr := fmt.Errorf("%w: digest %d", ErrUnexpectedSyncFrame, d)
				s.detector.OnMisbehavior(ctx, unsolErr, p.DataHeader.GetDigest())
				return received, remoteFP, unsolErr
			}
			if _, ok := expectedData[d]; !ok {
				unexpErr := fmt.Errorf("%w: %d", ErrUnexpectedDigest, d)
				s.detector.OnMisbehavior(ctx, unexpErr, p.DataHeader.GetDigest())
				return received, remoteFP, unexpErr
			}
			if s.maxItemBytes > 0 && p.DataHeader.GetTotalSize() > s.maxItemBytes {
				sizeErr := fmt.Errorf("%w: header size %d > %d", ErrItemSizeLimitExceeded, p.DataHeader.GetTotalSize(), s.maxItemBytes)
				s.detector.OnMisbehavior(ctx, sizeErr, p.DataHeader.GetDigest())
				return received, remoteFP, sizeErr
			}
			curDigest = d
			buf.Reset()
			hasActiveData = true
		case *transferpb.SyncFrame_DataChunk:
			if !hasActiveData {
				frameErr := fmt.Errorf("%w: received DataChunk without active DataHeader", ErrFramingViolation)
				s.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, remoteFP, frameErr
			}
			if p.DataChunk != nil && len(p.DataChunk.GetData()) > 0 {
				if s.maxItemBytes > 0 && int64(buf.Len()+len(p.DataChunk.GetData())) > s.maxItemBytes {
					sizeErr := fmt.Errorf("%w: accumulated item size exceeds %d", ErrItemSizeLimitExceeded, s.maxItemBytes)
					s.detector.OnMisbehavior(ctx, sizeErr, nil)
					return received, remoteFP, sizeErr
				}
				buf.Write(p.DataChunk.GetData())
			}
		case *transferpb.SyncFrame_DataEnd:
			if !hasActiveData {
				frameErr := fmt.Errorf("%w: received DataEnd without active DataHeader", ErrFramingViolation)
				s.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, remoteFP, frameErr
			}
			expected, err := digestmaps.DecodeDigestSymbol(p.DataEnd.GetDigest())
			if err != nil {
				s.detector.OnMisbehavior(ctx, err, p.DataEnd.GetDigest())
				return received, remoteFP, err
			}
			if expected != curDigest {
				frameErr := fmt.Errorf("%w: DataEnd digest %d != DataHeader digest %d", ErrFramingViolation, expected, curDigest)
				s.detector.OnMisbehavior(ctx, frameErr, p.DataEnd.GetDigest())
				return received, remoteFP, frameErr
			}
			item, err := s.codec.Decode(buf.Bytes())
			if err != nil {
				s.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, remoteFP, fmt.Errorf("decode synced item: %w", err)
			}
			if got := s.store.Digest(item); got != expected {
				mismatchErr := fmt.Errorf("digest mismatch: got %d, want %d", got, expected)
				s.detector.OnMisbehavior(ctx, mismatchErr, buf.Bytes())
				return received, remoteFP, mismatchErr
			}
			if err := s.detector.ValidateItem(ctx, item); err != nil {
				s.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, remoteFP, err
			}
			if err := s.applier(ctx, item); err != nil {
				s.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, remoteFP, err
			}
			delete(expectedData, curDigest)
			hasActiveData = false
			buf.Reset()
			received++
		case *transferpb.SyncFrame_Complete:
			if p.Complete != nil {
				gotComplete = true
				remoteFP = p.Complete.GetFingerprint()
				return received, remoteFP, nil
			}
		}
	}
}
