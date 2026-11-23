package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Engine executes single-RPC two-phase set reconciliation (pluggable Phase 1
// Negotiator followed by validated Phase 2 chunked item transfer) on one store.
type Engine[T any] struct {
	store          digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]
	negotiator     Negotiator
	registry       *Registry
	codec          ItemCodec[T]
	connProvider   ConnProvider
	auth           PeerAuthenticator
	detector       TamperDetector[T]
	applier        ItemApplier[T]
	maxItemBytes   int64
	maxWantDigests int
	timeout        time.Duration
	storeID        string
}

// NewEngine constructs an Engine bound to store and cfg.
// Fails closed if store, Negotiator/Registry, Detector, Codec, or Applier is missing.
func NewEngine[T any](
	store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol],
	cfg Config[T],
) (*Engine[T], error) {
	if store == nil {
		return nil, ErrMissingStore
	}
	if cfg.Negotiator == nil && cfg.Registry == nil {
		return nil, ErrMissingNegotiator
	}
	if cfg.Detector == nil {
		return nil, ErrMissingDetector
	}
	if cfg.Codec == nil {
		return nil, ErrMissingCodec
	}
	if cfg.Applier == nil {
		return nil, ErrMissingApplier
	}

	maxWant := cfg.MaxWantDigests
	if maxWant <= 0 {
		maxWant = DefaultMaxWantDigests
	}

	return &Engine[T]{
		store:          store,
		negotiator:     cfg.Negotiator,
		registry:       cfg.Registry,
		codec:          cfg.Codec,
		connProvider:   cfg.ConnProvider,
		auth:           cfg.Auth,
		detector:       cfg.Detector,
		applier:        cfg.Applier,
		maxItemBytes:   cfg.MaxItemBytes,
		maxWantDigests: maxWant,
		timeout:        cfg.Timeout,
		storeID:        cfg.StoreID,
	}, nil
}

type frameStream interface {
	Context() context.Context
	Send(*reconpb.Frame) error
	Recv() (*reconpb.Frame, error)
}

// negotiationStream implements NegotiationStream over the shared Reconcile gRPC stream,
// framing Phase 1 payloads in NegotiatePayload envelopes and tracking both sides' Done
// markers so Phase 1 transitions cleanly into Phase 2 on the same open stream.
type negotiationStream struct {
	stream        frameStream
	maxFrameBytes int
	sendMu        sync.Mutex
	localDone     bool
	peerDone      bool
}

func newNegotiationStream(stream frameStream, maxFrameBytes int) *negotiationStream {
	if maxFrameBytes <= 0 {
		maxFrameBytes = DefaultMaxNegotiateFrameBytes
	}
	return &negotiationStream{
		stream:        stream,
		maxFrameBytes: maxFrameBytes,
	}
}

// Send wraps payload in a Phase 1 NegotiatePayload frame and writes it to the stream.
// Enforces maxFrameBytes and returns ErrNegotiationClosed if CloseSend has already been called.
func (c *negotiationStream) Send(payload []byte) error {
	if len(payload) > c.maxFrameBytes {
		return fmt.Errorf("%w: negotiate payload %d > %d", ErrSessionLimitExceeded, len(payload), c.maxFrameBytes)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.localDone {
		return ErrNegotiationClosed
	}
	return c.stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{
			Negotiate: &reconpb.NegotiatePayload{Data: payload},
		},
	})
}

// CloseSend emits a Phase 1 Done barrier (NegotiatePayload{Done: true}) to half-close
// negotiation from this side without closing the underlying gRPC stream. Idempotent.
func (c *negotiationStream) CloseSend() error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.localDone {
		return nil
	}
	c.localDone = true
	return c.stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{
			Negotiate: &reconpb.NegotiatePayload{Done: true},
		},
	})
}

// Recv reads the next Phase 1 NegotiatePayload from the stream. Rejects any non-Negotiate
// frame with ErrFramingViolation and enforces maxFrameBytes. When a Done frame arrives,
// any accompanying Data is returned first and subsequent calls return io.EOF.
func (c *negotiationStream) Recv() ([]byte, error) {
	if c.peerDone {
		return nil, io.EOF
	}
	for {
		frame, err := c.stream.Recv()
		if err != nil {
			return nil, err
		}
		if frame == nil {
			continue
		}
		neg, ok := frame.Payload.(*reconpb.Frame_Negotiate)
		if !ok || neg.Negotiate == nil {
			return nil, fmt.Errorf("%w: unexpected non-negotiate frame during Phase 1", ErrFramingViolation)
		}
		data := neg.Negotiate.GetData()
		if len(data) > c.maxFrameBytes {
			return nil, fmt.Errorf("%w: negotiate payload %d > %d", ErrSessionLimitExceeded, len(data), c.maxFrameBytes)
		}
		if neg.Negotiate.GetDone() {
			c.peerDone = true
			if len(data) > 0 {
				return data, nil
			}
			return nil, io.EOF
		}
		return data, nil
	}
}

// DrainPeer discards any remaining in-flight Phase 1 Negotiate frames (for example, coded
// symbols sent by a rateless initiator before it observed Decoded) until the peer's Done
// barrier arrives, aligning the stream at the exact Phase 1 -> Phase 2 frame boundary
// while bounding drained frames and bytes against DoS.
func (c *negotiationStream) DrainPeer(ctx context.Context, maxFrames int, maxBytes int64) error {
	frames := 0
	var bytesDrained int64
	for !c.peerDone {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := c.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		frames++
		bytesDrained += int64(len(data))
		if (maxFrames > 0 && frames > maxFrames) || (maxBytes > 0 && bytesDrained > maxBytes) {
			return fmt.Errorf("%w: Phase 1 drain limit exceeded (%d frames, %d bytes)", ErrSessionLimitExceeded, frames, bytesDrained)
		}
	}
	return nil
}

func (e *Engine[T]) outgoingContext(ctx context.Context, protoName string) context.Context {
	pairs := make([]string, 0, 4)
	if e.storeID != "" {
		pairs = append(pairs, StoreIDMetadataKey, e.storeID)
	}
	if protoName != "" {
		pairs = append(pairs, ProtocolMetadataKey, protoName)
	}
	if len(pairs) == 0 {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(pairs...))
}

func (e *Engine[T]) resolveProtocol(ctx context.Context) (Negotiator, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	var vals []string
	if ok {
		vals = md.Get(ProtocolMetadataKey)
	}
	if len(vals) != 1 || vals[0] == "" {
		return nil, status.Error(codes.InvalidArgument, "missing or invalid reconcile-protocol metadata")
	}
	name := vals[0]
	if e.registry != nil {
		neg, err := e.registry.Get(name)
		if err == nil {
			return neg, nil
		}
	}
	if e.negotiator != nil && e.negotiator.Name() == name {
		return e.negotiator, nil
	}
	return nil, status.Errorf(codes.Unimplemented, "unsupported reconcile protocol %q", name)
}

func (e *Engine[T]) connFor(ctx context.Context, addr string) (grpc.ClientConnInterface, error) {
	if e.connProvider == nil {
		return nil, ErrMissingConnProvider
	}
	return e.connProvider(ctx, addr)
}

// Fingerprint returns the canonical 8-byte big-endian fingerprint of the engine's store.
func (e *Engine[T]) Fingerprint() []byte {
	return digestmaps.EncodeDigestSymbol(e.store.Fingerprint())
}

// ReconcileWithPeer initiates a single-RPC Phase 1 + Phase 2 reconciliation against addr.
func (e *Engine[T]) ReconcileWithPeer(ctx context.Context, addr string) (Summary, error) {
	summary := Summary{Peer: addr}
	if e.negotiator == nil {
		return summary, ErrMissingNegotiator
	}
	if e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	cc, err := e.connFor(ctx, addr)
	if err != nil {
		return summary, err
	}
	if cc == nil {
		return summary, ErrMissingConnProvider
	}

	ctx, cancel := context.WithCancel(e.outgoingContext(ctx, e.negotiator.Name()))
	defer cancel()

	stream, err := reconpb.NewReconcileServiceClient(cc).Reconcile(ctx)
	if err != nil {
		return summary, err
	}

	negStream := newNegotiationStream(stream, DefaultMaxNegotiateFrameBytes)
	diff, err := e.negotiator.Initiate(ctx, negStream, e.store)
	if err != nil {
		e.detector.OnMisbehavior(ctx, err, nil)
		return summary, fmt.Errorf("reconcile with %s: %w", addr, err)
	}

	summary.DigestsRequested = len(diff.Requested)
	summary.DigestsAvailable = len(diff.Available)
	summary.RemoteFingerprint = diff.RemoteFP
	summary.UsedFallback = diff.UsedFallback

	if len(diff.Requested) == 0 && len(diff.Available) == 0 {
		_ = negStream.CloseSend()
		_ = stream.CloseSend()
		return summary, nil
	}

	if err := negStream.CloseSend(); err != nil {
		return summary, fmt.Errorf("close Phase 1 with %s: %w", addr, err)
	}
	if err := negStream.DrainPeer(ctx, DefaultMaxDrainFrames, DefaultMaxDrainBytes); err != nil {
		e.detector.OnMisbehavior(ctx, err, nil)
		return summary, fmt.Errorf("drain Phase 1 with %s: %w", addr, err)
	}

	expected := digestSetFromSlice(diff.Available)

	type recvRes struct {
		count    int
		ignored  int
		remoteFP []byte
		err      error
	}
	recvCh := make(chan recvRes, 1)
	go func() {
		n, ign, fp, recvErr := e.recvSyncFrames(ctx, stream, expected, nil)
		recvCh <- recvRes{count: n, ignored: ign, remoteFP: fp, err: recvErr}
	}()

	sendErr := func(err error) error {
		if err == io.EOF {
			res := <-recvCh
			if res.err != nil {
				return res.err
			}
			return err
		}
		cancel()
		<-recvCh
		return err
	}

	const wantBatchSize = 32768
	for i := 0; i < len(diff.Available); i += wantBatchSize {
		end := min(i+wantBatchSize, len(diff.Available))
		want := make([][]byte, end-i)
		for j, d := range diff.Available[i:end] {
			want[j] = digestmaps.EncodeDigestSymbol(d)
		}
		if err := stream.Send(&reconpb.Frame{
			Payload: &reconpb.Frame_WantDigests{
				WantDigests: &reconpb.WantDigests{Digests: want},
			},
		}); err != nil {
			return summary, sendErr(err)
		}
	}

	sent, err := e.sendSyncItemsCtx(ctx, stream, diff.Requested)
	summary.ItemsSent = sent
	if err != nil {
		return summary, sendErr(err)
	}

	if err := stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Complete{
			Complete: &reconpb.SyncComplete{Fingerprint: digestmaps.EncodeDigestSymbol(e.store.Fingerprint())},
		},
	}); err != nil {
		return summary, sendErr(err)
	}
	_ = stream.CloseSend()

	res := <-recvCh
	summary.ItemsReceived = res.count
	summary.ItemsIgnored = res.ignored
	if len(res.remoteFP) > 0 {
		summary.RemoteFingerprint = res.remoteFP
	}
	if res.err != nil {
		return summary, fmt.Errorf("sync with %s: %w", addr, res.err)
	}
	return summary, nil
}

// HandleReconcile serves an inbound single-RPC Phase 1 + Phase 2 Reconcile stream.
func (e *Engine[T]) HandleReconcile(stream reconpb.ReconcileService_ReconcileServer) error {
	ctx := stream.Context()
	if e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	if e.auth == nil {
		e.detector.OnMisbehavior(ctx, ErrMissingAuthenticator, nil)
		return status.Error(codes.Unauthenticated, ErrMissingAuthenticator.Error())
	}
	if err := e.auth(ctx); err != nil {
		e.detector.OnMisbehavior(ctx, err, nil)
		return err
	}

	neg, err := e.resolveProtocol(ctx)
	if err != nil {
		return err
	}

	negStream := newNegotiationStream(stream, DefaultMaxNegotiateFrameBytes)

	type phase1Res struct {
		diff Diff
		err  error
	}
	p1Done := make(chan phase1Res, 1)
	go func() {
		diff, p1Err := neg.Respond(ctx, negStream, e.store)
		if p1Err != nil {
			p1Done <- phase1Res{err: p1Err}
			return
		}
		if closeErr := negStream.CloseSend(); closeErr != nil {
			p1Done <- phase1Res{err: closeErr}
			return
		}
		if len(diff.Requested) == 0 && len(diff.Available) == 0 {
			p1Done <- phase1Res{diff: diff}
			return
		}
		if drainErr := negStream.DrainPeer(ctx, DefaultMaxDrainFrames, DefaultMaxDrainBytes); drainErr != nil {
			p1Done <- phase1Res{err: drainErr}
			return
		}
		p1Done <- phase1Res{diff: diff}
	}()

	var diff Diff
	select {
	case res := <-p1Done:
		if res.err != nil {
			e.detector.OnMisbehavior(ctx, res.err, nil)
			if errors.Is(res.err, ErrSessionLimitExceeded) {
				return status.Error(codes.ResourceExhausted, res.err.Error())
			}
			return res.err
		}
		diff = res.diff
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, ctx.Err().Error())
	}

	if len(diff.Requested) == 0 && len(diff.Available) == 0 {
		return nil
	}

	// Both allowlists live strictly on the stack of this RPC (kills S1 & closes S2).
	expectedData := digestSetFromSlice(diff.Requested)
	allowedWant := digestSetFromSlice(diff.Available)

	wantCh := make(chan []digestmaps.DigestSymbol, 16)
	sendErrCh := make(chan error, 1)
	var sendWG sync.WaitGroup
	sendWG.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case digests, ok := <-wantCh:
				if !ok {
					return
				}
				if _, err := e.sendSyncItemsCtx(ctx, stream, digests); err != nil {
					select {
					case sendErrCh <- err:
					default:
					}
					return
				}
			}
		}
	})

	totalWant := 0
	onWant := func(digests []digestmaps.DigestSymbol) error {
		totalWant += len(digests)
		if totalWant > e.maxWantDigests {
			wantErr := fmt.Errorf("%w: want digests %d > %d", ErrSessionLimitExceeded, totalWant, e.maxWantDigests)
			e.detector.OnMisbehavior(ctx, wantErr, nil)
			return status.Error(codes.ResourceExhausted, wantErr.Error())
		}
		for _, d := range digests {
			if _, ok := allowedWant[d]; !ok {
				unexpErr := fmt.Errorf("%w: wanted digest %d not in negotiated available set", ErrUnexpectedDigest, d)
				e.detector.OnMisbehavior(ctx, unexpErr, digestmaps.EncodeDigestSymbol(d))
				return unexpErr
			}
			delete(allowedWant, d)
		}
		select {
		case wantCh <- digests:
			return nil
		case err := <-sendErrCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	recvDone := make(chan error, 1)
	go func() {
		_, _, _, recvErr := e.recvSyncFrames(ctx, stream, expectedData, onWant)
		recvDone <- recvErr
	}()

	var recvErr error
	select {
	case recvErr = <-recvDone:
		close(wantCh)
		sendWG.Wait()
	case <-ctx.Done():
		sendWG.Wait()
		return status.Error(codes.DeadlineExceeded, ctx.Err().Error())
	}

	if recvErr != nil {
		return recvErr
	}
	select {
	case err := <-sendErrCh:
		return err
	default:
	}

	return stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Complete{
			Complete: &reconpb.SyncComplete{Fingerprint: digestmaps.EncodeDigestSymbol(e.store.Fingerprint())},
		},
	})
}

func (e *Engine[T]) sendSyncItemsCtx(ctx context.Context, stream frameStream, digests []digestmaps.DigestSymbol) (int, error) {
	const syncChunkBytes = 128 * 1024
	sent := 0

	for _, d := range digests {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		item, found := e.store.GetByDigest(d)
		if !found {
			continue
		}
		raw, err := e.codec.Encode(item)
		if err != nil {
			return sent, err
		}
		rawDigest := digestmaps.EncodeDigestSymbol(d)

		if err := stream.Send(&reconpb.Frame{
			Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{
					Digest:    rawDigest,
					TotalSize: int64(len(raw)),
				},
			},
		}); err != nil {
			return sent, err
		}

		for off := 0; off < len(raw); off += syncChunkBytes {
			end := min(off+syncChunkBytes, len(raw))
			if err := stream.Send(&reconpb.Frame{
				Payload: &reconpb.Frame_DataChunk{
					DataChunk: &reconpb.DataItemChunk{Data: raw[off:end]},
				},
			}); err != nil {
				return sent, err
			}
		}

		if err := stream.Send(&reconpb.Frame{
			Payload: &reconpb.Frame_DataEnd{
				DataEnd: &reconpb.DataItemEnd{Digest: rawDigest},
			},
		}); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (e *Engine[T]) recvSyncFrames(
	ctx context.Context,
	stream frameStream,
	expectedData map[digestmaps.DigestSymbol]struct{},
	onWant func([]digestmaps.DigestSymbol) error,
) (int, int, []byte, error) {
	var buf bytes.Buffer
	var curDigest digestmaps.DigestSymbol
	var expectedTotalSize int64
	var hasActiveData bool
	var gotComplete bool
	var remoteFP []byte
	received := 0
	ignored := 0

	for {
		if err := ctx.Err(); err != nil {
			return received, ignored, remoteFP, err
		}

		frame, err := stream.Recv()
		if err == io.EOF {
			if hasActiveData {
				truncErr := fmt.Errorf("%w: stream closed mid-item %d", io.ErrUnexpectedEOF, curDigest)
				e.detector.OnMisbehavior(ctx, truncErr, nil)
				return received, ignored, remoteFP, truncErr
			}
			if !gotComplete {
				truncErr := fmt.Errorf("%w: stream closed before SyncComplete", io.ErrUnexpectedEOF)
				e.detector.OnMisbehavior(ctx, truncErr, nil)
				return received, ignored, remoteFP, truncErr
			}
			return received, ignored, remoteFP, nil
		}
		if err != nil {
			return received, ignored, remoteFP, err
		}
		if frame == nil {
			continue
		}

		switch p := frame.Payload.(type) {
		case *reconpb.Frame_Negotiate:
			frameErr := fmt.Errorf("%w: received Negotiate frame during Phase 2", ErrFramingViolation)
			e.detector.OnMisbehavior(ctx, frameErr, nil)
			return received, ignored, remoteFP, frameErr
		case *reconpb.Frame_WantDigests:
			if onWant == nil {
				frameErr := fmt.Errorf("%w: unexpected WantDigests frame on initiator", ErrFramingViolation)
				e.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, ignored, remoteFP, frameErr
			}
			if p.WantDigests != nil {
				digests := make([]digestmaps.DigestSymbol, len(p.WantDigests.Digests))
				for i, raw := range p.WantDigests.Digests {
					d, decErr := digestmaps.DecodeDigestSymbol(raw)
					if decErr != nil {
						e.detector.OnMisbehavior(ctx, decErr, raw)
						return received, ignored, remoteFP, decErr
					}
					digests[i] = d
				}
				if err := onWant(digests); err != nil {
					return received, ignored, remoteFP, err
				}
			}
		case *reconpb.Frame_DataHeader:
			if hasActiveData {
				frameErr := fmt.Errorf("%w: received DataHeader while item %d is active", ErrFramingViolation, curDigest)
				e.detector.OnMisbehavior(ctx, frameErr, p.DataHeader.GetDigest())
				return received, ignored, remoteFP, frameErr
			}
			if p.DataHeader == nil {
				continue
			}
			d, err := digestmaps.DecodeDigestSymbol(p.DataHeader.GetDigest())
			if err != nil {
				e.detector.OnMisbehavior(ctx, err, p.DataHeader.GetDigest())
				return received, ignored, remoteFP, err
			}
			if len(expectedData) == 0 {
				unsolErr := fmt.Errorf("%w: digest %d", ErrUnexpectedSyncFrame, d)
				e.detector.OnMisbehavior(ctx, unsolErr, p.DataHeader.GetDigest())
				return received, ignored, remoteFP, unsolErr
			}
			if _, ok := expectedData[d]; !ok {
				unexpErr := fmt.Errorf("%w: %d", ErrUnexpectedDigest, d)
				e.detector.OnMisbehavior(ctx, unexpErr, p.DataHeader.GetDigest())
				return received, ignored, remoteFP, unexpErr
			}
			if p.DataHeader.GetTotalSize() < 0 {
				sizeErr := fmt.Errorf("%w: negative header size %d", ErrFramingViolation, p.DataHeader.GetTotalSize())
				e.detector.OnMisbehavior(ctx, sizeErr, p.DataHeader.GetDigest())
				return received, ignored, remoteFP, sizeErr
			}
			if e.maxItemBytes > 0 && p.DataHeader.GetTotalSize() > e.maxItemBytes {
				sizeErr := fmt.Errorf("%w: header size %d > %d", ErrItemSizeLimitExceeded, p.DataHeader.GetTotalSize(), e.maxItemBytes)
				e.detector.OnMisbehavior(ctx, sizeErr, p.DataHeader.GetDigest())
				return received, ignored, remoteFP, sizeErr
			}
			curDigest = d
			expectedTotalSize = p.DataHeader.GetTotalSize()
			buf.Reset()
			hasActiveData = true
		case *reconpb.Frame_DataChunk:
			if !hasActiveData {
				frameErr := fmt.Errorf("%w: received DataChunk without active DataHeader", ErrFramingViolation)
				e.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, ignored, remoteFP, frameErr
			}
			if p.DataChunk != nil && len(p.DataChunk.GetData()) > 0 {
				if e.maxItemBytes > 0 && int64(buf.Len()+len(p.DataChunk.GetData())) > e.maxItemBytes {
					sizeErr := fmt.Errorf("%w: accumulated item size exceeds %d", ErrItemSizeLimitExceeded, e.maxItemBytes)
					e.detector.OnMisbehavior(ctx, sizeErr, nil)
					return received, ignored, remoteFP, sizeErr
				}
				buf.Write(p.DataChunk.GetData())
			}
		case *reconpb.Frame_DataEnd:
			if !hasActiveData {
				frameErr := fmt.Errorf("%w: received DataEnd without active DataHeader", ErrFramingViolation)
				e.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, ignored, remoteFP, frameErr
			}
			expected, err := digestmaps.DecodeDigestSymbol(p.DataEnd.GetDigest())
			if err != nil {
				e.detector.OnMisbehavior(ctx, err, p.DataEnd.GetDigest())
				return received, ignored, remoteFP, err
			}
			if expected != curDigest {
				frameErr := fmt.Errorf("%w: DataEnd digest %d != DataHeader digest %d", ErrFramingViolation, expected, curDigest)
				e.detector.OnMisbehavior(ctx, frameErr, p.DataEnd.GetDigest())
				return received, ignored, remoteFP, frameErr
			}
			if int64(buf.Len()) != expectedTotalSize {
				sizeErr := fmt.Errorf("%w: received %d bytes, header declared %d", ErrFramingViolation, buf.Len(), expectedTotalSize)
				e.detector.OnMisbehavior(ctx, sizeErr, p.DataEnd.GetDigest())
				return received, ignored, remoteFP, sizeErr
			}
			item, err := e.codec.Decode(buf.Bytes())
			if err != nil {
				e.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, ignored, remoteFP, fmt.Errorf("decode synced item: %w", err)
			}
			if got := e.store.Digest(item); got != expected {
				mismatchErr := fmt.Errorf("digest mismatch: got %d, want %d", got, expected)
				e.detector.OnMisbehavior(ctx, mismatchErr, buf.Bytes())
				return received, ignored, remoteFP, mismatchErr
			}
			if err := e.detector.ValidateItem(ctx, item); err != nil {
				if errors.Is(err, ErrIgnore) {
					delete(expectedData, curDigest)
					hasActiveData = false
					buf.Reset()
					ignored++
					continue
				}
				e.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, ignored, remoteFP, err
			}
			if err := e.applier(ctx, item); err != nil {
				if errors.Is(err, ErrIgnore) {
					delete(expectedData, curDigest)
					hasActiveData = false
					buf.Reset()
					ignored++
					continue
				}
				e.detector.OnMisbehavior(ctx, err, buf.Bytes())
				return received, ignored, remoteFP, err
			}
			delete(expectedData, curDigest)
			hasActiveData = false
			buf.Reset()
			received++
		case *reconpb.Frame_Complete:
			if hasActiveData {
				frameErr := fmt.Errorf("%w: received SyncComplete while item %d is active", ErrFramingViolation, curDigest)
				e.detector.OnMisbehavior(ctx, frameErr, nil)
				return received, ignored, remoteFP, frameErr
			}
			if p.Complete != nil {
				gotComplete = true
				remoteFP = p.Complete.GetFingerprint()
				return received, ignored, remoteFP, nil
			}
		}
	}
}

func digestSetFromSlice(digests []digestmaps.DigestSymbol) map[digestmaps.DigestSymbol]struct{} {
	if len(digests) == 0 {
		return nil
	}
	out := make(map[digestmaps.DigestSymbol]struct{}, len(digests))
	for _, d := range digests {
		out[d] = struct{}{}
	}
	return out
}
