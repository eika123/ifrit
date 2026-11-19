package reconcile_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/internal/testutil"
	"github.com/eika123/ifrit/reconcile/naive"
	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// staticNegotiator returns a fixed Diff immediately on Respond (after reading Phase 1 done)
// or Initiate, letting tests inject arbitrary raw Phase 2 frames cleanly.
type staticNegotiator struct {
	name    string
	mu      sync.Mutex
	resp    reconcile.Diff
	blockP1 bool
}

func (s *staticNegotiator) Name() string { return s.name }

func (s *staticNegotiator) setDiff(d reconcile.Diff) {
	s.mu.Lock()
	s.resp = d
	s.mu.Unlock()
}

func (s *staticNegotiator) Initiate(_ context.Context, stream reconcile.NegotiationStream, _ reconcile.Set) (reconcile.Diff, error) {
	if err := stream.CloseSend(); err != nil {
		return reconcile.Diff{}, err
	}
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return reconcile.Diff{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resp, nil
}

func (s *staticNegotiator) Respond(ctx context.Context, stream reconcile.NegotiationStream, _ reconcile.Set) (reconcile.Diff, error) {
	if s.blockP1 {
		<-ctx.Done()
		return reconcile.Diff{}, ctx.Err()
	}
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return reconcile.Diff{}, err
		}
	}
	if err := stream.CloseSend(); err != nil {
		return reconcile.Diff{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resp, nil
}

func newTestStore(t *testing.T, items ...string) digestmaps.ReverseIndexStore[string, digestmaps.DigestSymbol] {
	t.Helper()
	s, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	s.InsertBatch(items...)
	return s
}

func startLoopbackMux(t *testing.T, mux *reconcile.Mux) (string, *grpc.ClientConn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	mux.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	cc, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return lis.Addr().String(), cc
}

func TestEngine_FailClosedDefaults(t *testing.T) {
	store := newTestStore(t, "alpha")
	neg := naive.NewNegotiator()

	// Missing store
	_, err := reconcile.NewEngine[string](nil, reconcile.Config[string]{
		Negotiator: neg,
		Detector:   reconcile.AcceptAll[string](),
	})
	require.ErrorIs(t, err, reconcile.ErrMissingStore)

	// Missing Negotiator & Registry
	_, err = reconcile.NewEngine(store, reconcile.Config[string]{
		Detector: reconcile.AcceptAll[string](),
	})
	require.ErrorIs(t, err, reconcile.ErrMissingNegotiator)

	// Missing Detector
	_, err = reconcile.NewEngine(store, reconcile.Config[string]{
		Negotiator: neg,
		Codec:      reconcile.JSONCodec[string]{},
	})
	require.ErrorIs(t, err, reconcile.ErrMissingDetector)

	// Missing Codec
	_, err = reconcile.NewEngine(store, reconcile.Config[string]{
		Negotiator: neg,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    reconcile.NoopApplier[string],
	})
	require.ErrorIs(t, err, reconcile.ErrMissingCodec)

	// Missing Applier
	_, err = reconcile.NewEngine(store, reconcile.Config[string]{
		Negotiator: neg,
		Codec:      reconcile.JSONCodec[string]{},
		Detector:   reconcile.AcceptAll[string](),
	})
	require.ErrorIs(t, err, reconcile.ErrMissingApplier)

	// Missing ConnProvider fails closed on ReconcileWithPeer
	eng, err := reconcile.NewEngine(store, reconcile.Config[string]{
		Negotiator: neg,
		Codec:      reconcile.JSONCodec[string]{},
		Detector:   reconcile.AcceptAll[string](),
		Applier:    reconcile.NoopApplier[string],
		StoreID:    "data",
	})
	require.NoError(t, err)
	_, err = eng.ReconcileWithPeer(context.Background(), "127.0.0.1:12345")
	require.ErrorIs(t, err, reconcile.ErrMissingConnProvider)

	// Missing Auth fails closed on inbound HandleReconcile with Unauthenticated
	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", eng))
	_, cc := startLoopbackMux(t, mux)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := reconpb.NewReconcileServiceClient(cc).Reconcile(testutil.OutgoingContext(ctx, "data", naive.ProtocolName))
	require.NoError(t, err)
	require.NoError(t, stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{Negotiate: &reconpb.NegotiatePayload{Done: true}},
	}))
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestEngine_HappyPathBidirectionalAndLargeChunkedItem(t *testing.T) {
	largeA := strings.Repeat("A", 300*1024) // > 2 * 128 KiB syncChunkBytes
	largeB := strings.Repeat("B", 200*1024)

	storeA := newTestStore(t, "shared", largeA)
	storeB := newTestStore(t, "shared", largeB)

	engB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: naive.NewNegotiator(),
		Codec:      reconcile.JSONCodec[string]{},
		Auth:       reconcile.NoopAuthenticator,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    testutil.InsertTestApplier(storeB),
		StoreID:    "data",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", engB))
	addr, cc := startLoopbackMux(t, mux)

	engA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   naive.NewNegotiator(),
		Codec:        reconcile.JSONCodec[string]{},
		ConnProvider: func(context.Context, string) (grpc.ClientConnInterface, error) { return cc, nil },
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "data",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sum, err := engA.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, 1, sum.ItemsSent)
	assert.Equal(t, 1, sum.ItemsReceived)
	assert.Equal(t, 0, sum.ItemsIgnored)
	assert.NotEmpty(t, sum.RemoteFingerprint)
	assert.Equal(t, 3, storeA.Size())
	assert.Equal(t, 3, storeB.Size())
	assert.Equal(t, storeA.Fingerprint(), storeB.Fingerprint())

	// Second pass: empty diff 1-RTT fast path
	sumZero, err := engA.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, 0, sumZero.DigestsRequested)
	assert.Equal(t, 0, sumZero.DigestsAvailable)
	assert.Equal(t, 0, sumZero.ItemsSent)
	assert.Equal(t, 0, sumZero.ItemsReceived)
	assert.Equal(t, digestmaps.EncodeDigestSymbol(storeB.Fingerprint()), sumZero.RemoteFingerprint)
}

func TestEngine_AdversarialFramingGuards(t *testing.T) {
	storeB := newTestStore(t, "existing")
	det := &testutil.RecordingDetector[string]{}
	sNeg := &staticNegotiator{name: "static/1"}

	engB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator:   sNeg,
		Codec:        reconcile.JSONCodec[string]{},
		Auth:         reconcile.NoopAuthenticator,
		Detector:     det,
		Applier:      testutil.InsertTestApplier(storeB),
		MaxItemBytes: 32,
		StoreID:      "data",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", engB))
	_, cc := startLoopbackMux(t, mux)
	client := reconpb.NewReconcileServiceClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	item := "hello-world"
	itemBytes, err := reconcile.JSONCodec[string]{}.Encode(item)
	require.NoError(t, err)
	d := storeB.Digest(item)
	dRaw := digestmaps.EncodeDigestSymbol(d)
	existingD := storeB.Digest("existing")

	// Helper: completes Phase 1 barrier then sends raw Phase 2 frames.
	sendPhase2AndExpectErr := func(t *testing.T, diff reconcile.Diff, frames []*reconpb.Frame, closeSend bool, wantErr error) {
		t.Helper()
		sNeg.setDiff(diff)
		prev := det.Count()
		stream, err := client.Reconcile(testutil.OutgoingContext(ctx, "data", "static/1"))
		require.NoError(t, err)
		require.NoError(t, stream.Send(&reconpb.Frame{
			Payload: &reconpb.Frame_Negotiate{Negotiate: &reconpb.NegotiatePayload{Done: true}},
		}))
		// Read server's Phase 1 Done frame before sending Phase 2 frames.
		p1Ack, err := stream.Recv()
		require.NoError(t, err)
		require.NotNil(t, p1Ack.GetNegotiate())
		require.True(t, p1Ack.GetNegotiate().GetDone())

		for _, f := range frames {
			if sendErr := stream.Send(f); sendErr != nil {
				break
			}
		}
		if closeSend {
			_ = stream.CloseSend()
		}
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Greater(t, det.Count(), prev)
		if wantErr != nil {
			assert.ErrorIs(t, det.Last(), wantErr)
		}
	}

	t.Run("non-negotiate frame during Phase 1", func(t *testing.T) {
		prev := det.Count()
		stream, err := client.Reconcile(testutil.OutgoingContext(ctx, "data", "static/1"))
		require.NoError(t, err)
		require.NoError(t, stream.Send(&reconpb.Frame{
			Payload: &reconpb.Frame_DataChunk{DataChunk: &reconpb.DataItemChunk{Data: []byte("premature")}},
		}))
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Greater(t, det.Count(), prev)
		assert.ErrorIs(t, det.Last(), reconcile.ErrFramingViolation)
	})

	t.Run("negotiate frame during Phase 2", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Available: []digestmaps.DigestSymbol{existingD}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_Negotiate{Negotiate: &reconpb.NegotiatePayload{Data: []byte("late")}}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("unsolicited DataHeader when 0 requested", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Available: []digestmaps.DigestSymbol{existingD}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
		}, false, reconcile.ErrUnexpectedSyncFrame)
	})

	t.Run("header digest not in allowlist", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{storeB.Digest("other")}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
		}, false, reconcile.ErrUnexpectedDigest)
	})

	t.Run("nested DataHeader while item active", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("DataChunk without DataHeader", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataChunk{
				DataChunk: &reconpb.DataItemChunk{Data: []byte("orphan")},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("DataEnd without DataHeader", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataEnd{
				DataEnd: &reconpb.DataItemEnd{Digest: dRaw},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("DataEnd digest mismatch", func(t *testing.T) {
		wrongEnd := digestmaps.EncodeDigestSymbol(d + 1)
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
			{Payload: &reconpb.Frame_DataChunk{
				DataChunk: &reconpb.DataItemChunk{Data: itemBytes},
			}},
			{Payload: &reconpb.Frame_DataEnd{
				DataEnd: &reconpb.DataItemEnd{Digest: wrongEnd},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("negative TotalSize in header", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: -1},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("TotalSize exceeds MaxItemBytes", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: 64},
			}},
		}, false, reconcile.ErrItemSizeLimitExceeded)
	})

	t.Run("accumulated chunks exceed MaxItemBytes", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: 10},
			}},
			{Payload: &reconpb.Frame_DataChunk{
				DataChunk: &reconpb.DataItemChunk{Data: make([]byte, 20)},
			}},
			{Payload: &reconpb.Frame_DataChunk{
				DataChunk: &reconpb.DataItemChunk{Data: make([]byte, 20)},
			}},
		}, false, reconcile.ErrItemSizeLimitExceeded)
	})

	t.Run("TotalSize mismatch at DataEnd", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes) + 5)},
			}},
			{Payload: &reconpb.Frame_DataChunk{
				DataChunk: &reconpb.DataItemChunk{Data: itemBytes},
			}},
			{Payload: &reconpb.Frame_DataEnd{
				DataEnd: &reconpb.DataItemEnd{Digest: dRaw},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("SyncComplete mid-item", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
			{Payload: &reconpb.Frame_Complete{
				Complete: &reconpb.SyncComplete{},
			}},
		}, false, reconcile.ErrFramingViolation)
	})

	t.Run("decoded payload digest mismatch", func(t *testing.T) {
		wrongBytes, _ := reconcile.JSONCodec[string]{}.Encode("tampered-value")
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(wrongBytes))},
			}},
			{Payload: &reconpb.Frame_DataChunk{
				DataChunk: &reconpb.DataItemChunk{Data: wrongBytes},
			}},
			{Payload: &reconpb.Frame_DataEnd{
				DataEnd: &reconpb.DataItemEnd{Digest: dRaw},
			}},
		}, false, nil)
	})

	t.Run("EOF mid-item", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_DataHeader{
				DataHeader: &reconpb.DataItemHeader{Digest: dRaw, TotalSize: int64(len(itemBytes))},
			}},
		}, true, io.ErrUnexpectedEOF)
	})

	t.Run("EOF without SyncComplete", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Requested: []digestmaps.DigestSymbol{d}}, nil, true, io.ErrUnexpectedEOF)
	})

	t.Run("WantDigests outside negotiated Available allowlist", func(t *testing.T) {
		sendPhase2AndExpectErr(t, reconcile.Diff{Available: []digestmaps.DigestSymbol{existingD}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_WantDigests{
				WantDigests: &reconpb.WantDigests{Digests: [][]byte{dRaw}},
			}},
		}, false, reconcile.ErrUnexpectedDigest)
	})

	t.Run("duplicate WantDigests amplification rejected", func(t *testing.T) {
		existingRaw := digestmaps.EncodeDigestSymbol(existingD)
		sendPhase2AndExpectErr(t, reconcile.Diff{Available: []digestmaps.DigestSymbol{existingD}}, []*reconpb.Frame{
			{Payload: &reconpb.Frame_WantDigests{
				WantDigests: &reconpb.WantDigests{Digests: [][]byte{existingRaw, existingRaw}},
			}},
		}, false, reconcile.ErrUnexpectedDigest)
	})
}

func TestEngine_MaxWantDigestsAndServerTimeouts(t *testing.T) {
	storeB := newTestStore(t, "item-1", "item-2", "item-3")
	d1, d2, d3 := storeB.Digest("item-1"), storeB.Digest("item-2"), storeB.Digest("item-3")

	det := &testutil.RecordingDetector[string]{}
	sNeg := &staticNegotiator{
		name: "static/1",
		resp: reconcile.Diff{Available: []digestmaps.DigestSymbol{d1, d2, d3}},
	}
	blockNeg := &staticNegotiator{
		name:    "stall/1",
		blockP1: true,
	}
	reg, err := reconcile.NewRegistry(sNeg, blockNeg)
	require.NoError(t, err)

	engB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Registry:       reg,
		Codec:          reconcile.JSONCodec[string]{},
		Auth:           reconcile.NoopAuthenticator,
		Detector:       det,
		Applier:        testutil.InsertTestApplier(storeB),
		MaxWantDigests: 2,
		Timeout:        150 * time.Millisecond,
		StoreID:        "data",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", engB))
	_, cc := startLoopbackMux(t, mux)
	client := reconpb.NewReconcileServiceClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Exceed MaxWantDigests even when digests are in Available
	stream1, err := client.Reconcile(testutil.OutgoingContext(ctx, "data", "static/1"))
	require.NoError(t, err)
	require.NoError(t, stream1.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{Negotiate: &reconpb.NegotiatePayload{Done: true}},
	}))
	_, err = stream1.Recv()
	require.NoError(t, err)
	require.NoError(t, stream1.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_WantDigests{
			WantDigests: &reconpb.WantDigests{
				Digests: [][]byte{
					digestmaps.EncodeDigestSymbol(d1),
					digestmaps.EncodeDigestSymbol(d2),
					digestmaps.EncodeDigestSymbol(d3),
				},
			},
		},
	}))
	_, err = stream1.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.ErrorIs(t, det.Last(), reconcile.ErrSessionLimitExceeded)

	// 2. Phase 1 stall hits server-side Timeout
	streamP1, err := client.Reconcile(testutil.OutgoingContext(ctx, "data", "stall/1"))
	require.NoError(t, err)
	_, err = streamP1.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

	// 3. Phase 2 stall hits server-side Timeout
	streamP2, err := client.Reconcile(testutil.OutgoingContext(ctx, "data", "static/1"))
	require.NoError(t, err)
	require.NoError(t, streamP2.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{Negotiate: &reconpb.NegotiatePayload{Done: true}},
	}))
	_, err = streamP2.Recv() // Phase 1 Done
	require.NoError(t, err)
	_, err = streamP2.Recv() // stalls in Phase 2 until server timeout
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
}

func TestEngine_RegistryMuxAndMixedProtocols(t *testing.T) {
	// Registry validation
	reg, err := reconcile.NewRegistry(naive.NewNegotiator(), ratelessIBLT.NewNegotiator())
	require.NoError(t, err)
	require.Error(t, reg.Register(nil))
	require.Error(t, reg.Register(naive.NewNegotiator())) // duplicate
	_, err = reg.Get("unknown/9")
	require.ErrorIs(t, err, reconcile.ErrUnknownProtocol)

	// Two stores on ONE Mux: "store-riblt" (default riblt/1) and "store-naive" (naive/1),
	// plus shared Registry so "store-riblt" also accepts inbound naive/1!
	ribltA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	ribltB, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	ribltA.InsertBatch("r-shared", "r-only-a")
	ribltB.InsertBatch("r-shared", "r-only-b")

	naiveA, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	naiveB, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	naiveA.InsertBatch("n-shared", "n-only-a")
	naiveB.InsertBatch("n-shared", "n-only-b")

	engRibltB, err := reconcile.NewEngine(ribltB, reconcile.Config[string]{
		Negotiator: ribltB.Negotiator(),
		Registry:   reg,
		Codec:      reconcile.JSONCodec[string]{},
		Auth:       reconcile.NoopAuthenticator,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    testutil.InsertTestApplier(ribltB),
		StoreID:    "store-riblt",
	})
	require.NoError(t, err)
	engNaiveB, err := reconcile.NewEngine(naiveB, reconcile.Config[string]{
		Negotiator: naiveB.Negotiator(),
		Registry:   reg,
		Codec:      reconcile.JSONCodec[string]{},
		Auth:       reconcile.NoopAuthenticator,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    testutil.InsertTestApplier(naiveB),
		StoreID:    "store-naive",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("store-riblt", engRibltB))
	require.ErrorIs(t, mux.RegisterStore("store-riblt", engRibltB), reconcile.ErrStoreAlreadyRegistered)
	require.NoError(t, mux.RegisterStore("store-naive", engNaiveB))

	addr, cc := startLoopbackMux(t, mux)
	connProv := func(context.Context, string) (grpc.ClientConnInterface, error) { return cc, nil }

	engRibltA, err := reconcile.NewEngine(ribltA, reconcile.Config[string]{
		Negotiator:   ribltA.Negotiator(),
		Codec:        reconcile.JSONCodec[string]{},
		ConnProvider: connProv,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(ribltA),
		StoreID:      "store-riblt",
	})
	require.NoError(t, err)
	engNaiveA, err := reconcile.NewEngine(naiveA, reconcile.Config[string]{
		Negotiator:   naiveA.Negotiator(),
		Codec:        reconcile.JSONCodec[string]{},
		ConnProvider: connProv,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(naiveA),
		StoreID:      "store-naive",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Both stores reconcile using their respective protocols on the same Mux.
	_, err = engRibltA.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, ribltA.Fingerprint(), ribltB.Fingerprint())

	_, err = engNaiveA.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, naiveA.Fingerprint(), naiveB.Fingerprint())

	// 2. Peer initiates with naive/1 against "store-riblt" (whose outbound default is riblt/1).
	ribltA.Insert("cross-proto-item")
	crossEngA, err := reconcile.NewEngine(ribltA, reconcile.Config[string]{
		Negotiator:   naive.NewNegotiator(),
		Codec:        reconcile.JSONCodec[string]{},
		ConnProvider: connProv,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(ribltA),
		StoreID:      "store-riblt",
	})
	require.NoError(t, err)
	_, err = crossEngA.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	_, hasCross := ribltB.Contains("cross-proto-item")
	assert.True(t, hasCross)

	// 3. Unknown protocol header fails explicitly with codes.Unimplemented.
	badStream, err := reconpb.NewReconcileServiceClient(cc).Reconcile(testutil.OutgoingContext(ctx, "store-riblt", "bogus/99"))
	require.NoError(t, err)
	_, err = badStream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestEngine_ErrIgnoreSkipsWithoutMisbehaviorOrAbort(t *testing.T) {
	storeA := newTestStore(t, "keep-1", "stale-val", "stale-apply", "keep-2")
	storeB := newTestStore(t)

	detB := &testutil.RecordingDetector[string]{
		ValidateFn: func(_ context.Context, item string) error {
			if item == "stale-val" {
				return errors.Join(reconcile.ErrIgnore, errors.New("old version"))
			}
			return nil
		},
	}

	engB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: naive.NewNegotiator(),
		Codec:      reconcile.JSONCodec[string]{},
		Auth:       reconcile.NoopAuthenticator,
		Detector:   detB,
		Applier: func(_ context.Context, item string) error {
			if item == "stale-apply" {
				return errors.Join(reconcile.ErrIgnore, errors.New("already superseded"))
			}
			storeB.Insert(item)
			return nil
		},
		StoreID: "data",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", engB))
	addr, cc := startLoopbackMux(t, mux)

	engA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   naive.NewNegotiator(),
		Codec:        reconcile.JSONCodec[string]{},
		ConnProvider: func(context.Context, string) (grpc.ClientConnInterface, error) { return cc, nil },
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "data",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sum, err := engA.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, 4, sum.ItemsSent)
	assert.Equal(t, 0, detB.Count(), "ErrIgnore must not trigger OnMisbehavior")
	assert.Equal(t, 2, storeB.Size())
	_, hasKeep1 := storeB.Contains("keep-1")
	_, hasKeep2 := storeB.Contains("keep-2")
	_, hasStaleVal := storeB.Contains("stale-val")
	_, hasStaleApply := storeB.Contains("stale-apply")
	assert.True(t, hasKeep1)
	assert.True(t, hasKeep2)
	assert.False(t, hasStaleVal)
	assert.False(t, hasStaleApply)

	// Also verify ItemsIgnored counter on the initiator side when initiator ignores an item from B.
	storeB.Insert("from-b-stale")
	storeB.Insert("from-b-valid")
	detA := &testutil.RecordingDetector[string]{}
	engA2, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   naive.NewNegotiator(),
		Codec:        reconcile.JSONCodec[string]{},
		ConnProvider: func(context.Context, string) (grpc.ClientConnInterface, error) { return cc, nil },
		Detector:     detA,
		Applier: func(_ context.Context, item string) error {
			if item == "from-b-stale" {
				return errors.Join(reconcile.ErrIgnore, errors.New("stale"))
			}
			storeA.Insert(item)
			return nil
		},
		StoreID: "data",
	})
	require.NoError(t, err)

	sum2, err := engA2.ReconcileWithPeer(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, 1, sum2.ItemsReceived)
	assert.Equal(t, 1, sum2.ItemsIgnored)
	assert.Equal(t, 0, detA.Count())
}
