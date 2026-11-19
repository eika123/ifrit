package ratelessIBLT

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/internal/testutil"
	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yangl1996/riblt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReconciler_MTLSOverCommAndMux(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	auth := func(ctx context.Context) error {
		_, err := comm.PeerCertFromContext(ctx)
		return err
	}
	connProvA := testutil.CommConnProvider(commA)

	baseCertA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	baseCertB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	baseDataA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	baseDataB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	storeCertA := NewRatelessIBLTStore(baseCertA, 64)
	storeCertB := NewRatelessIBLTStore(baseCertB, 64)
	storeDataA := NewRatelessIBLTStore(baseDataA, 16) // small sketch to exercise rateless fallback
	storeDataB := NewRatelessIBLTStore(baseDataB, 16)

	storeCertA.InsertBatch("cert-1", "cert-2")
	storeCertB.InsertBatch("cert-2", "cert-3")

	for i := range 30 {
		storeDataA.Insert(fmt.Sprintf("item-a-%d", i))
		storeDataB.Insert(fmt.Sprintf("item-b-%d", i))
	}

	recCertA, err := reconcile.NewEngine(storeCertA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: connProvA,
		Auth:         auth,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeCertA),
		StoreID:      "certs",
		MaxItemBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	recCertB, err := reconcile.NewEngine(storeCertB, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		Auth:         auth,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeCertB),
		StoreID:      "certs",
		MaxItemBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	recDataA, err := reconcile.NewEngine(storeDataA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: connProvA,
		Auth:         auth,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeDataA),
		StoreID:      "data",
		MaxItemBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	recDataB, err := reconcile.NewEngine(storeDataB, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		Auth:         auth,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeDataB),
		StoreID:      "data",
		MaxItemBytes: 1024 * 1024,
	})
	require.NoError(t, err)

	muxB := reconcile.NewMux()
	require.NoError(t, muxB.RegisterStore("certs", recCertB))
	require.NoError(t, muxB.RegisterStore("data", recDataB))
	muxB.Register(commB)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Reconcile only "certs": "data" on B must remain untouched.
	summaryCert, err := recCertA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 1, summaryCert.ItemsSent)
	assert.Equal(t, 1, summaryCert.ItemsReceived)
	assert.Equal(t, storeCertA.Fingerprint(), storeCertB.Fingerprint())
	assert.Equal(t, digestmaps.EncodeDigestSymbol(storeCertB.Fingerprint()), summaryCert.RemoteFingerprint)
	assert.Equal(t, 30, storeDataB.Size())

	// 1b. Second pass with zero diff still populates RemoteFingerprint from Phase 1.
	summaryZero, err := recCertA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 0, summaryZero.DigestsRequested)
	assert.Equal(t, 0, summaryZero.DigestsAvailable)
	assert.Equal(t, digestmaps.EncodeDigestSymbol(storeCertB.Fingerprint()), summaryZero.RemoteFingerprint)

	// 2. Reconcile "data" with > sketch capacity (triggers UsedFallback).
	summaryData, err := recDataA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.True(t, summaryData.UsedFallback)
	assert.Equal(t, 60, storeDataA.Size())
	assert.Equal(t, 60, storeDataB.Size())
	assert.Equal(t, storeDataA.Fingerprint(), storeDataB.Fingerprint())

	// 3. Unknown store-id must fail cleanly.
	cc, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	badCtx := testutil.OutgoingContext(ctx, "unknown", ProtocolName)
	stream, err := reconpb.NewReconcileServiceClient(cc).Reconcile(badCtx)
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestReconciler_AuthRejectionAndItemApplier(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	baseA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	baseB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	storeA := NewRatelessIBLTStore(baseA, 64)
	storeB := NewRatelessIBLTStore(baseB, 64)
	storeA.InsertBatch("valid-item", "rejected-item")

	detReject := &testutil.RecordingDetector[string]{}
	recBReject, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: NewNegotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth: func(context.Context) error {
			return status.Error(codes.PermissionDenied, "unauthorized peer")
		},
		Detector: detReject,
		Applier:  testutil.InsertTestApplier(storeB),
	})
	require.NoError(t, err)
	recA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "notes",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("notes", recBReject))
	mux.Register(commB)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.Equal(t, 0, storeB.Size())
	assert.GreaterOrEqual(t, detReject.Count(), 1)

	detApplier := &testutil.RecordingDetector[string]{}
	recBApplier, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: NewNegotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth: func(ctx context.Context) error {
			_, err := comm.PeerCertFromContext(ctx)
			return err
		},
		Detector: detApplier,
		Applier: func(_ context.Context, item string) error {
			if item == "rejected-item" {
				return errors.New("policy rejected")
			}
			storeB.Insert(item)
			return nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, mux.RegisterStore("notes-applier", recBApplier))
	recA2, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "notes-applier",
	})
	require.NoError(t, err)

	_, err = recA2.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.GreaterOrEqual(t, detApplier.Count(), 1)
	_, hasNotRejected := storeB.Contains("rejected-item")
	assert.False(t, hasNotRejected)
}

func TestReconciler_MaxItemBytesAndMaxSymbolsLimit(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	baseA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	baseB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	storeA := NewRatelessIBLTStore(baseA, 16)
	storeB := NewRatelessIBLTStore(baseB, 16)
	for i := 0; i < 60; i++ {
		storeA.Insert(fmt.Sprintf("item-%d", i))
	}

	det := &testutil.RecordingDetector[string]{}
	recB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: NewNegotiator(WithMaxSymbols(24)),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       reconcile.NoopAuthenticator,
		Detector:   det,
		Applier:    testutil.InsertTestApplier(storeB),
	})
	require.NoError(t, err)
	recA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "sym-limit",
	})
	require.NoError(t, err)

	// Separate store testing MaxItemBytes
	smallA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string](), 64)
	require.NoError(t, err)
	smallB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string](), 64)
	require.NoError(t, err)
	smallA.Insert("this-string-exceeds-16-bytes-easily")

	detSize := &testutil.RecordingDetector[string]{}
	recSmallB, err := reconcile.NewEngine(smallB, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		Auth:         reconcile.NoopAuthenticator,
		Detector:     detSize,
		Applier:      testutil.InsertTestApplier(smallB),
		MaxItemBytes: 16,
	})
	require.NoError(t, err)
	recSmallA, err := reconcile.NewEngine(smallA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(smallA),
		StoreID:      "size-limit",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("sym-limit", recB))
	require.NoError(t, mux.RegisterStore("size-limit", recSmallB))
	mux.Register(commB)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(errors.Unwrap(err)))
	assert.GreaterOrEqual(t, det.Count(), 1)

	_, err = recSmallA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.GreaterOrEqual(t, detSize.Count(), 1)
}

func TestStore_CopyAndRemovePreserveSketchIntegrity(t *testing.T) {
	base, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	orig := NewRatelessIBLTStore(base, 64)
	orig.InsertBatch("a", "b", "c")

	// Copy must preserve sketch and stay independent of subsequent mutations.
	cpAny := orig.Copy()
	cp, ok := cpAny.(*Store[string, digestmaps.DigestSymbol])
	require.True(t, ok, "Copy() must return a *Store preserving the RIBLT sketch")
	require.Len(t, cp.SnapshotSketch(), 64)

	orig.Insert("d")
	assert.False(t, cp.ContainsDigest(orig.Digest("d")))

	// Subtracting sketches of orig and cp must decode cleanly to exactly {"d"}.
	diffSketch := orig.SnapshotSketch()
	diffSketch.Subtract(cp.SnapshotSketch())
	fwd, rev, decoded := diffSketch.Decode()
	require.True(t, decoded)
	require.Len(t, fwd, 1)
	assert.Equal(t, orig.Digest("d"), fwd[0].Symbol)
	assert.Empty(t, rev)

	// Remove on orig must keep its sketch in sync with cp!
	require.True(t, orig.Remove("d"))
	diffAfterRemove := orig.SnapshotSketch()
	diffAfterRemove.Subtract(cp.SnapshotSketch())
	fwd, rev, decoded = diffAfterRemove.Decode()
	require.True(t, decoded)
	assert.Empty(t, fwd)
	assert.Empty(t, rev)
}

func TestNegotiator_PlainReverseIndexStoreFallback(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	// Plain DigestSet (does NOT implement SketchStore) reconciles over riblt/1 cleanly.
	plainA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	plainB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	plainA.InsertBatch("shared", "plain-a-1", "plain-a-2")
	plainB.InsertBatch("shared", "plain-b-1")

	engB, err := reconcile.NewEngine(plainB, reconcile.Config[string]{
		Negotiator: NewNegotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       reconcile.NoopAuthenticator,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    testutil.InsertTestApplier(plainB),
		StoreID:    "plain",
	})
	require.NoError(t, err)
	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("plain", engB))
	mux.Register(commB)
	go commB.Start()

	engA, err := reconcile.NewEngine(plainA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(plainA),
		StoreID:      "plain",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sum, err := engA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 2, sum.ItemsSent)
	assert.Equal(t, 1, sum.ItemsReceived)
	assert.Equal(t, plainA.Fingerprint(), plainB.Fingerprint())
}

type singleShotEOFTransport struct {
	batch []riblt.CodedSymbol[digestmaps.DigestSymbol]
	sent  bool
}

func (t *singleShotEOFTransport) RecvCoded() ([]riblt.CodedSymbol[digestmaps.DigestSymbol], bool, error) {
	if t.sent {
		return nil, true, nil
	}
	t.sent = true
	return t.batch, true, nil
}

func (t *singleShotEOFTransport) SendNeedMore() error { return nil }

func (t *singleShotEOFTransport) SendDiffPage(_, _ []riblt.HashedSymbol[digestmaps.DigestSymbol]) error {
	return nil
}

func TestReconcileServer_ProcessesFinalBatchReturnedWithEOF(t *testing.T) {
	baseA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	baseB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	storeA := NewRatelessIBLTStore(baseA, 0) // plain rateless fallback path
	storeB := NewRatelessIBLTStore(baseB, 0)
	storeA.InsertBatch("shared", "only-a")
	storeB.InsertBatch("shared", "only-b")

	// Generate enough coded symbols and deliver them in a single call with eof=true.
	enc := storeA.MakeEncoder()
	syms := make([]riblt.CodedSymbol[digestmaps.DigestSymbol], 32)
	for i := range syms {
		syms[i] = enc.ProduceNextCodedSymbol()
	}

	diff, err := ReconcileServer(&singleShotEOFTransport{batch: syms}, storeB)
	require.NoError(t, err)
	assert.Equal(t, []digestmaps.DigestSymbol{storeA.Digest("only-a")}, diff.Requested)
	assert.Equal(t, []digestmaps.DigestSymbol{storeB.Digest("only-b")}, diff.Available)

	// Insufficient symbols delivered with eof=true must return io.ErrUnexpectedEOF.
	_, err = ReconcileServer(&singleShotEOFTransport{batch: syms[:1]}, storeB)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
