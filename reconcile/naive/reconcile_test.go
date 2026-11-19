package naive

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/internal/testutil"
	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNaiveReconciler_MTLSOverCommAndMux(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	storeCertA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeCertB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeDataA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeDataB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	storeCertA.InsertBatch("cert-a", "cert-shared")
	storeCertB.InsertBatch("cert-b", "cert-shared")
	for i := 0; i < 20; i++ {
		storeDataA.Insert(fmt.Sprintf("item-a-%d", i))
		storeDataB.Insert(fmt.Sprintf("item-b-%d", i))
	}

	auth := func(ctx context.Context) error {
		cert, err := comm.PeerCertFromContext(ctx)
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}
		if string(cert.SubjectKeyId) != "peer-a" {
			return status.Error(codes.PermissionDenied, "unknown peer")
		}
		return nil
	}
	connProvA := testutil.CommConnProvider(commA)

	recCertA, err := reconcile.NewEngine(storeCertA, reconcile.Config[string]{
		Negotiator:   storeCertA.Negotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: connProvA,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeCertA),
		StoreID:      "certs",
	})
	require.NoError(t, err)
	recCertB, err := reconcile.NewEngine(storeCertB, reconcile.Config[string]{
		Negotiator: storeCertB.Negotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       auth,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    testutil.InsertTestApplier(storeCertB),
		StoreID:    "certs",
	})
	require.NoError(t, err)
	recDataA, err := reconcile.NewEngine(storeDataA, reconcile.Config[string]{
		Negotiator:   storeDataA.Negotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: connProvA,
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeDataA),
		StoreID:      "data",
		MaxItemBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	recDataB, err := reconcile.NewEngine(storeDataB, reconcile.Config[string]{
		Negotiator:   storeDataB.Negotiator(),
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

	// 1. Reconcile "certs" store.
	sumCert, err := recCertA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 1, sumCert.ItemsSent)
	assert.Equal(t, 1, sumCert.ItemsReceived)
	assert.Equal(t, storeCertA.Fingerprint(), storeCertB.Fingerprint())
	assert.Equal(t, digestmaps.EncodeDigestSymbol(storeCertB.Fingerprint()), sumCert.RemoteFingerprint)

	// Zero-diff run still captures RemoteFingerprint.
	sumCertZero, err := recCertA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 0, sumCertZero.ItemsSent)
	assert.Equal(t, 0, sumCertZero.ItemsReceived)
	assert.Equal(t, digestmaps.EncodeDigestSymbol(storeCertB.Fingerprint()), sumCertZero.RemoteFingerprint)

	// 2. Reconcile "data" store.
	sumData, err := recDataA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 20, sumData.ItemsSent)
	assert.Equal(t, 20, sumData.ItemsReceived)
	assert.Equal(t, 40, storeDataA.Size())
	assert.Equal(t, 40, storeDataB.Size())
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

func TestNaiveReconciler_AuthEnforcedBeforeDataExchange(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB.Insert("secret-server-item")

	recB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: storeB.Negotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth: func(context.Context) error {
			return status.Error(codes.PermissionDenied, "unauthorized peer")
		},
		Detector: reconcile.AcceptAll[string](),
		Applier:  testutil.InsertTestApplier(storeB),
	})
	require.NoError(t, err)
	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", recB))
	mux.Register(commB)
	go commB.Start()

	cc, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	client := reconpb.NewReconcileServiceClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outCtx := testutil.OutgoingContext(ctx, "data", ProtocolName)

	stream, err := client.Reconcile(outCtx)
	require.NoError(t, err)
	_ = stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{Negotiate: &reconpb.NegotiatePayload{Done: true}},
	})
	resp, err := stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Nil(t, resp)
}

func TestNaiveReconciler_LargeBatchedDigestExchange(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	storeA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	// 40,000 items crosses the 32,768 batch boundary.
	const sharedCount = 40000
	shared := make([]string, sharedCount)
	for i := 0; i < sharedCount; i++ {
		shared[i] = fmt.Sprintf("shared-%d", i)
	}
	storeA.InsertBatch(shared...)
	storeB.InsertBatch(shared...)
	storeA.Insert("only-on-a")
	storeB.Insert("only-on-b")

	recA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   storeA.Negotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "data",
	})
	require.NoError(t, err)
	recB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: storeB.Negotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       reconcile.NoopAuthenticator,
		Detector:   reconcile.AcceptAll[string](),
		Applier:    testutil.InsertTestApplier(storeB),
		StoreID:    "data",
	})
	require.NoError(t, err)

	muxB := reconcile.NewMux()
	require.NoError(t, muxB.RegisterStore("data", recB))
	muxB.Register(commB)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sum, err := recA.ReconcileWithPeer(ctx, addrB)
	require.NoError(t, err)
	assert.Equal(t, 1, sum.ItemsSent)
	assert.Equal(t, 1, sum.ItemsReceived)
	assert.Equal(t, sharedCount+2, storeA.Size())
	assert.Equal(t, sharedCount+2, storeB.Size())
	assert.Equal(t, storeA.Fingerprint(), storeB.Fingerprint())
}

func TestNaiveReconciler_ItemApplierAndFramingGuards(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	storeA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeA.InsertBatch("valid-item", "rejected-item")

	det := &testutil.RecordingDetector[string]{}
	recB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: storeB.Negotiator(),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       reconcile.NoopAuthenticator,
		Detector:   det,
		Applier: func(_ context.Context, item string) error {
			if item == "rejected-item" {
				return errors.New("policy rejected")
			}
			storeB.Insert(item)
			return nil
		},
		StoreID: "data",
	})
	require.NoError(t, err)
	recA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   storeA.Negotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "data",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", recB))
	mux.Register(commB)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.GreaterOrEqual(t, det.Count(), 1)
	_, hasRejected := storeB.Contains("rejected-item")
	assert.False(t, hasRejected)
}

func TestNaiveReconciler_MaxDigestsLimitAndMalformedPayload(t *testing.T) {
	commA, commB, addrB := testutil.SetupCommPair(t)

	storeA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeA.InsertBatch("a", "b", "c", "d", "e")

	det := &testutil.RecordingDetector[string]{}
	recB, err := reconcile.NewEngine(storeB, reconcile.Config[string]{
		Negotiator: NewNegotiator(WithMaxDigests(3)),
		Codec:      reconcile.DefaultItemCodec[string](),
		Auth:       reconcile.NoopAuthenticator,
		Detector:   det,
		Applier:    testutil.InsertTestApplier(storeB),
		StoreID:    "data",
	})
	require.NoError(t, err)
	recA, err := reconcile.NewEngine(storeA, reconcile.Config[string]{
		Negotiator:   NewNegotiator(),
		Codec:        reconcile.DefaultItemCodec[string](),
		ConnProvider: testutil.CommConnProvider(commA),
		Detector:     reconcile.AcceptAll[string](),
		Applier:      testutil.InsertTestApplier(storeA),
		StoreID:      "data",
	})
	require.NoError(t, err)

	mux := reconcile.NewMux()
	require.NoError(t, mux.RegisterStore("data", recB))
	mux.Register(commB)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Exceed MaxDigests
	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(errors.Unwrap(err)))
	assert.GreaterOrEqual(t, det.Count(), 1)

	// 2. Malformed binary digest batch (not multiple of 8 bytes)
	cc, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	outCtx := testutil.OutgoingContext(ctx, "data", ProtocolName)
	stream, err := reconpb.NewReconcileServiceClient(cc).Reconcile(outCtx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&reconpb.Frame{
		Payload: &reconpb.Frame_Negotiate{
			Negotiate: &reconpb.NegotiatePayload{Data: []byte{1, 2, 3}, Done: true},
		},
	}))
	_, err = stream.Recv()
	require.Error(t, err)
	assert.GreaterOrEqual(t, det.Count(), 2)
}
