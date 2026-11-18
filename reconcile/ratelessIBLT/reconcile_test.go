package ratelessIBLT

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/digestmaps"
	reconpb_riblt "github.com/eika123/ifrit/reconcile/ratelessIBLT/proto"
	transferpb "github.com/eika123/ifrit/reconcile/transfer/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func genMTLSKeyAndCert(t *testing.T, caCert *x509.Certificate, caPriv *ecdsa.PrivateKey, id []byte) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		SubjectKeyId:          id,
		Subject:               pkix.Name{Locality: []string{"127.0.0.1:0", "127.0.0.1:0"}},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if caCert == nil {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		caCert = tmpl
		caPriv = priv
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caPriv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return priv, cert
}

type recordingDetector[T any] struct {
	mu          sync.Mutex
	validateErr error
	misbehaved  []error
}

func (d *recordingDetector[T]) ValidateItem(_ context.Context, _ T) error {
	return d.validateErr
}

func (d *recordingDetector[T]) OnMisbehavior(_ context.Context, err error, _ []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.misbehaved = append(d.misbehaved, err)
}

func (d *recordingDetector[T]) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.misbehaved)
}

func setupCommPair(t *testing.T) (*comm.Comm, *comm.Comm, string) {
	t.Helper()
	caPriv, caCert := genMTLSKeyAndCert(t, nil, nil, []byte("ca"))
	privA, certA := genMTLSKeyAndCert(t, caCert, caPriv, []byte("node-a"))
	privB, certB := genMTLSKeyAndCert(t, caCert, caPriv, []byte("node-b"))

	lisA, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	lisB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addrB := lisB.Addr().String()

	cA, err := comm.NewComm(certA, caCert, privA, lisA)
	require.NoError(t, err)
	t.Cleanup(cA.Stop)

	cB, err := comm.NewComm(certB, caCert, privB, lisB)
	require.NoError(t, err)
	t.Cleanup(cB.Stop)

	return cA, cB, addrB
}

func TestReconciler_MTLSOverCommAndMux(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

	auth := func(ctx context.Context) error {
		_, err := comm.PeerCertFromContext(ctx)
		return err
	}
	connProvA := func(_ context.Context, addr string) (grpc.ClientConnInterface, error) {
		return commA.ClientConn(addr)
	}

	// Register two stores on Node B's ReconcilerMux: "certs" and "data".
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
	storeDataA := NewRatelessIBLTStore(baseDataA, 16) // small sketch to also exercise fallback
	storeDataB := NewRatelessIBLTStore(baseDataB, 16)

	storeCertA.InsertBatch("cert-1", "cert-2")
	storeCertB.InsertBatch("cert-2", "cert-3")

	for i := range 30 {
		storeDataA.Insert(fmt.Sprintf("item-a-%d", i))
		storeDataB.Insert(fmt.Sprintf("item-b-%d", i))
	}

	recCertA := NewReconciler(storeCertA, Config[string]{
		ConnProvider: connProvA,
		Auth:         auth,
		StoreID:      "certs",
		MaxItemBytes: 1024 * 1024,
	})
	recCertB := NewReconciler(storeCertB, Config[string]{
		Auth:         auth,
		StoreID:      "certs",
		MaxItemBytes: 1024 * 1024,
	})
	recDataA := NewReconciler(storeDataA, Config[string]{
		ConnProvider: connProvA,
		Auth:         auth,
		StoreID:      "data",
		MaxItemBytes: 1024 * 1024,
	})
	recDataB := NewReconciler(storeDataB, Config[string]{
		Auth:         auth,
		StoreID:      "data",
		MaxItemBytes: 1024 * 1024,
	})

	muxB := NewReconcilerMux()
	muxB.RegisterStore("certs", recCertB)
	muxB.RegisterStore("data", recDataB)
	commB.RegisterGRPC(muxB.RegisterGRPC)
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
	badCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("store-id", "unknown"))
	stream, err := reconpb_riblt.NewReconcilerClient(cc).ReconcileDigests(badCtx)
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestReconciler_AuthRejectionAndItemApplier(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

	baseA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	baseB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	storeA := NewRatelessIBLTStore(baseA, 64)
	storeB := NewRatelessIBLTStore(baseB, 64)
	storeA.InsertBatch("valid-item", "rejected-item")

	// Auth rejection on server
	detReject := &recordingDetector[string]{}
	recBReject := NewReconciler(storeB, Config[string]{
		Auth: func(context.Context) error {
			return status.Error(codes.PermissionDenied, "unauthorized peer")
		},
		Detector: detReject,
	})
	recA := NewReconciler(storeA, Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) {
			return commA.ClientConn(addr)
		},
		StoreID: "notes",
	})

	mux := NewReconcilerMux()
	mux.RegisterStore("notes", recBReject)
	commB.RegisterGRPC(mux.RegisterGRPC)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.Equal(t, 0, storeB.Size())
	assert.GreaterOrEqual(t, detReject.count(), 1)

	// Custom ItemApplier rejects "rejected-item" while accepting "valid-item".
	detApplier := &recordingDetector[string]{}
	recBApplier := NewReconciler(storeB, Config[string]{
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
	mux.RegisterStore("notes-applier", recBApplier)
	recA2 := NewReconciler(storeA, Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) {
			return commA.ClientConn(addr)
		},
		StoreID: "notes-applier",
	})

	_, err = recA2.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.GreaterOrEqual(t, detApplier.count(), 1)
	_, hasRejected := storeB.Contains("rejected-item")
	assert.False(t, hasRejected)
}

func TestReconciler_Phase2SecurityAndFramingGuards(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

	baseB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB := NewRatelessIBLTStore(baseB, 64)

	det := &recordingDetector[string]{}
	recB := NewReconciler(storeB, Config[string]{
		Detector:     det,
		MaxItemBytes: 16,
	})
	mux := NewReconcilerMux()
	mux.RegisterStore("data", recB)
	commB.RegisterGRPC(mux.RegisterGRPC)
	go commB.Start()

	cc, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	client := transferpb.NewItemTransferClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("store-id", "data"))

	// 1. Unsolicited DataHeader (zero items negotiated via Sync without WantDigests / ReconcileDigests)
	stream1, err := client.Sync(outCtx)
	require.NoError(t, err)
	require.NoError(t, stream1.Send(&transferpb.SyncFrame{
		Payload: &transferpb.SyncFrame_DataHeader{
			DataHeader: &transferpb.DataItemHeader{
				Digest:    digestmaps.EncodeDigestSymbol(12345),
				TotalSize: 4,
			},
		},
	}))
	_, err = stream1.Recv()
	require.Error(t, err)

	// 2. DataChunk without DataHeader (framing violation)
	stream2, err := client.Sync(outCtx)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(&transferpb.SyncFrame{
		Payload: &transferpb.SyncFrame_DataChunk{
			DataChunk: &transferpb.DataItemChunk{Data: []byte("orphan-chunk")},
		},
	}))
	_, err = stream2.Recv()
	require.Error(t, err)

	// 3. MaxItemBytes exceeded in DataHeader
	baseA, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeA := NewRatelessIBLTStore(baseA, 64)
	storeA.Insert("this-string-exceeds-16-bytes-easily")

	recA := NewReconciler(storeA, Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) {
			return commA.ClientConn(addr)
		},
		StoreID: "data",
	})
	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.GreaterOrEqual(t, det.count(), 3)
}

func TestReconciler_AuthEnforcedBeforeDataExchange(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

	baseB, err := digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB := NewRatelessIBLTStore(baseB, 64)
	storeB.Insert("secret-server-item")

	recB := NewReconciler(storeB, Config[string]{
		Auth: func(context.Context) error {
			return status.Error(codes.PermissionDenied, "unauthorized peer")
		},
	})
	mux := NewReconcilerMux()
	mux.RegisterStore("data", recB)
	commB.RegisterGRPC(mux.RegisterGRPC)
	go commB.Start()

	cc, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	client := reconpb_riblt.NewReconcilerClient(cc)
	transferClient := transferpb.NewItemTransferClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("store-id", "data"))

	// 1. ReconcileDigests must reject with PermissionDenied and leak no fingerprint or digests.
	digStream, err := client.ReconcileDigests(outCtx)
	require.NoError(t, err)
	_ = digStream.Send(&reconpb_riblt.ReconcileRequest{})
	_ = digStream.CloseSend()
	resp, err := digStream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Nil(t, resp)

	// 2. Direct Sync stream must reject with PermissionDenied before any frame is exchanged.
	stream, err := transferClient.Sync(outCtx)
	require.NoError(t, err)
	_ = stream.Send(&transferpb.SyncFrame{
		Payload: &transferpb.SyncFrame_WantDigests{
			WantDigests: &transferpb.WantDigests{
				Digests: [][]byte{digestmaps.EncodeDigestSymbol(storeB.Digest("secret-server-item"))},
			},
		},
	})
	frame, err := stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Nil(t, frame)
}
