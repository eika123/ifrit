package naive

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
	"github.com/eika123/ifrit/reconcile"
	naivepb "github.com/eika123/ifrit/reconcile/naive/proto"
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
	mu     sync.Mutex
	errors []error
}

func (d *recordingDetector[T]) ValidateItem(context.Context, T) error { return nil }
func (d *recordingDetector[T]) OnMisbehavior(_ context.Context, err error, _ []byte) {
	d.mu.Lock()
	d.errors = append(d.errors, err)
	d.mu.Unlock()
}
func (d *recordingDetector[T]) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.errors)
}

func setupCommPair(t *testing.T) (*comm.Comm, *comm.Comm, string) {
	t.Helper()

	caPriv, caCert := genMTLSKeyAndCert(t, nil, nil, []byte("ca"))
	privA, certA := genMTLSKeyAndCert(t, caCert, caPriv, []byte("peer-a"))
	privB, certB := genMTLSKeyAndCert(t, caCert, caPriv, []byte("peer-b"))

	lisA, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	lisB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addrB := lisB.Addr().String()

	commA, err := comm.NewComm(certA, caCert, privA, lisA)
	require.NoError(t, err)
	t.Cleanup(commA.Stop)

	commB, err := comm.NewComm(certB, caCert, privB, lisB)
	require.NoError(t, err)
	t.Cleanup(commB.Stop)

	return commA, commB, addrB
}

func TestNaiveReconciler_MTLSOverCommAndMux(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

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

	recCertA := storeCertA.NewReconciler(reconcile.Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) { return commA.ClientConn(addr) },
		StoreID:      "certs",
	})
	recCertB := storeCertB.NewReconciler(reconcile.Config[string]{Auth: auth, StoreID: "certs"})
	recDataA := storeDataA.NewReconciler(reconcile.Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) { return commA.ClientConn(addr) },
		StoreID:      "data",
		MaxItemBytes: 1024 * 1024,
	})
	recDataB := storeDataB.NewReconciler(reconcile.Config[string]{Auth: auth, StoreID: "data", MaxItemBytes: 1024 * 1024})

	muxB := NewReconcilerMux()
	muxB.RegisterStore("certs", recCertB)
	muxB.RegisterStore("data", recDataB)
	commB.RegisterGRPC(muxB.RegisterGRPC)
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
	badCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("store-id", "unknown"))
	stream, err := naivepb.NewNaiveReconcilerClient(cc).ExchangeDigests(badCtx)
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
}

func TestNaiveReconciler_AuthEnforcedBeforeDataExchange(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB.Insert("secret-server-item")

	recB := storeB.NewReconciler(reconcile.Config[string]{
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
	client := naivepb.NewNaiveReconcilerClient(cc)
	transferClient := transferpb.NewItemTransferClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("store-id", "data"))

	// 1. ExchangeDigests rejects with PermissionDenied and leaks no fingerprint or digests.
	digStream, err := client.ExchangeDigests(outCtx)
	require.NoError(t, err)
	_ = digStream.Send(&naivepb.DigestBatch{})
	_ = digStream.CloseSend()
	resp, err := digStream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Nil(t, resp)

	// 2. Direct ItemTransfer.Sync stream rejects with PermissionDenied before any frame is exchanged.
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

func TestNaiveReconciler_LargeBatchedDigestExchange(t *testing.T) {
	commA, commB, addrB := setupCommPair(t)

	storeA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)

	// 40,000 items crosses the 32,768 DigestBatch / DigestDiffBatch boundary.
	const sharedCount = 40000
	shared := make([]string, sharedCount)
	for i := 0; i < sharedCount; i++ {
		shared[i] = fmt.Sprintf("shared-%d", i)
	}
	storeA.InsertBatch(shared...)
	storeB.InsertBatch(shared...)
	storeA.Insert("only-on-a")
	storeB.Insert("only-on-b")

	recA := storeA.NewReconciler(reconcile.Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) { return commA.ClientConn(addr) },
		StoreID:      "data",
	})
	recB := storeB.NewReconciler(reconcile.Config[string]{StoreID: "data"})

	muxB := NewReconcilerMux()
	muxB.RegisterStore("data", recB)
	commB.RegisterGRPC(muxB.RegisterGRPC)
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
	commA, commB, addrB := setupCommPair(t)

	storeA, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeB, err := NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	storeA.InsertBatch("valid-item", "rejected-item")

	det := &recordingDetector[string]{}
	recB := storeB.NewReconciler(reconcile.Config[string]{
		Detector: det,
		Applier: func(_ context.Context, item string) error {
			if item == "rejected-item" {
				return errors.New("policy rejected")
			}
			storeB.Insert(item)
			return nil
		},
		StoreID: "data",
	})
	recA := storeA.NewReconciler(reconcile.Config[string]{
		ConnProvider: func(_ context.Context, addr string) (grpc.ClientConnInterface, error) { return commA.ClientConn(addr) },
		StoreID:      "data",
	})

	mux := NewReconcilerMux()
	mux.RegisterStore("data", recB)
	commB.RegisterGRPC(mux.RegisterGRPC)
	go commB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = recA.ReconcileWithPeer(ctx, addrB)
	require.Error(t, err)
	assert.GreaterOrEqual(t, det.count(), 1)
	_, hasRejected := storeB.Contains("rejected-item")
	assert.False(t, hasRejected)
}
