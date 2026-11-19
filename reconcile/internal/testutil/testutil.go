package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	// DefaultPeerAID and DefaultPeerBID are the SubjectKeyIds used by SetupCommPair.
	DefaultPeerAID = "peer-a"
	DefaultPeerBID = "peer-b"
)

// InsertTestApplier returns an ItemApplier for tests that inserts every validated
// item directly into store without additional semantic checks.
func InsertTestApplier[T any](store digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]) reconcile.ItemApplier[T] {
	return func(_ context.Context, item T) error {
		store.Insert(item)
		return nil
	}
}

// RecordingDetector is a thread-safe TamperDetector for tests that records every
// OnMisbehavior error and optionally runs ValidateFn on each item.
type RecordingDetector[T any] struct {
	ValidateFn func(context.Context, T) error

	mu     sync.Mutex
	errors []error
}

func (d *RecordingDetector[T]) ValidateItem(ctx context.Context, item T) error {
	if d.ValidateFn != nil {
		return d.ValidateFn(ctx, item)
	}
	return nil
}

func (d *RecordingDetector[T]) OnMisbehavior(_ context.Context, err error, _ []byte) {
	d.mu.Lock()
	d.errors = append(d.errors, err)
	d.mu.Unlock()
}

func (d *RecordingDetector[T]) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.errors)
}

func (d *RecordingDetector[T]) Last() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.errors) == 0 {
		return nil
	}
	return d.errors[len(d.errors)-1]
}

// GenMTLSKeyAndCert generates an ECDSA keypair and X.509 certificate for loopback mTLS tests.
// When caCert is nil, a self-signed CA certificate is created.
func GenMTLSKeyAndCert(t *testing.T, caCert *x509.Certificate, caPriv *ecdsa.PrivateKey, id []byte) (*ecdsa.PrivateKey, *x509.Certificate) {
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

// SetupCommPair creates a pair of loopback mTLS comm.Comm instances ("peer-a" and "peer-b")
// signed by a shared test CA, registers t.Cleanup hooks to stop both, and returns (commA, commB, addrB).
func SetupCommPair(t *testing.T) (*comm.Comm, *comm.Comm, string) {
	t.Helper()

	caPriv, caCert := GenMTLSKeyAndCert(t, nil, nil, []byte("ca"))
	privA, certA := GenMTLSKeyAndCert(t, caCert, caPriv, []byte(DefaultPeerAID))
	privB, certB := GenMTLSKeyAndCert(t, caCert, caPriv, []byte(DefaultPeerBID))

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

// CommConnProvider adapts comm.Comm.ClientConn to reconcile.ConnProvider.
func CommConnProvider(c *comm.Comm) reconcile.ConnProvider {
	return func(_ context.Context, addr string) (grpc.ClientConnInterface, error) {
		return c.ClientConn(addr)
	}
}

// OutgoingContext attaches store-id and reconcile-protocol gRPC metadata headers to ctx.
func OutgoingContext(ctx context.Context, storeID, protoName string) context.Context {
	pairs := make([]string, 0, 4)
	if storeID != "" {
		pairs = append(pairs, reconcile.StoreIDMetadataKey, storeID)
	}
	if protoName != "" {
		pairs = append(pairs, reconcile.ProtocolMetadataKey, protoName)
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(pairs...))
}
