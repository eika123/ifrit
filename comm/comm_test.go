package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/eika123/ifrit/protobuf"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func genTestKeyAndCert(t *testing.T, caCert *x509.Certificate, caPriv *ecdsa.PrivateKey, id []byte) (*ecdsa.PrivateKey, *x509.Certificate) {
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

type testGossipService struct {
	pb.UnimplementedGossipServer
	onSpread func(ctx context.Context, req *pb.State) (*pb.StateResponse, error)
}

func (s *testGossipService) Spread(ctx context.Context, req *pb.State) (*pb.StateResponse, error) {
	return s.onSpread(ctx, req)
}

func TestComm_RegisterServiceClientConnAndPeerCert(t *testing.T) {
	caPriv, caCert := genTestKeyAndCert(t, nil, nil, []byte("test-ca"))
	privA, certA := genTestKeyAndCert(t, caCert, caPriv, []byte("peer-a-id"))
	privB, certB := genTestKeyAndCert(t, caCert, caPriv, []byte("peer-b-id"))

	lisB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addrB := lisB.Addr().String()
	lisA, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	dbPath := filepath.Join(t.TempDir(), "telemetry.db")
	t.Setenv("IFRIT_TELEMETRY_DB", dbPath)

	commA, err := NewComm(certA, caCert, privA, lisA)
	require.NoError(t, err)
	defer commA.Stop()

	commB, err := NewComm(certB, caCert, privB, lisB)
	require.NoError(t, err)
	defer commB.Stop()

	var seenCert *x509.Certificate
	svc := &testGossipService{
		onSpread: func(ctx context.Context, req *pb.State) (*pb.StateResponse, error) {
			cert, err := PeerCertFromContext(ctx)
			require.NoError(t, err)
			seenCert = cert
			return &pb.StateResponse{}, nil
		},
	}

	// Verify Comm routes generic gRPC service registrations onto its mTLS server.
	commB.RegisterGRPC(func(s *grpc.Server) {
		pb.RegisterGossipServer(s, svc)
	})

	go commB.Start()

	// Pooled ClientConn must return the same underlying connection on repeat calls.
	cc1, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	require.NotNil(t, cc1)

	cc2, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	assert.Same(t, cc1, cc2)

	client := pb.NewGossipClient(cc1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Spread(ctx, &pb.State{})
	require.NoError(t, err)
	require.NotNil(t, seenCert)
	assert.Equal(t, []byte("peer-a-id"), seenCert.SubjectKeyId)

	// Verify telemetry interceptor recorded the RPC made over ClientConn.
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM gossip_exchange`).Scan(&count))
	assert.GreaterOrEqual(t, count, 1)
}

func TestPeerCertFromContext_Errors(t *testing.T) {
	_, err := PeerCertFromContext(context.Background())
	require.Error(t, err)
}
