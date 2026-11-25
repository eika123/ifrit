package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/eika123/ifrit/protobuf"
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

type testFirefliesService struct {
	pb.UnimplementedFirefliesServer
	onAnnounce func(ctx context.Context, req *pb.AnnounceRequest) (*pb.AnnounceResponse, error)
}

func (s *testFirefliesService) Announce(ctx context.Context, req *pb.AnnounceRequest) (*pb.AnnounceResponse, error) {
	return s.onAnnounce(ctx, req)
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

	var clientIntercepted atomic.Int32
	var serverIntercepted atomic.Int32

	commA, err := NewComm(
		certA, caCert, privA, lisA,
		WithUnaryClientInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			clientIntercepted.Add(1)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
	)
	require.NoError(t, err)
	defer commA.Stop()

	commB, err := NewComm(
		certB, caCert, privB, lisB,
		WithUnaryServerInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			serverIntercepted.Add(1)
			return handler(ctx, req)
		}),
	)
	require.NoError(t, err)
	defer commB.Stop()

	var seenCert *x509.Certificate
	svc := &testFirefliesService{
		onAnnounce: func(ctx context.Context, req *pb.AnnounceRequest) (*pb.AnnounceResponse, error) {
			cert, err := PeerCertFromContext(ctx)
			require.NoError(t, err)
			seenCert = cert
			return &pb.AnnounceResponse{}, nil
		},
	}

	// Verify Comm registers a gRPC service onto its mTLS server via grpc.ServiceRegistrar.
	pb.RegisterFirefliesServer(commB, svc)

	go commB.Start()

	// Pooled ClientConn must return the same underlying connection on repeat calls.
	cc1, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	require.NotNil(t, cc1)

	cc2, err := commA.ClientConn(addrB)
	require.NoError(t, err)
	assert.Same(t, cc1, cc2)

	client := pb.NewFirefliesClient(cc1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Announce(ctx, &pb.AnnounceRequest{})
	require.NoError(t, err)
	require.NotNil(t, seenCert)
	assert.Equal(t, []byte("peer-a-id"), seenCert.SubjectKeyId)

	// Verify injected client and server interceptors were invoked for the ClientConn RPC.
	assert.Equal(t, int32(1), clientIntercepted.Load())
	assert.Equal(t, int32(1), serverIntercepted.Load())
}

func TestPeerCertFromContext_Errors(t *testing.T) {
	_, err := PeerCertFromContext(context.Background())
	require.Error(t, err)
}

func TestComm_RegisterServiceAndUntrustedCARejection(t *testing.T) {
	caPriv, caCert := genTestKeyAndCert(t, nil, nil, []byte("trusted-ca"))
	privB, certB := genTestKeyAndCert(t, caCert, caPriv, []byte("peer-b-id"))

	// Client signed by a completely different CA.
	rogueCAPriv, rogueCACert := genTestKeyAndCert(t, nil, nil, []byte("rogue-ca"))
	privRogue, certRogue := genTestKeyAndCert(t, rogueCACert, rogueCAPriv, []byte("rogue-peer"))

	lisB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addrB := lisB.Addr().String()
	lisRogue, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	commB, err := NewComm(certB, caCert, privB, lisB)
	require.NoError(t, err)
	defer commB.Stop()

	commRogue, err := NewComm(certRogue, rogueCACert, privRogue, lisRogue)
	require.NoError(t, err)
	defer commRogue.Stop()

	var handlerCalled atomic.Bool
	svc := &testFirefliesService{
		onAnnounce: func(ctx context.Context, req *pb.AnnounceRequest) (*pb.AnnounceResponse, error) {
			handlerCalled.Store(true)
			return &pb.AnnounceResponse{}, nil
		},
	}

	// Register directly via RegisterService.
	pb.RegisterFirefliesServer(commB, svc)
	go commB.Start()

	cc, err := commRogue.ClientConn(addrB)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = pb.NewFirefliesClient(cc).Announce(ctx, &pb.AnnounceRequest{})
	require.Error(t, err)
	assert.False(t, handlerCalled.Load(), "untrusted CA client must be rejected by mTLS before reaching RPC handler")
}
