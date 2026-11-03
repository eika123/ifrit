package core

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
)

func (suite *HandlerTestSuite) TestEvalCertificate() {
	node := suite.n

	rings := node.view.NumRings()
	live := node.view.Live()
	peer := live[0]

	tests := []struct {
		cert   *x509.Certificate
		out    error
		exists bool

		nonNilError bool
	}{
		{
			cert:        nil,
			out:         errNilCert,
			exists:      false,
			nonNilError: false,
		},

		{
			cert:        node.idCatalog.Certificate(),
			out:         errSelfCert,
			exists:      false,
			nonNilError: false,
		},

		{
			cert:        genInvalidIdCert(suite.privMap[peer.Id], rings),
			out:         errInvalidId,
			exists:      false,
			nonNilError: false,
		},

		{
			cert:        genInvalidSignatureCert(suite.privMap[peer.Id], rings),
			out:         errSelfCert,
			exists:      false,
			nonNilError: true,
		},

		{
			cert:        genCert(suite.privMap[peer.Id], rings),
			out:         nil,
			exists:      true,
			nonNilError: false,
		},

		{
			cert:        genCert(suite.privMap[peer.Id], rings),
			out:         nil,
			exists:      true,
			nonNilError: false,
		},
	}
	for i, t := range tests {
		valErr := node.validateCertificate(t.cert)
		if !t.nonNilError {
			require.Equalf(suite.T(), t.out, valErr,
				"Invalid output for test %d.", i)
		} else {
			require.Errorf(suite.T(), valErr,
				"Invalid output for test %d.", i)
		}

		if valErr == nil {
			err := node.evalValidCertificate(t.cert)
			require.NoError(suite.T(), err, "evalValidCertificate should succeed for valid cert")
		}

		if t.cert != nil {
			require.Equalf(suite.T(), t.exists, node.view.Exists(string(t.cert.SubjectKeyId)),
				"Invalid exists state for test %d.", i)
		}
	}
}

func (suite *HandlerTestSuite) TestValidateCtx() {
	node := suite.n

	live := node.view.Live()
	peer := live[0]

	validCert := genCert(suite.privMap[peer.Id], node.view.NumRings())

	noAuthInfo := &grpcPeer.Peer{
		AuthInfo: credentials.TLSInfo{},
	}

	validAuthInfo := &grpcPeer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{validCert},
			},
		},
	}

	tests := []struct {
		ctx context.Context
		out error

		cert *x509.Certificate
	}{
		{
			ctx:  context.Background(),
			out:  errNoPeerInCtx,
			cert: nil,
		},

		{
			ctx:  grpcPeer.NewContext(context.Background(), &grpcPeer.Peer{}),
			out:  errNoTLSInfo,
			cert: nil,
		},

		{
			ctx:  grpcPeer.NewContext(context.Background(), noAuthInfo),
			out:  errNoCert,
			cert: nil,
		},

		{
			ctx:  grpcPeer.NewContext(context.Background(), validAuthInfo),
			out:  nil,
			cert: validCert,
		},
	}
	for i, t := range tests {
		c, err := node.validateCtx(t.ctx)
		require.Equalf(suite.T(), t.out, err, "Invalid output for test %d.", i)
		require.Equalf(suite.T(), t.cert, c, "Invalid output for test %d.", i)
	}
}
