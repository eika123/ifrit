package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"

	log "github.com/inconshreveable/log15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PeerTestSuite struct {
	suite.Suite
	priv *ecdsa.PrivateKey

	numRings uint32
	p        *Peer
	signer   signer
}

func (suite *PeerTestSuite) SetupTest() {
	var numRings uint32 = 5

	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err, "Failed to generate private key.")

	suite.priv = privKey

	id := "selfId"

	p := &Peer{
		Id:        id,
		publicKey: suite.priv.Public().(*ecdsa.PublicKey),
		cert: &x509.Certificate{
			SubjectKeyId: []byte(id),
			Subject: pkix.Name{
				Locality: []string{"rpcAddr", "pingAddr", "httpAddr"},
			},
			PublicKey: suite.priv.Public(),
		},
	}

	suite.p = p
	suite.numRings = numRings
	suite.signer = &signerMock{
		priv: suite.priv,
	}
}

func TestPeerTestSuite(t *testing.T) {
	r := log.Root()

	r.SetHandler(log.CallerFileHandler(log.StreamHandler(os.Stdout, log.TerminalFormat())))

	//r.SetHandler(log.DiscardHandler())
	suite.Run(t, new(PeerTestSuite))
}

func (suite *PeerTestSuite) TestNewPeer() {
	validCert := &x509.Certificate{
		SubjectKeyId: []byte("testId"),
		Subject: pkix.Name{
			Locality: []string{"rpcAddr", "pingAddr", "httpAddr"},
		},
		PublicKey: suite.priv.Public(),
	}

	noSubjectCert := &x509.Certificate{
		SubjectKeyId: []byte("testId"),
		PublicKey:    suite.priv.Public(),
	}

	noIdCert := &x509.Certificate{
		Subject: pkix.Name{
			Locality: []string{"rpcAddr", "pingAddr", "httpAddr"},
		},
		PublicKey: suite.priv.Public(),
	}

	noPubCert := &x509.Certificate{
		SubjectKeyId: []byte("testId"),
		Subject: pkix.Name{
			Locality: []string{"rpcAddr", "pingAddr", "httpAddr"},
		},
	}

	tests := []struct {
		in       *x509.Certificate
		numRings uint32
		err      error

		addr     string
		pingAddr string
		httpAddr string
		id       string
		pub      ecdsa.PublicKey
	}{
		{
			in:       validCert,
			numRings: suite.numRings,
			err:      nil,
			addr:     validCert.Subject.Locality[0],
			pingAddr: validCert.Subject.Locality[1],
			httpAddr: validCert.Subject.Locality[2],
			id:       string(validCert.SubjectKeyId),
		},

		{
			in:  validCert,
			err: errNoRings,
		},

		{
			in:       nil,
			numRings: suite.numRings,
			err:      errNoCert,
		},

		{
			in:       noSubjectCert,
			numRings: suite.numRings,
			err:      errPeerAddr,
		},

		{
			in:       noIdCert,
			numRings: suite.numRings,
			err:      errPeerId,
		},

		{
			in:       noPubCert,
			numRings: suite.numRings,
			err:      errPubKey,
		},
	}

	for i, t := range tests {
		p, err := newPeer(t.in, t.numRings)
		require.Equalf(suite.T(), t.err, err, "Invalid error for test %d", i)

		if t.err != nil {
			require.Nilf(suite.T(), p, "Invalid output for test %d", i)
		} else {
			require.NotNilf(suite.T(), p, "Invalid output for test %d", i)

			require.Equalf(suite.T(), t.addr, p.Addr, "Invalid addr for test %d", i)
			require.Equalf(suite.T(), t.pingAddr, p.PingAddr,
				"Invalid pingAddr for test %d", i)
			require.Equalf(suite.T(), t.httpAddr, p.HttpAddr, "Invalid error for test %d", i)
			require.Equalf(suite.T(), t.id, p.Id, "Invalid id for test %d", i)
		}

	}
}

func (suite *PeerTestSuite) TestCertificate() {
	p := &Peer{
		cert: &x509.Certificate{
			Raw: []byte("testCertificate"),
		},
	}

	nilCertPeer := &Peer{}

	tests := []struct {
		p   *Peer
		out []byte
	}{
		{
			p:   p,
			out: p.cert.Raw,
		},

		{
			p:   nilCertPeer,
			out: nil,
		},
	}

	for i, t := range tests {
		require.Equalf(suite.T(), t.out, t.p.Certificate(), "Invalid output for test %d", i)
	}
}

func (suite *PeerTestSuite) TestPublicKey() {
	pb, ok := suite.priv.Public().(*ecdsa.PublicKey)
	require.True(suite.T(), ok, "Failed to cast cert public key to ecdsa pub key")

	p := &Peer{
		publicKey: pb,
	}

	nilPubPeer := &Peer{}

	tests := []struct {
		p   *Peer
		out *ecdsa.PublicKey
	}{
		{
			p:   p,
			out: pb,
		},

		{
			p:   nilPubPeer,
			out: nil,
		},
	}

	for i, t := range tests {
		require.Equalf(suite.T(), t.out, t.p.PublicKey(), "Invalid output for test %d", i)
	}
}

func (suite *PeerTestSuite) TestIncrementPingCount() {
	prevPing := suite.p.nPing

	suite.p.IncrementPingCount()

	assert.Equal(suite.T(), suite.p.nPing, prevPing+1, "Num ping was not incremented.")
}

func (suite *PeerTestSuite) TestResetPingCount() {
	suite.p.nPing = 10

	suite.p.ResetPingCount()

	assert.Zero(suite.T(), suite.p.nPing, "Num ping was not reset.")
}

func (suite *PeerTestSuite) TestNumPing() {
	suite.p.nPing = 10

	currPing := suite.p.nPing

	assert.Equal(suite.T(), suite.p.NumPing(), currPing, "Retreived wrong ping value.")
}

func (suite *PeerTestSuite) TestHashContent() {
	data := []byte("testbyteslice")

	assert.NotNil(suite.T(), hashContent(data), "Returned hash is nil.")
}

type signerMock struct {
	priv *ecdsa.PrivateKey
}

func (sm *signerMock) Verify(data, r, s []byte, pub *ecdsa.PublicKey) bool {
	if pub == nil {
		log.Error("Peer had no publicKey")
		return false
	}

	var rInt, sInt big.Int

	b := hashContent(data)

	rInt.SetBytes(r)
	sInt.SetBytes(s)

	return ecdsa.Verify(pub, b, &rInt, &sInt)
}

func (sm *signerMock) Sign(data []byte) ([]byte, []byte, error) {
	hash := hashContent(data)

	r, s, err := ecdsa.Sign(rand.Reader, sm.priv, hash)
	if err != nil {
		return nil, nil, err
	}

	return r.Bytes(), s.Bytes(), nil
}
