package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type CertificateTestSuite struct {
	suite.Suite
}

func TestCertificateTestSuite(t *testing.T) {
	r := log.Root()
	r.SetHandler(log.DiscardHandler())
	suite.Run(t, new(CertificateTestSuite))
}

func (suite *CertificateTestSuite) TestCryptographicIdentity() {
	raw := []byte("cert-der-bytes-1")
	cert := NewCertificate(raw)
	require.NotNil(suite.T(), cert)
	assert.Equal(suite.T(), raw, cert.CryptographicIdentity())
	assert.Equal(suite.T(), raw, cert.Raw())
}

func (suite *CertificateTestSuite) TestEqual() {
	raw1 := []byte("cert-bytes-1")
	raw2 := []byte("cert-bytes-2")

	c1 := NewCertificate(raw1)
	c2 := NewCertificate(raw1)
	c3 := NewCertificate(raw2)

	assert.True(suite.T(), c1.Equal(c2))
	assert.False(suite.T(), c1.Equal(c3))
	assert.False(suite.T(), c1.Equal(nil))
}

func (suite *CertificateTestSuite) TestToPbMsgAndFromPb() {
	raw := []byte("cert-der-bytes")
	cert := NewCertificate(raw)
	pbCert := cert.ToPbMsg()
	require.NotNil(suite.T(), pbCert)
	assert.Equal(suite.T(), raw, pbCert.GetRaw())

	recovered := CertificateFromPb(pbCert)
	require.NotNil(suite.T(), recovered)
	assert.Equal(suite.T(), raw, recovered.Raw())

	// Nil safety
	var nilCert *Certificate
	assert.Nil(suite.T(), nilCert.ToPbMsg())
	assert.Nil(suite.T(), CertificateFromPb(nil))
	assert.Nil(suite.T(), CertificateFromPb(&pb.Certificate{}))
	assert.Nil(suite.T(), CertificateFromX509(nil))
	assert.Nil(suite.T(), NewCertificate(nil))
	assert.Nil(suite.T(), NewCertificate([]byte{}))
}

func (suite *CertificateTestSuite) TestParseAndFromX509() {
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(suite.T(), err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		SubjectKeyId: []byte("node-cert-id"),
		Subject: pkix.Name{
			Locality: []string{"rpcAddr", "pingAddr", "httpAddr"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.Public(), privKey)
	require.NoError(suite.T(), err)

	x509Cert, err := x509.ParseCertificate(derBytes)
	require.NoError(suite.T(), err)

	cert := CertificateFromX509(x509Cert)
	require.NotNil(suite.T(), cert)
	assert.Equal(suite.T(), x509Cert.Raw, cert.Raw())

	parsed, err := cert.Parse()
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), x509Cert.SubjectKeyId, parsed.SubjectKeyId)
}

func (suite *CertificateTestSuite) TestDefaultHasherIntegration() {
	raw1 := []byte("cert-der-1")
	raw2 := []byte("cert-der-2")

	c1 := NewCertificate(raw1)
	c2 := NewCertificate(raw2)

	hasher := revIdxStore.DefaultHasher[*Certificate]()
	d1 := hasher(c1)
	d2 := hasher(c2)

	assert.NotEqual(suite.T(), revIdxStore.DigestSymbol(0), d1)
	assert.NotEqual(suite.T(), revIdxStore.DigestSymbol(0), d2)
	assert.NotEqual(suite.T(), d1, d2)

	// Idempotent hashing
	assert.Equal(suite.T(), d1, hasher(NewCertificate(raw1)))

	// DigestSet integration
	store, err := revIdxStore.NewDigestSet[*Certificate, revIdxStore.DigestSymbol](hasher)
	require.NoError(suite.T(), err)

	d, added := store.Insert(c1)
	assert.True(suite.T(), added)
	assert.Equal(suite.T(), d1, d)

	// Duplicate insert
	dDup, addedDup := store.Insert(c1)
	assert.False(suite.T(), addedDup)
	assert.Equal(suite.T(), d1, dDup)

	// Lookup by digest
	foundCert, found := store.GetByDigest(d1)
	assert.True(suite.T(), found)
	assert.Equal(suite.T(), c1.Raw(), foundCert.Raw())

	// Fingerprint equals digest for single element
	assert.Equal(suite.T(), d1, store.Fingerprint())

	// Add second element
	store.Insert(c2)
	assert.Equal(suite.T(), d1^d2, store.Fingerprint())
}
