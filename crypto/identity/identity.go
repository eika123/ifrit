package identity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/crypto"
	"github.com/joonnna/ifrit/crypto/pki"
)

var (
	ErrNoRingNum    = errors.New("no ring number present in received certificate")
	ErrNoHostIp     = errors.New("no ip or hostname present in received identity")
	ErrNoAddrs      = errors.New("not enough addresses present in identity")
	ErrInvlPath     = errors.New("argument path to load empty")
	ErrPemDecode    = errors.New("unable to decode content in given file")
	ErrNoCryptoPath = errors.New("path for crypto resources is empty")
	ErrNoCa         = errors.New("no address for Certificate Authority")
	ErrNoConfig     = errors.New("crypto unit configuration is nil")
)

// Identity encapsulates the node's local cryptographic identity,
// including its private key, certificate, CA certificate, trusted peer contacts,
// and ring metadata.
type Identity struct {
	priv   *ecdsa.PrivateKey
	pk     pkix.Name
	caAddr string

	path       string
	self       *x509.Certificate
	ca         *x509.Certificate
	numRings   uint32
	knownCerts []*x509.Certificate
	trusted    bool
}

// Config defines the configuration parameters for initializing an Identity.
type Config struct {
	Identity pkix.Name
	CaAddr   string
	DNSNames []string
	Path     string
}

// New creates and initializes a new node Identity, requesting certificates
// from a CA if caAddr is specified, or generating self-signed certificates.
func New(config *Config) (*Identity, error) {
	var certs *certSet
	var extValue []byte

	if config == nil {
		return nil, ErrNoConfig
	}

	if addrs := len(config.Identity.Locality); addrs < 2 {
		return nil, ErrNoAddrs
	}

	priv, err := genKeys()
	if err != nil {
		return nil, err
	}

	if config.CaAddr != "" {
		caAddr := strings.TrimPrefix(strings.TrimPrefix(config.CaAddr, "http://"), "https://")
		addr := fmt.Sprintf("http://%s/certificateRequest", caAddr)
		certs, err = sendCertRequest(priv, addr, config.Identity, config.DNSNames)
		if err != nil {
			return nil, err
		}
	} else {
		certs, err = selfSignedCert(priv, config.Identity)
		if err != nil {
			return nil, err
		}
	}

	for _, e := range certs.ownCert.Extensions {
		if e.Id.Equal(pki.RingNumberOid) {
			extValue = e.Value
		}
	}

	if extValue == nil {
		return nil, ErrNoRingNum
	}

	numRings := binary.LittleEndian.Uint32(extValue[0:])

	return &Identity{
		ca:         certs.caCert,
		self:       certs.ownCert,
		numRings:   numRings,
		caAddr:     config.CaAddr,
		path:       config.Path,
		pk:         config.Identity,
		priv:       priv,
		knownCerts: certs.knownCerts,
		trusted:    certs.trusted,
	}, nil
}

// Load loads an existing Identity from PEM files stored on disk.
func Load(cryptoPath string, identity pkix.Name, caAddr string) (*Identity, error) {
	var extValue []byte

	certs, err := loadCertSet(cryptoPath)
	if err != nil {
		return nil, err
	}

	priv, err := loadPrivKey(cryptoPath)
	if err != nil {
		return nil, err
	}

	for _, e := range certs.ownCert.Extensions {
		if e.Id.Equal(pki.RingNumberOid) {
			extValue = e.Value
		}
	}

	if extValue == nil {
		return nil, ErrNoRingNum
	}

	numRings := binary.LittleEndian.Uint32(extValue[0:])

	return &Identity{
		ca:         certs.caCert,
		path:       cryptoPath,
		self:       certs.ownCert,
		numRings:   numRings,
		caAddr:     caAddr,
		pk:         identity,
		priv:       priv,
		knownCerts: certs.knownCerts,
		trusted:    certs.trusted,
	}, nil
}

func (id *Identity) Trusted() bool {
	return id.trusted
}

func (id *Identity) Certificate() *x509.Certificate {
	return id.self
}

func (id *Identity) CaCertificate() *x509.Certificate {
	return id.ca
}

func (id *Identity) NumRings() uint32 {
	return id.numRings
}

func (id *Identity) Priv() *ecdsa.PrivateKey {
	return id.priv
}

func (id *Identity) ContactList() []*x509.Certificate {
	ret := make([]*x509.Certificate, 0, len(id.knownCerts))
	for _, c := range id.knownCerts {
		ret = append(ret, c)
	}
	return ret
}

// Verify validates an ECDSA signature over data using pub.
func (id *Identity) Verify(data, r, s []byte, pub *ecdsa.PublicKey) bool {
	if pub == nil {
		log.Error("Peer had no publicKey")
		return false
	}

	var rInt, sInt big.Int
	b := crypto.HashContent(data)

	rInt.SetBytes(r)
	sInt.SetBytes(s)

	return ecdsa.Verify(pub, b, &rInt, &sInt)
}

// Sign computes the SHA-256 digest and ECDSA signs data using the Identity private key.
func (id *Identity) Sign(data []byte) ([]byte, []byte, error) {
	hash := crypto.HashContent(data)

	r, s, err := ecdsa.Sign(rand.Reader, id.priv, hash)
	if err != nil {
		return nil, nil, err
	}

	return r.Bytes(), s.Bytes(), nil
}
