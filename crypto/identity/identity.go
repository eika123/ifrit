package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/crypto"
	"github.com/joonnna/ifrit/crypto/pki"
	"github.com/joonnna/ifrit/netutil"
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

type certResponse struct {
	OwnCert    []byte
	KnownCerts [][]byte
	CaCert     []byte
	Trusted    bool
}

type certSet struct {
	ownCert    *x509.Certificate
	caCert     *x509.Certificate
	knownCerts []*x509.Certificate
	trusted    bool
}

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

// SavePrivateKey writes the identity's EC private key to key.pem in id.path.
func (id *Identity) SavePrivateKey() error {
	if _, err := os.Stat(id.path); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(id.path, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	path := filepath.Join(id.path, "key.pem")
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(id.priv)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	err = pem.Encode(f, block)
	if err != nil {
		return err
	}

	log.Info("private-key stored", "path", path)
	return f.Close()
}

// SaveCertificate writes known peer certificates, CA certificate, and own certificate to id.path.
func (id *Identity) SaveCertificate() error {
	if _, err := os.Stat(id.path); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(id.path, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Peer certificates
	for i, knownCert := range id.knownCerts {
		fname := filepath.Join(id.path, fmt.Sprintf("g-%s.pem", knownCert.SerialNumber))
		if err := saveCert(knownCert, fname); err != nil {
			log.Error(err.Error())
		}
		log.Info(fmt.Sprintf("known-certificate #%v stored", i+1), "path", fname)
	}

	// CA's certificate
	if id.ca != nil {
		fname := filepath.Join(id.path, fmt.Sprintf("ca-%s.pem", id.ca.SerialNumber))
		if err := saveCert(id.ca, fname); err != nil {
			log.Error(err.Error())
		}
		log.Info("CA-certificate stored", "path", fname)
	}

	// Own certificate
	if id.self != nil {
		fname := filepath.Join(id.path, fmt.Sprintf("self-%s.pem", id.self.SerialNumber))
		if err := saveCert(id.self, fname); err != nil {
			log.Error(err.Error())
		}
		log.Info("own-certificate stored", "path", fname)
	}

	return nil
}

func saveCert(cert *x509.Certificate, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	if err := pem.Encode(f, block); err != nil {
		return err
	}

	return f.Close()
}

func loadCertSet(certPath string) (*certSet, error) {
	if certPath == "" {
		return nil, ErrInvlPath
	}

	// Own certificate
	matches, err := filepath.Glob(filepath.Join(certPath, "self-*.pem"))
	if err != nil {
		return nil, err
	} else if matches == nil {
		return nil, fmt.Errorf("storage path '%s' gave no hits on certificates", certPath)
	} else if len(matches) > 1 {
		return nil, fmt.Errorf("argument path: \"%s\" contains more than one own certificate", certPath)
	}

	selfCert, err := loadCert(matches[0])
	if err != nil {
		return nil, err
	}
	log.Info("own-certificate loaded", "path", matches[0])

	// Peer certificates
	matches, err = filepath.Glob(filepath.Join(certPath, "g-*.pem"))
	if err != nil {
		return nil, err
	}

	knownCerts := make([]*x509.Certificate, 0, len(matches))
	for i, path := range matches {
		gCert, err := loadCert(path)
		if err != nil {
			return nil, err
		}
		knownCerts = append(knownCerts, gCert)
		log.Info(fmt.Sprintf("known certificate #%d loaded", i+1), "path", path)
	}

	// CA certificate
	matches, err = filepath.Glob(filepath.Join(certPath, "ca-*.pem"))
	if err != nil {
		return nil, err
	} else if len(matches) > 1 {
		return nil, fmt.Errorf("argument path: \"%s\" contains more than one CA certificate", certPath)
	}

	var caCert *x509.Certificate
	if len(matches) == 1 {
		caCert, err = loadCert(matches[0])
		if err != nil {
			return nil, err
		}
		log.Info("ca-certificate loaded", "path", matches[0])
	}

	return &certSet{
		ownCert:    selfCert,
		knownCerts: knownCerts,
		caCert:     caCert,
		trusted:    true,
	}, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	certPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		return nil, ErrPemDecode
	}

	return x509.ParseCertificate(certBlock.Bytes)
}

func loadPrivKey(certPath string) (*ecdsa.PrivateKey, error) {
	if certPath == "" {
		return nil, ErrInvlPath
	}

	path := filepath.Join(certPath, "key.pem")
	keyPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPem)
	if keyBlock == nil {
		return nil, ErrPemDecode
	}

	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	log.Info("private-key loaded", "path", path)
	return privKey, nil
}

func sendCertRequest(privKey *ecdsa.PrivateKey, caAddr string, pk pkix.Name, DNSNames []string) (*certSet, error) {
	var certs certResponse
	set := &certSet{}

	localIP := netutil.GetLocalIP()

	var ipAddresses []net.IP
	if parsed := net.ParseIP(localIP); parsed != nil {
		ipAddresses = append(ipAddresses, parsed)
	}

	template := x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject:            pk,
		DNSNames:           DNSNames,
		IPAddresses:        ipAddresses,
	}

	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(caAddr, "text", bytes.NewBuffer(certReqBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("ca certificate request failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(resp.Body).Decode(&certs)
	if err != nil {
		return nil, err
	}

	set.ownCert, err = x509.ParseCertificate(certs.OwnCert)
	if err != nil {
		return nil, err
	}

	set.caCert, err = x509.ParseCertificate(certs.CaCert)
	if err != nil {
		return nil, err
	}

	for _, b := range certs.KnownCerts {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, err
		}
		set.knownCerts = append(set.knownCerts, c)
	}

	set.trusted = certs.Trusted

	return set, nil
}

func selfSignedCert(priv *ecdsa.PrivateKey, pk pkix.Name) (*certSet, error) {
	ringBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ringBytes[0:], uint32(32))

	ext := pkix.Extension{
		Id:       pki.RingNumberOid,
		Critical: false,
		Value:    ringBytes,
	}

	serial, err := genSerialNumber()
	if err != nil {
		return nil, err
	}

	serviceAddr := strings.Split(pk.Locality[0], ":")
	if len(serviceAddr) <= 0 {
		return nil, ErrNoHostIp
	}

	serviceIP, err := net.LookupIP(serviceAddr[0])
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(serviceIP[0].String())
	if ip == nil {
		return nil, ErrNoHostIp
	}

	newCert := &x509.Certificate{
		SerialNumber:          serial,
		SubjectKeyId:          genId(),
		Subject:               pk,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().AddDate(-10, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtraExtensions:       []pkix.Extension{ext},
		PublicKey:             &priv.PublicKey,
		IPAddresses:           []net.IP{ip},
		IsCA:                  true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign,
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, newCert, newCert, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	parsed, err := x509.ParseCertificate(signedCert)
	if err != nil {
		return nil, err
	}

	return &certSet{ownCert: parsed}, nil
}

func genId() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

func genSerialNumber() (*big.Int, error) {
	sLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, sLimit)
}

func genKeys() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}
