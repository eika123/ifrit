package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"

	log "github.com/inconshreveable/log15"
)

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

