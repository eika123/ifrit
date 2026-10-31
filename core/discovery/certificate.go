package discovery

import (
	"bytes"
	"crypto/x509"

	pb "github.com/joonnna/ifrit/protobuf"
)

type Certificate struct {
	raw []byte
}

// CryptographicIdentity returns the raw DER bytes uniquely identifying this certificate.
// ReverseIndexStore hashes this with SHA-256 to produce the 64-bit BigEndian DigestSymbol.
func (c Certificate) CryptographicIdentity() []byte {
	return c.raw
}

func (c *Certificate) Raw() []byte {
	if c == nil {
		return nil
	}
	return c.raw
}

func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.raw, other.raw)
}

func (c *Certificate) Parse() (*x509.Certificate, error) {
	if c == nil || len(c.raw) == 0 {
		return nil, errNoCert
	}
	return x509.ParseCertificate(c.raw)
}

// ToPbMsg converts the Certificate struct to a protobuf Certificate message.
func (c *Certificate) ToPbMsg() *pb.Certificate {
	if c == nil || len(c.raw) == 0 {
		return nil
	}
	return &pb.Certificate{
		Raw: c.raw,
	}
}

// CertificateFromPb unconditionally constructs an internal Certificate from a protobuf Certificate message,
// safely returning nil if pbCert or its Raw content is empty.
func CertificateFromPb(pbCert *pb.Certificate) *Certificate {
	if pbCert == nil || len(pbCert.GetRaw()) == 0 {
		return nil
	}
	return &Certificate{
		raw: pbCert.GetRaw(),
	}
}

// CertificateFromX509 constructs an internal Certificate from a Go standard library x509.Certificate.
func CertificateFromX509(cert *x509.Certificate) *Certificate {
	if cert == nil || len(cert.Raw) == 0 {
		return nil
	}
	return &Certificate{
		raw: cert.Raw,
	}
}

// NewCertificate creates an internal Certificate from raw DER bytes.
func NewCertificate(raw []byte) *Certificate {
	if len(raw) == 0 {
		return nil
	}
	return &Certificate{
		raw: raw,
	}
}

