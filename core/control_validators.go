package core

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/golang/protobuf/proto"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
)

// validateCertificate checks if a certificate is non-nil, does not belong to self,
// has a valid SubjectKeyId length, and is signed by the CA (or self-signed if CA is absent).
func (n *Node) validateCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return errNilCert
	}

	id := string(cert.SubjectKeyId)

	if id == n.Id() {
		return errSelfCert
	}

	if len(id) != sha256.Size {
		return errInvalidId
	}

	if caCert := n.cm.CaCertificate(); caCert != nil {
		// our chain of trust is currently just CA -> nodes, no intermediaries
		return cert.CheckSignatureFrom(caCert)
	}
	return cert.CheckSignatureFrom(cert)
}

func (n *Node) validateCtx(ctx context.Context) (*x509.Certificate, error) {
	var tlsInfo credentials.TLSInfo
	var ok bool

	p, ok := grpcPeer.FromContext(ctx)
	if !ok {
		return nil, errNoPeerInCtx
	}

	if tlsInfo, ok = p.AuthInfo.(credentials.TLSInfo); !ok {
		return nil, errNoTLSInfo
	}

	if len(tlsInfo.State.PeerCertificates) < 1 {
		return nil, errNoCert
	}

	return tlsInfo.State.PeerCertificates[0], nil
}

// validateRemoteAccusation verifies that an accusation against a remote peer matches the peer's
// current note epoch, is on an enabled ring, that the accuserPeer is the legitimate predecessor of accusedPeer,
// and carries a valid cryptographic signature.
func (n *Node) validateRemoteAccusation(a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer) error {
	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	note, ok := n.view.ActiveNote(accusedPeer.Id)
	if !ok || !note.Equal(epoch) {
		return errInvalidEpoch
	}

	if note.IsRingDisabled(ringNum, n.view.NumRings()) {
		return errDisabledRing
	}

	if !n.view.ValidAccuser(accusedPeer, accuserPeer, ringNum) {
		return errInvalidAccuser
	}

	return n.verifySignedMessage(a, a.GetSignature(), accuserPeer)
}

// verifySignedMessage strips the signature from a protobuf message (Note or Accusation),
// marshals the payload, and verifies the ECDSA signature against the signer's public key.
func (n *Node) verifySignedMessage(msg proto.Message, sign *pb.Signature, signer *discovery.Peer) error {
	if sign == nil || signer == nil || signer.PublicKey() == nil {
		return errInvalidSignature
	}

	content, err := marshalWithoutSignature(msg)
	if err != nil {
		return err
	}

	if !n.cs.Verify(content, sign.GetR(), sign.GetS(), signer.PublicKey()) {
		return errInvalidSignature
	}

	return nil
}

// marshalWithoutSignature strips the signature from a Note or Accusation,
// marshals the payload to bytes for cryptographic verification, and restores the signature.
func marshalWithoutSignature(msg proto.Message) ([]byte, error) {
	var sign *pb.Signature

	switch m := msg.(type) {
	case *pb.Note:
		sign = m.GetSignature()
		if sign == nil {
			return nil, errInvalidSignature
		}
		m.Signature = nil
		defer func() { m.Signature = sign }()
	case *pb.Accusation:
		sign = m.GetSignature()
		if sign == nil {
			return nil, errInvalidSignature
		}
		m.Signature = nil
		defer func() { m.Signature = sign }()
	default:
		return nil, errors.New("unsupported message type for signature stripping")
	}

	return proto.Marshal(msg)
}
