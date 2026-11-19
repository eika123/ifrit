package core

//// Contents
// Helpers:
// 		mergers, promoters, evaluators
//
// Validators:  check (and sign) singatures for certificats, notes and accusations

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/pki"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
)

func (n *Node) validateCertItem(item *pki.Certificate) (*x509.Certificate, error) {
	if item == nil || len(item.Raw()) == 0 {
		return nil, errNilCert
	}
	cert, err := x509.ParseCertificate(item.Raw())
	if err != nil {
		return nil, err
	}
	if n.self != nil && n.self.Id == string(cert.SubjectKeyId) {
		return nil, nil
	}
	if err := n.validateCertificate(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func (n *Node) applyVerifiedCert(item *pki.Certificate, cert *x509.Certificate) error {
	if cert == nil {
		return nil
	}
	if n.view == nil || n.view.CertStore() == nil {
		return errors.New("cert store is not initialized")
	}
	n.view.CertStore().Insert(item)
	if !n.view.Exists(string(cert.SubjectKeyId)) {
		return n.evalValidCertificate(cert)
	}
	return nil
}

func (n *Node) mergeAccusations(accusations []*pb.Accusation) {
	if accusations == nil {
		return
	}

	for _, acc := range accusations {
		accuser, err := n.validateAccusationPb(acc)
		if err != nil {
			log.Debug("mergeAccusations: rejected accusation", "err", err)
			continue
		}
		if err := n.applyVerifiedAccusation(acc, accuser); err != nil {
			log.Debug(err.Error(), "ringNum", acc.GetRingNum(), "epoch", acc.GetEpoch())
		}
	}
}

func (n *Node) validateAccusationPb(pbAcc *pb.Accusation) (*discovery.Peer, error) {
	if pbAcc == nil {
		return nil, errors.New("nil accusation")
	}
	if pbAcc.GetRingNum() == 0 || pbAcc.GetRingNum() > n.view.NumRings() {
		return nil, errors.New("accusation ring number out of bounds")
	}
	accuserID := string(pbAcc.GetAccuser())
	var accuser *discovery.Peer
	if n.self != nil && accuserID == n.self.Id {
		accuser = n.self
	} else {
		accuser = n.view.Peer(accuserID)
	}
	if accuser == nil {
		return nil, errNoPeer
	}
	if err := n.verifySignedMessage(pbAcc, pbAcc.GetSignature(), accuser); err != nil {
		return nil, err
	}
	return accuser, nil
}

func (n *Node) applyVerifiedAccusation(pbAcc *pb.Accusation, accuser *discovery.Peer) error {
	if n.view == nil || n.view.AccusationStore() == nil {
		return errors.New("accusation store is not initialized")
	}
	rawAcc := discovery.AccusationFromPb(pbAcc)
	if rawAcc == nil {
		return errInvalidSignature
	}
	n.view.AccusationStore().Insert(rawAcc)

	accusedID := string(pbAcc.GetAccused())
	var accused *discovery.Peer
	if n.self != nil && accusedID == n.self.Id {
		accused = n.self
	} else {
		accused = n.view.Peer(accusedID)
	}
	if accused == nil {
		return nil
	}
	if _, ok := n.view.ActiveNote(accusedID); !ok {
		return nil
	}

	return n.promoteVerifiedAccusation(rawAcc, pbAcc, accuser, accused)
}

func (n *Node) promoteVerifiedAccusation(rawAcc *discovery.Accusation, a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer) error {
	if n.self.Id == accusedPeer.Id {
		return n.handleSelfAccusationVerified(a, accuserPeer)
	}

	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	if n.view.HasActiveAccusation(accusedPeer.Id, ringNum, epoch) {
		note, ok := n.view.ActiveNote(accusedPeer.Id)
		if ok && epoch >= note.Epoch() {
			n.ensureAccusationTimer(accusedPeer, accuserPeer)
		}
		return errAccAlreadyExists
	}

	if err := n.validateRemoteAccusationVerified(a, accuserPeer, accusedPeer); err != nil {
		return err
	}

	if n.view.PromoteAccusation(rawAcc) {
		n.ensureAccusationTimer(accusedPeer, accuserPeer)
	}
	return nil
}

// evalAccusation validates and processes an incoming gossip accusation against given peer.
func (n *Node) evalAccusation(a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer) error {
	if err := n.verifySignedMessage(a, a.GetSignature(), accuserPeer); err != nil {
		return err
	}
	rawAcc := discovery.AccusationFromPb(a)
	if rawAcc == nil {
		return errInvalidSignature
	}
	if n.view.AccusationStore() != nil {
		n.view.AccusationStore().Insert(rawAcc)
	}
	return n.promoteVerifiedAccusation(rawAcc, a, accuserPeer, accusedPeer)
}

func (node *Node) validateNotePb(newNote *pb.Note) (*discovery.Peer, error) {
	if newNote == nil {
		return nil, errors.New("nil note")
	}
	if node.self != nil && node.self.Id == string(newNote.GetId()) {
		return nil, nil
	}
	sign := newNote.GetSignature()
	if sign == nil {
		return nil, errInvalidSignature
	}
	peer := node.view.Peer(string(newNote.GetId()))
	if peer == nil {
		return nil, errNoPeer
	}
	if valid := node.view.ValidMask(newNote.GetMask()); !valid {
		return nil, errInvalidMask
	}
	if err := node.verifySignedMessage(newNote, sign, peer); err != nil {
		return nil, err
	}
	return peer, nil
}

func (node *Node) applyVerifiedNote(newNote *pb.Note, peer *discovery.Peer) error {
	if peer == nil {
		return nil
	}
	rawNote := discovery.NoteFromPb(newNote)
	if node.view.NoteStore() != nil {
		node.view.NoteStore().Insert(rawNote)
	}
	if node.view.HasNote(peer.Id, newNote.GetEpoch()) {
		return errOldNote
	}
	node.promoteValidNote(rawNote, newNote, peer)
	return nil
}

func (node *Node) evalNote(newNote *pb.Note) error {
	peer, err := node.validateNotePb(newNote)
	if err != nil {
		return err
	}
	return node.applyVerifiedNote(newNote, peer)
}

func (node *Node) promoteValidNote(rawNote *discovery.Note, newNote *pb.Note, peer *discovery.Peer) {
	node.view.PromoteNote(rawNote)

	// If peer is not accused under its most recent note, ensure timers are stopped
	// and peer is restored to live status.
	if !node.view.IsAccused(peer) {
		peer.ResetPingCount()

		if exists := node.view.HasTimer(peer); exists {
			node.view.DeleteTimeout(peer)
		}

		if alive := node.view.IsAlive(peer); !alive {
			node.view.AddLive(peer)
		}

		log.Debug("Rebuttal received or live peer updated", "epoch", newNote.GetEpoch(), "addr", peer.Addr)
	}

	node.promotePendingAccusationsForPeer(peer.Id)
}

// evalValidCertificate adds a pre-validated certificate to the full view if not already present,
// promoting any previously unpromoted notes and accusations for this newly admitted peer.
//
// it is the responsibility of the caller to assure that the certificate is valid.
func (n *Node) evalValidCertificate(cert *x509.Certificate) error {
	id := string(cert.SubjectKeyId)
	if !n.view.Exists(id) {
		if err := n.view.AddFull(id, cert); err != nil {
			log.Error("Failed to add peer certificate to full view", "err", err)
			return err
		}
		n.promotePendingAccusationsForPeer(id)
	}
	return nil
}

func (n *Node) admitCaller(cert *x509.Certificate, remoteId string, ownNote *pb.Note) (*discovery.Peer, bool, bool, error) {
	var wasObserved, wasAccused bool

	if err := n.validateCertificate(cert); err != nil {
		log.Error(err.Error())
		return nil, wasObserved, wasAccused, err
	}

	peer := n.view.Peer(remoteId)
	if peer != nil {
		wasObserved = true
		wasAccused = n.view.IsAccused(peer)
	}

	if !wasObserved {
		if err := n.evalValidCertificate(cert); err != nil {
			log.Error(err.Error())
			return nil, wasObserved, wasAccused, err
		}
		if peer == nil {
			peer = n.view.Peer(remoteId)
		}
	}

	if ownNote != nil {
		if string(ownNote.GetId()) != remoteId {
			log.Warn("admitCaller: ownNote ID does not match mTLS certificate remoteId", "noteId", string(ownNote.GetId()), "remoteId", remoteId)
		} else {
			if err := n.evalNote(ownNote); err != nil && err != errOldNote {
				log.Debug(err.Error())
			}
		}
	}

	return peer, wasObserved, wasAccused, nil
}

// promotePendingAccusationsForPeer scans AccusationStore for any unpromoted accusations
// where id is either the accused or the accuser, and evaluates them if all prerequisite
// peers and active notes are now available.
func (n *Node) promotePendingAccusationsForPeer(id string) {
	if n.view.AccusationStore() == nil {
		return
	}
	for _, acc := range n.view.AccusationStore().Elements() {
		if acc == nil {
			continue
		}
		if acc.Accused() != id && acc.Accuser() != id {
			continue
		}

		accId := acc.Accused()
		accuserId := acc.Accuser()

		accuser := n.view.Peer(accuserId)
		if accuserId == n.self.Id {
			accuser = n.self
		} else if accuser == nil {
			continue
		}

		accused := n.view.Peer(accId)
		if accId == n.self.Id {
			accused = n.self
		} else if accused == nil {
			continue
		}

		if _, ok := n.view.ActiveNote(accId); !ok {
			continue
		}

		// AccusationStore only contains accusations whose signature was already verified on ingress.
		if err := n.promoteVerifiedAccusation(acc, acc.ToPbMsg(), accuser, accused); err != nil && err != errAccAlreadyExists {
			log.Debug("Failed to promote pending accusation", "err", err, "accused", accId, "accuser", accuserId)
		}
	}
}

// handleSelfAccusationVerified validates and responds to a signature-verified accusation against the local node.
func (n *Node) handleSelfAccusationVerified(a *pb.Accusation, accuserPeer *discovery.Peer) error {
	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	if !n.view.ValidAccuser(n.self, accuserPeer, ringNum) {
		return errInvalidAccuser
	}

	if n.view.ShouldRebuttal(epoch, ringNum) {
		n.rebuttal()
		return nil
	}
	return errInvalidSelfAccusation
}

// ensureAccusationTimer ensures a suspicion timer is active for an already recorded accusation if the peer is live.
func (n *Node) ensureAccusationTimer(accusedPeer, accuserPeer *discovery.Peer) {
	note, ok := n.view.ActiveNote(accusedPeer.Id)
	if n.view.IsAlive(accusedPeer) && !n.view.HasTimer(accusedPeer) && ok {
		n.view.StartTimer(accusedPeer, note, accuserPeer)
		log.Debug("Had accusation with no timer, starting timer.")
	}
}

/////////////////////////// Validators //////////////////////////////////

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

	if caCert := n.idCatalog.CaCertificate(); caCert != nil {
		// our chain of trust is currently just CA -> nodes, no intermediaries
		return cert.CheckSignatureFrom(caCert)
	}
	return cert.CheckSignatureFrom(cert)
}

func (n *Node) validateCtx(ctx context.Context) (*x509.Certificate, error) {
	cert, err := comm.PeerCertFromContext(ctx)
	if err != nil {
		switch {
		case errors.Is(err, comm.ErrNoPeerInCtx):
			return nil, errNoPeerInCtx
		case errors.Is(err, comm.ErrNoTLSInfo):
			return nil, errNoTLSInfo
		case errors.Is(err, comm.ErrNoCert):
			return nil, errNoCert
		default:
			return nil, err
		}
	}
	return cert, nil
}

// validateRemoteAccusationVerified verifies semantic rules (epoch, enabled ring, valid predecessor)
// for a signature-verified accusation against a remote peer.
func (n *Node) validateRemoteAccusationVerified(a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer) error {
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

	return nil
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

// marshalWithoutSignature marshals a fresh unsigned copy of a Note or Accusation
// for cryptographic verification without mutating msg.
func marshalWithoutSignature(msg proto.Message) ([]byte, error) {
	switch m := msg.(type) {
	case *pb.Note:
		if m.GetSignature() == nil {
			return nil, errInvalidSignature
		}
		return proto.Marshal(&pb.Note{
			Epoch: m.GetEpoch(),
			Id:    m.GetId(),
			Mask:  m.GetMask(),
		})
	case *pb.Accusation:
		if m.GetSignature() == nil {
			return nil, errInvalidSignature
		}
		return proto.Marshal(&pb.Accusation{
			Epoch:   m.GetEpoch(),
			Accuser: m.GetAccuser(),
			Accused: m.GetAccused(),
			RingNum: m.GetRingNum(),
		})
	default:
		return nil, errors.New("unsupported message type for signature stripping")
	}
}

func (n *Node) Sign(content []byte) ([]byte, []byte, error) {
	r, s, err := n.cs.Sign(content)
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil
}

func (n *Node) Verify(r, s, content []byte, id string) bool {
	peer := n.view.Peer(id)
	if peer == nil {
		return false
	}

	return n.cs.Verify(content, r, s, peer.PublicKey())
}

/////////////////////////////////////////////////////////////////////////
