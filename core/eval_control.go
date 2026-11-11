package core

//// Contents
// Helpers:
// 		mergers, promoters, evaluators
//
// Validators:  check (and sign) singatures for certificats, notes and accusations

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	"github.com/joonnna/ifrit/crypto/pki"
	pb "github.com/joonnna/ifrit/protobuf"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
)

func (n *Node) mergeNotes(notes []*pb.Note) {
	if notes == nil {
		return
	}

	for _, newNote := range notes {
		if n.self.Id == string(newNote.GetId()) {
			continue
		}

		err := n.evalNote(newNote)
		if err != nil && err != errOldNote {
			log.Debug(err.Error())
		}
	}
}

func (n *Node) mergeAccusations(accusations []*pb.Accusation) {
	if accusations == nil {
		return
	}

	for _, acc := range accusations {
		accId := string(acc.GetAccused())
		accuserId := string(acc.GetAccuser())

		accuser := n.view.Peer(accuserId)
		if accuserId == n.self.Id {
			accuser = n.self
		} else if accuser == nil {
			continue
		}

		// Cryptographic check: accuser signature must verify
		if err := n.verifySignedMessage(acc, acc.GetSignature(), accuser); err != nil {
			log.Debug("mergeAccusations: rejected accusation with invalid signature", "accuser", accuserId, "err", err)
			continue
		}

		// Ring check
		if acc.GetRingNum() == 0 || acc.GetRingNum() > n.view.NumRings() {
			log.Debug("mergeAccusations: rejected accusation with invalid ring", "ring", acc.GetRingNum())
			continue
		}

		// Verified accusation enters AccusationStore
		rawAcc := discovery.AccusationFromPb(acc)
		if rawAcc != nil && n.view.AccusationStore() != nil {
			n.view.AccusationStore().Insert(rawAcc)
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

		err := n.evalAccusation(acc, accuser, accused)
		if err != nil {
			log.Debug(err.Error(), "ringNum", acc.GetRingNum(), "epoch", acc.GetEpoch(), "accused", accused.Addr, "accuser", accuser.Addr)
		}
	}
}

func (n *Node) mergeCertificates(certs []*pb.Certificate) {
	if certs == nil {
		return
	}
	for _, b := range certs {
		if b == nil || len(b.GetRaw()) == 0 {
			continue
		}

		cert, err := x509.ParseCertificate(b.GetRaw())
		if err != nil {
			log.Error(err.Error())
			continue
		}

		if n.self.Id == string(cert.SubjectKeyId) {
			continue
		}

		if err := n.validateCertificate(cert); err != nil {
			log.Debug("mergeCertificates: rejected invalid certificate", "err", err)
			continue
		}

		// Valid certificate enters certStore
		if n.view.CertStore() != nil {
			n.view.CertStore().Insert(pki.CertificateFromPb(b))
		}

		// Skip expensive evalCertificate if peer already exists in full view
		if n.view.Exists(string(cert.SubjectKeyId)) {
			continue
		}

		// Adds a valid certificate to the full view if not already present.
		err = n.evalValidCertificate(cert)
		if err != nil {
			log.Debug(err.Error())
		}
	}
}

// applyValidAccusation records a validated accusation in the view's activeAccusations and starts a suspicion
// removal timer if the peer is live and the accusation is actively promoted.
func (n *Node) applyValidAccusation(a *pb.Accusation, accuserPeer, p *discovery.Peer) error {
	rawAcc := discovery.AccusationFromPb(a)
	if rawAcc == nil {
		return errInvalidSignature
	}

	if n.view.AccusationStore() != nil {
		n.view.AccusationStore().Insert(rawAcc)
	}

	if n.view.PromoteAccusation(rawAcc) {
		if n.view.IsAlive(p) && !n.view.HasTimer(p) {
			if note, ok := n.view.ActiveNote(p.Id); ok {
				n.view.StartTimer(p, note, accuserPeer)
			}
		}
	}
	return nil
}

// evalAccusation validates and processes an incoming gossip accusation against peer p.
//
// Behavior:
//  1. Verifies the accusation's ECDSA signature using the accuser's public key.
//  2. If the accusation targets the local node (self):
//     - Validates that the accuser is our legitimate ring predecessor.
//     - Checks if a rebuttal is needed (current epoch match) and triggers an immediate rebuttal broadcast.
//  3. If the accusation targets a remote peer:
//     - If already recorded, ensures the suspicion timer is active.
//     - If new, verifies that the target note epoch matches, the ring is not disabled, and the accuser is the valid predecessor.
//     - Stores the accusation on the peer and starts a suspicion removal timer if the peer is live.
func (n *Node) evalAccusation(a *pb.Accusation, accuserPeer, accusedPeer *discovery.Peer) error {
	if n.self.Id == accusedPeer.Id {
		return n.handleSelfAccusation(a, accuserPeer)
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

	if err := n.validateRemoteAccusation(a, accuserPeer, accusedPeer); err != nil {
		return err
	}

	return n.applyValidAccusation(a, accuserPeer, accusedPeer)
}

func (node *Node) evalNote(newNote *pb.Note) error {
	epoch := newNote.GetEpoch()
	mask := newNote.GetMask()

	sign := newNote.GetSignature()
	if sign == nil {
		return errInvalidSignature
	}

	// Get the peer this note is about.
	peer := node.view.Peer(string(newNote.GetId()))
	if peer == nil {
		return errNoPeer
	}

	if valid := node.view.ValidMask(mask); !valid {
		return errInvalidMask
	}

	if err := node.verifySignedMessage(newNote, sign, peer); err != nil {
		return err
	}

	rawNote := discovery.NoteFromPb(newNote)
	if node.view.NoteStore() != nil {
		node.view.NoteStore().Insert(rawNote)
	}

	if node.view.HasNote(peer.Id, epoch) {
		return errOldNote
	}

	node.applyValidNote(newNote, peer)
	return nil
}

// applyValidNote records a validated note in NoteStore, advances the peer's active note
// in the view, updates live/timer status, and promotes any pending accusations.
func (node *Node) applyValidNote(newNote *pb.Note, peer *discovery.Peer) {
	rawNote := discovery.NoteFromPb(newNote)
	if node.view.NoteStore() != nil {
		node.view.NoteStore().Insert(rawNote)
	}
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
		n.promotePendingNotesForPeer(id)
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

		if err := n.evalAccusation(acc.ToPbMsg(), accuser, accused); err != nil && err != errAccAlreadyExists {
			log.Debug("Failed to promote pending accusation", "err", err, "accused", accId, "accuser", accuserId)
		}
	}
}

// promotePendingNotesForPeer is a hook/stub for future work.
// Since notes require the peer's certificate for signature verification before entering NoteStore,
// no notes for unknown peers exist in NoteStore. If an unverified ingress note ring-buffer / cache
// is introduced in the future (e.g. a bounded FIFO buffer holding notes pending certificate arrival),
// this function would drain and evaluate matching notes when the certificate arrives.
func (n *Node) promotePendingNotesForPeer(id string) {
	// TODO: Drain bounded unverified note ingress cache when implemented.
}

// handleSelfAccusation validates and responds to an incoming accusation against the local node.
// If the accuser is a legitimate ring predecessor with a valid signature, an immediate
// rebuttal broadcast is triggered.
func (n *Node) handleSelfAccusation(a *pb.Accusation, accuserPeer *discovery.Peer) error {
	ringNum := a.GetRingNum()
	epoch := a.GetEpoch()

	if !n.view.ValidAccuser(n.self, accuserPeer, ringNum) {
		return errInvalidAccuser
	}

	if err := n.verifySignedMessage(a, a.GetSignature(), accuserPeer); err != nil {
		return err
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

func (n *Node) Sign(content []byte) ([]byte, []byte, error) {
	r, s, err := n.cs.Sign(content)
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil
}

func (n *Node) Verify(r, s, content []byte, id string) bool {
	p := n.view.Peer(id)
	if p == nil {
		return false
	}

	return n.cs.Verify(content, r, s, p.PublicKey())
}

/////////////////////////////////////////////////////////////////////////
