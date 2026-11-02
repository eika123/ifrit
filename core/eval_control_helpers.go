package core

import (
	"crypto/x509"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
)

func (n *Node) mergeNotes(notes []*pb.Note) {
	if notes == nil {
		return
	}

	// TIER 1: Unconditional ingestion into grow-only raw NoteStore.
	// Every incoming note — valid, invalid, corrupt, or carrying a bomb — is persisted
	// so set reconciliation fingerprints converge deterministically across all peers.
	for _, newNote := range notes {
		if rawNote := discovery.NoteFromPb(newNote); rawNote != nil && n.view.NoteStore() != nil {
			n.view.NoteStore().Insert(rawNote)
		}
	}

	// TIER 2: Semantic evaluation for active view and redirection layer.
	for _, newNote := range notes {
		if n.self.Id == string(newNote.GetId()) {
			continue
		}

		err := n.evalNote(newNote)
		if err != nil {
			log.Debug(err.Error())
		}
	}
}

func (n *Node) mergeAccusations(accusations []*pb.Accusation) {
	if accusations == nil {
		return
	}

	// TIER 1: Unconditional ingestion into grow-only raw AccusationStore.
	// Every incoming accusation — valid, invalid, corrupt, or carrying a bomb — is persisted
	// so set reconciliation fingerprints converge deterministically across all peers.
	for _, acc := range accusations {
		if rawAcc := discovery.AccusationFromPb(acc); rawAcc != nil && n.view.AccusationStore() != nil {
			n.view.AccusationStore().Insert(rawAcc)
		}
	}

	// TIER 2: Semantic evaluation for active view and redirection layer.
	for _, acc := range accusations {
		accId := string(acc.GetAccused())
		accuserId := string(acc.GetAccuser())

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

		// Tier 1: Raw ingestion into certStore for deterministic set reconciliation
		if n.view.CertStore() != nil {
			n.view.CertStore().Insert(discovery.CertificateFromPb(b))
		}

		cert, err := x509.ParseCertificate(b.GetRaw())
		if err != nil {
			log.Error(err.Error())
			continue
		}

		if n.self.Id == string(cert.SubjectKeyId) {
			continue
		}

		// Skip expensive evalCertificate if peer already exists in full view
		if n.view.Exists(string(cert.SubjectKeyId)) {
			continue
		}

		// Adds a valid certificate to the full view if valid and not already present.
		err = n.evalCertificate(cert)
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

	if node.view.HasNote(peer.Id, epoch) {
		return errOldNote
	}

	if valid := node.view.ValidMask(mask); !valid {
		return errInvalidMask
	}

	if err := node.verifySignedMessage(newNote, sign, peer); err != nil {
		return err
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

// evalCertificate validates a certificate and adds it to the full view if valid and not already present,
// promoting any previously unpromoted notes and accusations for this newly admitted peer.
func (n *Node) evalCertificate(cert *x509.Certificate) error {
	if err := n.validateCertificate(cert); err != nil {
		return err
	}

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

// promotePendingNotesForPeer scans NoteStore for any unpromoted notes belonging to id and evaluates the newest one.
func (n *Node) promotePendingNotesForPeer(id string) {
	if n.view.NoteStore() == nil {
		return
	}
	var newestNote *discovery.Note
	for _, note := range n.view.NoteStore().Elements() {
		if note.Id() == id {
			if newestNote == nil || note.Epoch() > newestNote.Epoch() {
				newestNote = note
			}
		}
	}
	if newestNote != nil {
		if err := n.evalNote(newestNote.ToPbMsg()); err != nil && err != errOldNote {
			log.Debug("Failed to promote pending note on certificate arrival", "err", err)
		}
	}
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
		n.protocol().Rebuttal(n)
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
