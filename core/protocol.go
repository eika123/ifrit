package core

import (
	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
)

type correct struct {
}

type spamAccusations struct {
}

type experiment struct {
	addr    string
	maxConc int
}

func (c correct) Rebuttal(n *Node) {
	neighbours := n.view.GossipPartners()

	selfNote := n.view.SelfNote()
	if selfNote == nil {
		return
	}
	noteMsg := selfNote.ToPbMsg()

	msg := &pb.State{
		OwnNote: noteMsg,
	}

	for _, p := range neighbours {
		_, err := n.comm.Gossip(p.Addr, msg)
		if err != nil {
			log.Error(err.Error(), "addr", p.Addr)
			continue
		}
	}
}

func (c correct) Gossip(n *Node) {
	neighbours := n.view.GossipPartners()

	for _, p := range neighbours {
		if !n.IsDivergent(p) {
			continue
		}

		var sess *PeerReconcileSession
		if n.sessionManager != nil {
			sess = n.sessionManager.GetOrCreate(p.Id)
			if !sess.TryStartReconciling() {
				continue
			}
		}

		msg := n.collectGossipContentForPeer(p)

		// the comm.Gossip actually does the RPC
		reply, err := n.comm.Gossip(p.Addr, msg)
		if err != nil {
			if sess != nil {
				sess.ResetToIdle()
			}
			log.Error(err.Error(), "addr", p.Addr)
			continue
		}

		// Ingest control items if present (e.g. bootstrap response)
		if certs := reply.GetCertificates(); len(certs) > 0 {
			n.mergeCertificates(certs)
		}
		if notes := reply.GetNotes(); len(notes) > 0 {
			n.mergeNotes(notes)
		}
		if accs := reply.GetAccusations(); len(accs) > 0 {
			n.mergeAccusations(accs)
		}

		hasDeltas := hasReconciliationDeltas(reply)
		if sess != nil {
			sess.SetHasDeltas(hasDeltas)
			sess.TransitionAfterReconcile(true)
		}

		if !hasDeltas {
			// In sync: update cached peer fingerprints from responder's reply
			if fpData := reply.GetFingerprintData(); fpData != nil {
				p.SetFingerprintData(fpData)
			}
			if fpAcc := reply.GetFingerprintAccusations(); fpAcc != nil {
				p.SetFingerprintAccusations(fpAcc)
			}
			if fpView := reply.GetFingerprintView(); fpView != nil {
				p.SetFingerprintView(fpView)
			}
		}

		if handler := n.getResponseHandler(); handler != nil {
			if replyGossip := reply.GetExternalGossip(); replyGossip != nil {
				handler(replyGossip)
			}
		}
	}
}

// hasReconciliationDeltas returns true if the StateResponse contains any requested
// or available digest differences for certificates, notes, accusations, or data.
func hasReconciliationDeltas(reply *pb.StateResponse) bool {
	if reply == nil {
		return false
	}
	return len(reply.GetRequestedCertificateDigests()) > 0 ||
		len(reply.GetAvailableCertificateDigests()) > 0 ||
		len(reply.GetRequestedNoteDigests()) > 0 ||
		len(reply.GetAvailableNoteDigests()) > 0 ||
		len(reply.GetRequestedAccusationDigests()) > 0 ||
		len(reply.GetAvailableAccusationDigests()) > 0 ||
		len(reply.GetRequestedDataDigests()) > 0 ||
		len(reply.GetAvailableDataDigests()) > 0
}

func (c correct) Monitor(n *Node) {

	// Fireflies protocol: ping one successor per ring,
	// up to ringsPingedPerInterval in total.
	for i := 1; i <= n.ringsPingedPerInterval; i++ {
		p, ringNum := n.view.MonitorTarget()
		if p == nil {
			continue
		}

		err := n.fd.probe(p)
		if err == errDead {
			log.Debug("Monitor --> Successor dead, accusing", "succ", p.Addr, "ringNum", ringNum)
			peerNote, found := n.view.ActiveNote(p.Id)

			// Will always have note for a peer in our liveView, except when the peer stems
			// from the initial contact list of the CA, if it's dead
			// we should remove it to ensure it doesn't stay in our liveView.
			// Not possible to accuse a peer without a note.
			if !found || peerNote == nil {
				n.view.RemoveLive(p)
				log.Debug("Monitor -- Removing live peer due to not having note and being accused",
					"addr", p.Addr)
				continue
			}

			err := n.view.CreateAccusation(p, peerNote, ringNum, n.cs)
			if err == discovery.ErrAccAlreadyExists || err == nil {
				live := n.view.IsAlive(p)
				if exists := n.view.HasTimer(p); !exists && live {
					n.view.StartTimer(p, peerNote, n.self)
				}
			} else {
				log.Error(err.Error())
			}
		}

		if err == errInvalidPongSignature {
			log.Debug("Monitor -- Invalid pong signature, successor is malicious (or this implementation is just buggy!)", "succ", p.Addr)
		}

		if err != nil && err != errInvalidPongSignature {
			log.Error(err.Error(), "Monitor -- successor peer addr:", p.Addr)
		}
	}
}
