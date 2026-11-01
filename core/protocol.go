package core

import (
	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type correct struct {
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
		var seq uint64
		if n.sessionManager != nil {
			sess = n.sessionManager.GetOrCreate(p.Id)
			var ok bool
			seq, ok = sess.TryStartOutboundReconciling()
			if !ok {
				continue
			}
		}

		msg := n.collectGossipContentForPeer(p)

		// the comm.Gossip actually does the RPC
		reply, err := n.comm.Gossip(p.Addr, msg)
		if err != nil {
			if sess != nil {
				sess.ResetIfSeq(seq)
			}
			if status.Code(err) == codes.Aborted {
				log.Debug("Outbound gossip aborted by peer tie-breaker", "addr", p.Addr)
			} else {
				log.Error(err.Error(), "addr", p.Addr)
			}
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

		deltas := ExtractReconcileDeltas(reply)
		if sess != nil {
			sess.SetDeltas(seq, deltas)
			sess.TransitionAfterReconcile(seq, true)
		}

		if !deltas.HasDeltas() {
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
