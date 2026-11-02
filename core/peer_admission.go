package core

import (
	"crypto/x509"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
)

func (n *Node) admitCaller(cert *x509.Certificate, remoteId string, ownNote *pb.Note) (*discovery.Peer, bool, bool, error) {
	var wasObserved, wasAccused bool

	// TIER 1: Unconditional raw ingestion of own note
	if ownNote != nil {
		if rawNote := discovery.NoteFromPb(ownNote); rawNote != nil && n.view.NoteStore() != nil {
			n.view.NoteStore().Insert(rawNote)
		}
	}

	peer := n.view.Peer(remoteId)
	if peer != nil {
		wasObserved = true
		wasAccused = n.view.IsAccused(peer)
	}

	if n.view.ShouldBeNeighbour(remoteId) || !wasObserved {
		if err := n.evalCertificate(cert); err != nil {
			log.Error(err.Error())
			return nil, wasObserved, wasAccused, err
		}
		if peer == nil {
			peer = n.view.Peer(remoteId)
		}
	}

	if ownNote != nil {
		if err := n.evalNote(ownNote); err != nil && err != errOldNote {
			log.Debug(err.Error())
		}
	}

	return peer, wasObserved, wasAccused, nil
}

func (n *Node) handleNonNeighbourSpread(remoteId string, peer *discovery.Peer, wasObserved bool, wasAccused bool, reply *pb.StateResponse) (*pb.StateResponse, error) {
	if wasObserved {
		if !wasAccused {
			return nil, errNotMyNeighbour
		}
		for _, a := range n.view.ActiveAccusationsForPeer(peer) {
			reply.Accusations = append(reply.Accusations, a.ToPbMsg())
		}
		return reply, nil
	}

	// Help new peer integrate into the network
	reply.Certificates = append(reply.Certificates,
		&pb.Certificate{Raw: n.cm.Certificate().Raw})
	if selfNote := n.view.SelfNote(); selfNote != nil {
		reply.Notes = append(reply.Notes, selfNote.ToPbMsg())
	}

	for _, p := range n.view.FindNeighbours(remoteId) {
		reply.Certificates = append(reply.Certificates,
			&pb.Certificate{Raw: p.Certificate()})
		if note, ok := n.view.ActiveNote(p.Id); ok {
			reply.Notes = append(reply.Notes, note.ToPbMsg())
		}
	}

	return reply, nil
}

