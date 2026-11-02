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

func (n *Node) handleNonNeighbourSpread(remoteId string, peer *discovery.Peer, wasObserved bool, wasAccused bool, args *pb.State, reply *pb.StateResponse) (*pb.StateResponse, error) {
	if wasObserved {
		if !wasAccused {
			return nil, errNotMyNeighbour
		}
		// the number of active accusations is bounded by the number of rings --
		// this acts as a fast path to piggyback active accusations that are on a
		// timer
		for _, a := range n.view.ActiveAccusationsForPeer(peer) {
			reply.Accusations = append(reply.Accusations, a.ToPbMsg())
		}
		return reply, nil
	}

	// priority reconciliation: certs, notes and accusations first.
	// Trigger applicaiton data reconciliation on next round when the remote peer
	// is integrated into the correct fireflies ring

	// fingerpints
	reply.FingerprintCertificates = n.CertFingerprintBytes()
	reply.FingerprintView = n.ViewFingerprintBytes()
	reply.FingerprintAccusations = n.AccusationFingerprintBytes()

	// force data reecon after integration -- find a better way to negotiate this later
	reply.FingerprintData = args.FingerprintData

	// compute control deltas for certs, notes, and accusations
	if err := n.computeControlDeltas(remoteId, args, reply); err != nil {
		return nil, err
	}

	return reply, nil
}
