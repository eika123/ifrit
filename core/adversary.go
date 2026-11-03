package core

import (
	"math/rand"

	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
)

// BasisPointMax represents 100.00% in integer basis points (bps).
const BasisPointMax uint32 = 10000

// AdversarialPolicy defines optional Byzantine hooks and integer basis-point rates
// to simulate malicious or faulty node behaviors without floating-point math.
type AdversarialPolicy struct {
	// Simple probabilistic rates in basis points (0..10000):
	// 0 = disabled (honest), 10000 = 100% trigger.
	SuppressRebuttalBps   uint32
	SuppressAccusationBps uint32

	// Contextual hooks:
	// OnRebuttal can inspect the target peer and either return nil (suppress),
	// the original msg (honest), or a modified msg (tampered).
	OnRebuttal func(target *discovery.Peer, msg *pb.State) *pb.State

	// OnProbeFailure is called when a successor ping fails.
	// Returning false suppresses emitting an accusation.
	OnProbeFailure func(target *discovery.Peer, ringNum uint32) bool

	// OnMonitorProbe allows forging an accusation against a peer during monitoring.
	OnMonitorProbe func(ringNum uint32) (target *discovery.Peer, forgedAcc *pb.Accusation)

	// OnGossipOut can mutate the outbound State message (e.g. poison digests or fingerprints).
	OnGossipOut func(target *discovery.Peer, msg *pb.State)
}

func (a *AdversarialPolicy) shouldSuppressRebuttal(target *discovery.Peer, msg *pb.State) (*pb.State, bool) {
	if a == nil {
		return msg, false
	}
	if a.OnRebuttal != nil {
		res := a.OnRebuttal(target, msg)
		return res, res == nil
	}
	if a.SuppressRebuttalBps > 0 && rand.Uint32()%BasisPointMax < a.SuppressRebuttalBps {
		return nil, true
	}
	return msg, false
}

func (a *AdversarialPolicy) shouldSuppressAccusation(target *discovery.Peer, ringNum uint32) bool {
	if a == nil {
		return false
	}
	if a.OnProbeFailure != nil {
		return !a.OnProbeFailure(target, ringNum)
	}
	if a.SuppressAccusationBps > 0 && rand.Uint32()%BasisPointMax < a.SuppressAccusationBps {
		return true
	}
	return false
}

