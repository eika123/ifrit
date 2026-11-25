package core

import (
	"math"
	"math/rand"
	"sync"

	"github.com/eika123/ifrit/core/discovery"
	pb "github.com/eika123/ifrit/protobuf"
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

	// OnIncomingRebuttal is called when an incoming rebuttal note arrives (via
	// Spread with IsRebuttal=true, or via ifrit/notes reconciliation for a peer
	// that currently has an active accusation or timer). Returning true drops
	// the rebuttal without aborting reconciliation, leaving the local view
	// divergent so SyncComplete triggers extra reconciliation rounds.
	OnIncomingRebuttal func(peer *discovery.Peer, note *discovery.Note) bool
}

func (n *Node) SetAdversarialPolicy(p *AdversarialPolicy) {
	n.adversaryMutex.Lock()
	defer n.adversaryMutex.Unlock()

	n.adversary = p
}

func (n *Node) AdversarialPolicy() *AdversarialPolicy {
	n.adversaryMutex.RLock()
	defer n.adversaryMutex.RUnlock()

	return n.adversary
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

func (a *AdversarialPolicy) shouldDropIncomingRebuttal(peer *discovery.Peer, note *discovery.Note) bool {
	if a == nil || a.OnIncomingRebuttal == nil {
		return false
	}
	return a.OnIncomingRebuttal(peer, note)
}

// NewDecreasingRebuttalDropper returns an OnIncomingRebuttal hook that tracks
// the 1-based count of received rebuttals per peer and drops each rebuttal with
// probability probFn(attempt) in [0, 1]. If rng is nil, math/rand's global
// source is used.
func NewDecreasingRebuttalDropper(probFn func(attempt int) float64, rng *rand.Rand) func(*discovery.Peer, *discovery.Note) bool {
	var (
		mu       sync.Mutex
		attempts = make(map[string]int)
	)
	return func(peer *discovery.Peer, _ *discovery.Note) bool {
		if peer == nil || probFn == nil {
			return false
		}
		mu.Lock()
		attempts[peer.Id]++
		attempt := attempts[peer.Id]
		var sample float64
		if rng != nil {
			sample = rng.Float64()
		} else {
			sample = rand.Float64()
		}
		mu.Unlock()

		p := probFn(attempt)
		if p <= 0 {
			return false
		}
		if p >= 1 {
			return true
		}
		return sample < p
	}
}

// NewExponentialRebuttalDropper returns an OnIncomingRebuttal hook whose drop
// probability decays exponentially per peer: p(k) = (initialBps/10000) * decay^(k-1).
func NewExponentialRebuttalDropper(initialBps uint32, decay float64, rng *rand.Rand) func(*discovery.Peer, *discovery.Note) bool {
	p0 := float64(initialBps) / float64(BasisPointMax)
	return NewDecreasingRebuttalDropper(func(attempt int) float64 {
		return p0 * math.Pow(decay, float64(attempt-1))
	}, rng)
}
