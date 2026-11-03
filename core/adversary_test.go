package core

import (
	"testing"

	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTrackingComm struct {
	*commStub
	sentMsgs []*pb.State
	addrs    []string
}

func (m *mockTrackingComm) Gossip(addr string, msg *pb.State) (*pb.StateResponse, error) {
	m.sentMsgs = append(m.sentMsgs, msg)
	m.addrs = append(m.addrs, addr)
	return &pb.StateResponse{}, nil
}

func TestAdversarialPolicy_SuppressRebuttalBps(t *testing.T) {
	node := &Node{
		view: &discovery.View{},
	}

	// 100% suppression (10000 bps)
	node.SetAdversarialPolicy(&AdversarialPolicy{
		SuppressRebuttalBps: BasisPointMax,
	})

	adv := node.AdversarialPolicy()
	require.NotNil(t, adv)

	p := &discovery.Peer{Addr: "127.0.0.1:1001"}
	msg := &pb.State{OwnNote: &pb.Note{Epoch: 1}}

	_, suppress := adv.shouldSuppressRebuttal(p, msg)
	assert.True(t, suppress, "10000 bps must suppress rebuttal")

	// 0% suppression (0 bps)
	node.SetAdversarialPolicy(&AdversarialPolicy{
		SuppressRebuttalBps: 0,
	})
	adv = node.AdversarialPolicy()
	_, suppress = adv.shouldSuppressRebuttal(p, msg)
	assert.False(t, suppress, "0 bps must not suppress rebuttal")
}

func TestAdversarialPolicy_SelectiveRebuttalHook(t *testing.T) {
	trustedPeerAddr := "127.0.0.1:1001"
	untrustedPeerAddr := "127.0.0.1:1002"

	// Selective rebuttal: only respond to trusted peer
	policy := &AdversarialPolicy{
		OnRebuttal: func(target *discovery.Peer, msg *pb.State) *pb.State {
			if target.Addr == untrustedPeerAddr {
				return nil // Suppress
			}
			return msg // Honest
		},
	}

	trustedPeer := &discovery.Peer{Addr: trustedPeerAddr}
	untrustedPeer := &discovery.Peer{Addr: untrustedPeerAddr}
	msg := &pb.State{OwnNote: &pb.Note{Epoch: 2}}

	resTrusted, suppressTrusted := policy.shouldSuppressRebuttal(trustedPeer, msg)
	assert.False(t, suppressTrusted)
	assert.Equal(t, msg, resTrusted)

	resUntrusted, suppressUntrusted := policy.shouldSuppressRebuttal(untrustedPeer, msg)
	assert.True(t, suppressUntrusted)
	assert.Nil(t, resUntrusted)
}

func TestAdversarialPolicy_SuppressAccusation(t *testing.T) {
	p := &discovery.Peer{Addr: "127.0.0.1:2001"}

	// 1. Basis points 100%
	policyBps := &AdversarialPolicy{
		SuppressAccusationBps: BasisPointMax,
	}
	assert.True(t, policyBps.shouldSuppressAccusation(p, 1))

	// 2. Basis points 0%
	policyBpsZero := &AdversarialPolicy{
		SuppressAccusationBps: 0,
	}
	assert.False(t, policyBpsZero.shouldSuppressAccusation(p, 1))

	// 3. Functional hook
	policyHook := &AdversarialPolicy{
		OnProbeFailure: func(target *discovery.Peer, ringNum uint32) bool {
			// Only allow accusations on ring 1, suppress on ring 2
			return ringNum == 1
		},
	}
	assert.False(t, policyHook.shouldSuppressAccusation(p, 1), "ring 1 allowed -> not suppressed")
	assert.True(t, policyHook.shouldSuppressAccusation(p, 2), "ring 2 not allowed -> suppressed")
}

func TestAdversarialPolicy_EndToEndRebuttalDispatch(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	selfCert := genCert(priv, 1)
	cs := &cryptoStub{priv: priv}
	comm := &mockTrackingComm{commStub: &commStub{}}

	v, err := discovery.NewView(1, selfCert, comm, cs)
	require.NoError(t, err)

	node := &Node{
		view: v,
		comm: comm,
	}

	p1 := &discovery.Peer{Id: "peer-1", Addr: "127.0.0.1:5001"}
	p2 := &discovery.Peer{Id: "peer-2", Addr: "127.0.0.1:5002"}
	v.AddLive(p1)
	v.AddLive(p2)

	// Configure adversarial policy that withholds rebuttal specifically from peer-2
	node.SetAdversarialPolicy(&AdversarialPolicy{
		OnRebuttal: func(target *discovery.Peer, msg *pb.State) *pb.State {
			if target.Addr == p2.Addr {
				return nil
			}
			return msg
		},
	})

	node.rebuttal()

	// Only p1 should have received the rebuttal RPC
	assert.Contains(t, comm.addrs, p1.Addr)
	assert.NotContains(t, comm.addrs, p2.Addr)
	assert.Len(t, comm.sentMsgs, 1)
	assert.NotNil(t, comm.sentMsgs[0].GetOwnNote())
}
