package core

import (
	"context"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/core/internal/testutil"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	msg := &pb.AnnounceRequest{OwnNote: &pb.Note{Epoch: 1}}

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
		OnRebuttal: func(target *discovery.Peer, msg *pb.AnnounceRequest) *pb.AnnounceRequest {
			if target.Addr == untrustedPeerAddr {
				return nil // Suppress
			}
			return msg // Honest
		},
	}

	trustedPeer := &discovery.Peer{Addr: trustedPeerAddr}
	untrustedPeer := &discovery.Peer{Addr: untrustedPeerAddr}
	msg := &pb.AnnounceRequest{OwnNote: &pb.Note{Epoch: 2}}

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
	comm := &commStub{}

	vs, err := newControlViewStores("naive")
	require.NoError(t, err)
	v, err := discovery.NewView(1, selfCert, comm, cs, vs)
	require.NoError(t, err)

	var (
		sentMsgs []*pb.AnnounceRequest
		addrs    []string
	)
	node := &Node{
		view: v,
		comm: comm,
		announceFn: func(_ context.Context, addr string, msg *pb.AnnounceRequest) (*pb.AnnounceResponse, error) {
			sentMsgs = append(sentMsgs, msg)
			addrs = append(addrs, addr)
			return &pb.AnnounceResponse{}, nil
		},
	}

	p1 := &discovery.Peer{Id: "peer-1", Addr: "127.0.0.1:5001"}
	p2 := &discovery.Peer{Id: "peer-2", Addr: "127.0.0.1:5002"}
	v.AddLive(p1)
	v.AddLive(p2)

	// Configure adversarial policy that withholds rebuttal specifically from peer-2
	node.SetAdversarialPolicy(&AdversarialPolicy{
		OnRebuttal: func(target *discovery.Peer, msg *pb.AnnounceRequest) *pb.AnnounceRequest {
			if target.Addr == p2.Addr {
				return nil
			}
			return msg
		},
	})

	node.rebuttal()

	// Only p1 should have received the rebuttal RPC
	assert.Contains(t, addrs, p1.Addr)
	assert.NotContains(t, addrs, p2.Addr)
	assert.Len(t, sentMsgs, 1)
	assert.NotNil(t, sentMsgs[0].GetOwnNote())
}

func TestByzantine_MaskUpperBitImmunityBypass(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	selfCert := genCert(priv, 3)
	cs := &cryptoStub{priv: priv}
	comm := &commStub{}

	// Cluster configured with numRings = 3 (maxByz = 1)
	vs, err := newControlViewStores("naive")
	require.NoError(t, err)
	v, err := discovery.NewView(3, selfCert, comm, cs, vs)
	require.NoError(t, err)

	node := &Node{
		view: v,
		comm: comm,
		cs:   cs,
	}

	peerPriv, err := genKeys()
	require.NoError(t, err)
	peerCert := genCert(peerPriv, 3)
	peerID := string(peerCert.SubjectKeyId)

	err = v.AddFull(peerID, peerCert)
	require.NoError(t, err)

	p := v.Peer(peerID)
	require.NotNil(t, p)
	v.AddLive(p)

	// Byzantine node sets unused upper bits (3..31) to 1 to deceptively deactivate all 3 rings
	// (mask = 0xFFFFFFF8). Bits 0..2 are 0 (all 3 rings disabled), bits 3..31 are 1.
	byzMask := uint32(0xFFFFFFF8)
	byzNote := testutil.NewNote(peerID, 2, byzMask, peerPriv)

	// evalNote must reject this note
	err = node.evalNote(byzNote)
	require.Error(t, err, "evalNote must reject note with upper bits set beyond numRings")
	require.Equal(t, errInvalidMask, err)
}

func TestAdversarialPolicy_ExponentialRebuttalDropper(t *testing.T) {
	// Always drop first attempt (p0 = 1.0), then halve on each attempt.
	// Over many independent peers, empirical drop rate must decrease monotonically.
	rng := rand.New(rand.NewSource(42))
	dropper := NewExponentialRebuttalDropper(BasisPointMax, 0.5, rng)

	const trials = 400
	var drops [4]int
	for i := 0; i < trials; i++ {
		p := &discovery.Peer{Id: string(genId())}
		for attempt := 0; attempt < 4; attempt++ {
			if dropper(p, nil) {
				drops[attempt]++
			}
		}
	}

	assert.Equal(t, trials, drops[0], "attempt 1 with initialBps=10000 must always drop")
	assert.Greater(t, drops[0], drops[1], "attempt 2 drop rate must be lower than attempt 1")
	assert.Greater(t, drops[1], drops[2], "attempt 3 drop rate must be lower than attempt 2")
	assert.Greater(t, drops[2], drops[3], "attempt 4 drop rate must be lower than attempt 3")
}

func TestAdversarialPolicy_DropIncomingRebuttal_TriggersExtraReconciliationRounds(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, _, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, _, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	// Admit both nodes via production Announce and converge baseline views cleanly.
	require.NoError(t, nodeA.announceToPeer(commB.Addr()))
	require.NoError(t, nodeB.announceToPeer(commA.Addr()))

	peerAOnB := nodeB.view.Peer(nodeA.self.Id)
	peerBOnA := nodeA.view.Peer(nodeB.self.Id)
	require.NotNil(t, peerAOnB)
	require.NotNil(t, peerBOnA)
	peerAOnB.Addr = commA.Addr()
	peerBOnA.Addr = commB.Addr()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	_, _, viewDiff, _ := nodeA.DivergentSets(peerBOnA)
	require.False(t, viewDiff, "baseline views must be converged before accusation")

	// nodeB has an active accusation against nodeA at epoch 1.
	acc := testutil.NewAccusation(1, peerAOnB.Id, nodeB.self.Id, 1, privB)
	testutil.AddTestAccusation(t, nodeB.view, acc)
	require.NotEmpty(t, nodeB.view.ActiveAccusationsForPeer(peerAOnB))

	// nodeB drops the first 2 incoming rebuttals from nodeA and accepts the 3rd.
	var attempts atomic.Int32
	nodeB.SetAdversarialPolicy(&AdversarialPolicy{
		OnIncomingRebuttal: NewDecreasingRebuttalDropper(func(attempt int) float64 {
			attempts.Store(int32(attempt))
			if attempt <= 2 {
				return 1.0
			}
			return 0.0
		}, nil),
	})

	// nodeA produces a real higher-epoch rebuttal self-note (epoch 2) via ShouldRebuttal.
	require.True(t, nodeA.view.ShouldRebuttal(1, 1))
	require.Equal(t, uint64(2), nodeA.view.SelfNote().Epoch())
	_, _, viewDiff, _ = nodeA.DivergentSets(peerBOnA)
	require.True(t, viewDiff)

	// Round 1: nodeB drops the rebuttal via ErrIgnore; SyncComplete reports nodeB's
	// unchanged fingerprint, so nodeA STILL sees nodeB's view as divergent.
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	assert.Equal(t, int32(1), attempts.Load())
	_, _, viewDiff, _ = nodeA.DivergentSets(peerBOnA)
	assert.True(t, viewDiff, "round 1: nodeA must remain view-divergent after nodeB dropped rebuttal")
	assert.NotEmpty(t, nodeB.view.ActiveAccusationsForPeer(peerAOnB), "round 1: accusation must still be active on nodeB")

	// Round 2: nodeB drops again -> still divergent.
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	assert.Equal(t, int32(2), attempts.Load())
	_, _, viewDiff, _ = nodeA.DivergentSets(peerBOnA)
	assert.True(t, viewDiff, "round 2: nodeA must remain view-divergent after nodeB dropped rebuttal")

	// Round 3: nodeB accepts the rebuttal -> fingerprints match and accusation is cleared.
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	assert.Equal(t, int32(3), attempts.Load())
	_, _, viewDiff, _ = nodeA.DivergentSets(peerBOnA)
	assert.False(t, viewDiff, "round 3: nodeA and nodeB views must converge once rebuttal is accepted")
	assert.Equal(t, nodeA.ViewFingerprintBytes(), peerBOnA.FingerprintView())
	assert.Empty(t, nodeB.view.ActiveAccusationsForPeer(peerAOnB), "round 3: accepted rebuttal must clear active accusation on nodeB")
	activeNote, ok := nodeB.view.ActiveNote(peerAOnB.Id)
	require.True(t, ok)
	assert.Equal(t, uint64(2), activeNote.Epoch())
}
