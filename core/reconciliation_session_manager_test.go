package core

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerReconcileSession_LifecycleAndConcurrency(t *testing.T) {
	s := NewPeerReconcileSession("peer-1")
	assert.Equal(t, "peer-1", s.PeerID())
	assert.Equal(t, SessionIdle, s.State())

	// Cannot transition directly to transferring from idle
	err := s.StartTransfer(1)
	assert.ErrorIs(t, err, ErrInvalidTransition)

	// TryStartOutboundReconciling
	seq, ok := s.TryStartOutboundReconciling()
	assert.True(t, ok)
	assert.Equal(t, SessionOutboundReconciling, s.State())

	// Mutual exclusion: simultaneous initiation attempt returns false
	_, ok = s.TryStartOutboundReconciling()
	assert.False(t, ok)

	// Transition without deltas -> returns to Idle
	nextState := s.TransitionAfterReconcile(seq, true)
	assert.Equal(t, SessionIdle, nextState)
	assert.Equal(t, SessionIdle, s.State())

	// Reconcile with deltas as Caller
	seq, ok = s.TryStartOutboundReconciling()
	assert.True(t, ok)
	s.SetHasDeltas(true)

	assert.True(t, s.HasDeltas())
	nextState = s.TransitionAfterReconcile(seq, true) // caller
	assert.Equal(t, SessionTransferring, nextState)
	assert.Equal(t, SessionTransferring, s.State())

	// CompleteTransfer returns to Idle
	assert.True(t, s.CompleteTransfer(seq))
	assert.Equal(t, SessionIdle, s.State())
	assert.False(t, s.HasDeltas())

	// Reconcile with deltas as Responder
	seq, ok, err = s.TryStartInboundReconciling("self-1", "peer-1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, SessionInboundReconciling, s.State())
	s.SetHasDeltas(true)
	nextState = s.TransitionAfterReconcile(seq, false) // responder
	assert.Equal(t, SessionAwaitingStream, nextState)
	assert.Equal(t, SessionAwaitingStream, s.State())

	// Remote peer opens stream -> transitions to Transferring
	err = s.StartTransfer(seq)
	require.NoError(t, err)
	assert.Equal(t, SessionTransferring, s.State())

	s.CompleteTransfer(seq)
	assert.Equal(t, SessionIdle, s.State())
}

func TestPeerReconcileSession_InboundReconcilingTransitions(t *testing.T) {
	s := NewPeerReconcileSession("peer-inbound")

	// Inbound from Idle succeeds
	seq, ok, err := s.TryStartInboundReconciling("self-node", "peer-inbound")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, SessionInboundReconciling, s.State())

	// Transition to AwaitingStream (deltas found)
	s.SetHasDeltas(true)
	s.TransitionAfterReconcile(seq, false)
	assert.Equal(t, SessionAwaitingStream, s.State())

	// New inbound Spread arrives while AwaitingStream (supersedes old round) -> succeeds
	seq2, ok, err := s.TryStartInboundReconciling("self-node", "peer-inbound")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Greater(t, seq2, seq)
	assert.Equal(t, SessionInboundReconciling, s.State())

	// Transition to Transferring
	s.SetHasDeltas(true)
	s.TransitionAfterReconcile(seq2, false)
	err = s.StartTransfer(seq2)
	require.NoError(t, err)
	assert.Equal(t, SessionTransferring, s.State())

	// Inbound Spread rejected while actively transferring
	_, ok, err = s.TryStartInboundReconciling("self-node", "peer-inbound")
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrSessionBusy)
	assert.Equal(t, SessionTransferring, s.State())

	assert.True(t, s.CompleteTransfer(seq2))
	assert.Equal(t, SessionIdle, s.State())
}

func TestPeerReconcileSession_TieBreaker_HigherPeerYieldsToLowerPeer(t *testing.T) {
	// Node A ("0001") is lower peer, Node B ("0002") is higher peer.
	idA := "0001"
	idB := "0002"

	// SCENARIO 1: We are Node B (higher peer). Node A (lower peer) calls us while we are dialing A.
	// Higher peer B must yield to lower peer A!
	sessOnB := NewPeerReconcileSession(idA)
	seqOutB, ok := sessOnB.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, SessionOutboundReconciling, sessOnB.State())

	// Inbound Spread from A arrives at B: selfID = B ("0002"), remoteID = A ("0001")
	// Since remoteID < selfID, B yields priority to A!
	seqInA, ok, err := sessOnB.TryStartInboundReconciling(idB, idA)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Greater(t, seqInA, seqOutB)
	assert.Equal(t, SessionInboundReconciling, sessOnB.State())

	// Stale outbound attempt on B returns and tries to mutate session with seqOutB:
	// All must be safely rejected due to stale seq!
	assert.False(t, sessOnB.SetDeltas(seqOutB, ReconcileDeltas{RequestedData: []uint64{1}}))
	assert.Equal(t, SessionInboundReconciling, sessOnB.TransitionAfterReconcile(seqOutB, true))
	assert.False(t, sessOnB.ResetIfSeq(seqOutB))
	assert.Equal(t, SessionInboundReconciling, sessOnB.State())

	// Responder B computes deltas for A using seqInA:
	deltas := ReconcileDeltas{AvailableData: []uint64{42}}
	assert.True(t, sessOnB.SetDeltas(seqInA, deltas))
	next := sessOnB.TransitionAfterReconcile(seqInA, false)
	assert.Equal(t, SessionAwaitingStream, next)
	assert.Equal(t, SessionAwaitingStream, sessOnB.State())

	// SCENARIO 2: We are Node A (lower peer). Node B (higher peer) calls us while we are dialing B.
	// Lower peer A holds priority! It must reject B's inbound attempt!
	sessOnA := NewPeerReconcileSession(idB)
	seqOutA, ok := sessOnA.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, SessionOutboundReconciling, sessOnA.State())

	// Inbound Spread from B arrives at A: selfID = A ("0001"), remoteID = B ("0002")
	// Since remoteID < selfID is false, A holds priority and rejects B!
	_, ok, err = sessOnA.TryStartInboundReconciling(idA, idB)
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrSessionBusy)
	assert.Equal(t, SessionOutboundReconciling, sessOnA.State())

	// Outbound call for A completes normally:
	assert.True(t, sessOnA.SetDeltas(seqOutA, ReconcileDeltas{AvailableData: []uint64{99}}))
	next = sessOnA.TransitionAfterReconcile(seqOutA, true)
	assert.Equal(t, SessionTransferring, next)
	assert.Equal(t, SessionTransferring, sessOnA.State())
}

func TestPeerReconcileSession_StaleSeqRejection(t *testing.T) {
	s := NewPeerReconcileSession("peer-stale")

	seq1, ok := s.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, uint64(1), seq1)

	// Sweep invalidates seq1 by incrementing seq
	swept := s.SweepIfStale(0) // immediately stale
	assert.True(t, swept)
	assert.Equal(t, SessionIdle, s.State())
	assert.Equal(t, uint64(2), s.Seq())

	// Old goroutine waking up with seq1 tries to operate:
	assert.False(t, s.SetDeltas(seq1, ReconcileDeltas{RequestedData: []uint64{10}}))
	assert.False(t, s.ResetIfSeq(seq1))
	assert.Equal(t, SessionIdle, s.TransitionAfterReconcile(seq1, true))
	assert.ErrorIs(t, s.StartTransfer(seq1), ErrInvalidTransition)
	assert.False(t, s.CompleteTransfer(seq1))
}

func TestPeerReconcileSession_ConcurrentAcquisitionRace(t *testing.T) {
	s := NewPeerReconcileSession("peer-2")

	const numGoroutines = 50
	var wg sync.WaitGroup
	acquiredCount := 0
	var mu sync.Mutex

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if _, ok := s.TryStartOutboundReconciling(); ok {
				mu.Lock()
				acquiredCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly one goroutine should win the race
	assert.Equal(t, 1, acquiredCount)
	assert.Equal(t, SessionOutboundReconciling, s.State())
}

func TestPeerSessionManager_StaleSweep(t *testing.T) {
	mgr := NewPeerSessionManager(50 * time.Millisecond)

	s1 := mgr.GetOrCreate("peer-a")
	s2 := mgr.GetOrCreate("peer-b")

	seq1, ok1 := s1.TryStartOutboundReconciling()
	assert.True(t, ok1)
	_, ok2 := s2.TryStartOutboundReconciling()
	assert.True(t, ok2)

	// S1 finishes normally
	s1.TransitionAfterReconcile(seq1, true)
	assert.Equal(t, SessionIdle, s1.State())

	// S2 gets stuck in Reconciling
	time.Sleep(70 * time.Millisecond)

	swept := mgr.SweepStaleSessions()
	assert.Equal(t, 1, swept)
	assert.Equal(t, SessionIdle, s2.State())
}

func TestProtocolRegistry_DefaultsAndResolution(t *testing.T) {
	// Available protocols
	protos := AvailableProtocols()
	assert.Contains(t, protos, "naive")
	assert.Contains(t, protos, "riblt")

	// GetProtocol
	naiveDef, ok := GetProtocol("naive")
	require.True(t, ok)
	assert.Equal(t, "naive", naiveDef.Name)
	assert.NotNil(t, naiveDef.NewCertSession)
	assert.NotNil(t, naiveDef.NewNoteSession)
	assert.NotNil(t, naiveDef.NewAccSession)

	ribltDef, ok := GetProtocol("riblt")
	require.True(t, ok)
	assert.Equal(t, "riblt", ribltDef.Name)
	assert.NotNil(t, ribltDef.NewCertSession)
	assert.NotNil(t, ribltDef.NewNoteSession)
	assert.NotNil(t, ribltDef.NewAccSession)

	// ResolveProtocol
	resolved := ResolveProtocol("riblt")
	assert.Equal(t, "riblt", resolved.Name)

	resolvedDefault := ResolveProtocol("unknown_strategy")
	assert.Equal(t, "naive", resolvedDefault.Name)
}

func TestNode_StartupReconciliationConfiguration(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	// Default node uses protocol initialized at startup from config/default
	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)
	defer n.Stop()

	protoDef := n.ReconciliationProtocol()
	require.Equal(t, "naive", protoDef.Name)
	require.NotNil(t, protoDef.NewCertSession)
	require.NotNil(t, protoDef.NewNoteSession)
	require.NotNil(t, protoDef.NewAccSession)
	require.NotNil(t, n.SessionManager())
}
