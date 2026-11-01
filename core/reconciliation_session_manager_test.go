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
	err := s.StartTransfer()
	assert.ErrorIs(t, err, ErrInvalidTransition)

	// TryStartReconciling
	assert.True(t, s.TryStartReconciling())
	assert.Equal(t, SessionReconciling, s.State())

	// Mutual exclusion: simultaneous initiation attempt returns false
	assert.False(t, s.TryStartReconciling())

	// Transition without deltas -> returns to Idle
	nextState := s.TransitionAfterReconcile(true)
	assert.Equal(t, SessionIdle, nextState)
	assert.Equal(t, SessionIdle, s.State())

	// Reconcile with deltas as Caller
	assert.True(t, s.TryStartReconciling())
	s.SetHasDeltas(true)

	assert.True(t, s.HasDeltas())
	nextState = s.TransitionAfterReconcile(true) // caller
	assert.Equal(t, SessionTransferring, nextState)
	assert.Equal(t, SessionTransferring, s.State())

	// FinishTransfer returns to Idle
	s.FinishTransfer()
	assert.Equal(t, SessionIdle, s.State())
	assert.False(t, s.HasDeltas())

	// Reconcile with deltas as Responder
	assert.True(t, s.TryStartReconciling())
	s.SetHasDeltas(true)
	nextState = s.TransitionAfterReconcile(false) // responder
	assert.Equal(t, SessionAwaitingStream, nextState)
	assert.Equal(t, SessionAwaitingStream, s.State())

	// Remote peer opens stream -> transitions to Transferring
	err = s.StartTransfer()
	require.NoError(t, err)
	assert.Equal(t, SessionTransferring, s.State())

	s.FinishTransfer()
	assert.Equal(t, SessionIdle, s.State())
}

func TestPeerReconcileSession_InboundReconcilingTransitions(t *testing.T) {
	s := NewPeerReconcileSession("peer-inbound")

	// Inbound from Idle succeeds
	assert.True(t, s.TryStartInboundReconciling())
	assert.Equal(t, SessionReconciling, s.State())

	// Transition to AwaitingStream (deltas found)
	s.SetHasDeltas(true)
	s.TransitionAfterReconcile(false)
	assert.Equal(t, SessionAwaitingStream, s.State())

	// New inbound Spread arrives while AwaitingStream (supersedes old round) -> succeeds
	assert.True(t, s.TryStartInboundReconciling())
	assert.Equal(t, SessionReconciling, s.State())

	// Transition to Transferring
	s.SetHasDeltas(true)
	s.TransitionAfterReconcile(false)
	err := s.StartTransfer()
	require.NoError(t, err)
	assert.Equal(t, SessionTransferring, s.State())

	// Inbound Spread rejected while actively transferring
	assert.False(t, s.TryStartInboundReconciling())
	assert.Equal(t, SessionTransferring, s.State())

	s.FinishTransfer()
	assert.Equal(t, SessionIdle, s.State())
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
			if s.TryStartReconciling() {
				mu.Lock()
				acquiredCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly one goroutine should win the race
	assert.Equal(t, 1, acquiredCount)
	assert.Equal(t, SessionReconciling, s.State())
}

func TestPeerSessionManager_StaleSweep(t *testing.T) {
	mgr := NewPeerSessionManager(50 * time.Millisecond)

	s1 := mgr.GetOrCreate("peer-a")
	s2 := mgr.GetOrCreate("peer-b")

	assert.True(t, s1.TryStartReconciling())
	assert.True(t, s2.TryStartReconciling())

	// S1 finishes normally
	s1.TransitionAfterReconcile(true)
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
