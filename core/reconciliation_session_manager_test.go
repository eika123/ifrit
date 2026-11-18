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

	// Acquire outbound lock
	seq, ok := s.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, SessionOutboundReconciling, s.State())

	// Mutual exclusion: simultaneous outbound initiation attempt returns false
	_, ok = s.TryStartOutboundReconciling()
	assert.False(t, ok)

	// ResetIfSeq returns to Idle when seq matches
	assert.True(t, s.ResetIfSeq(seq))
	assert.Equal(t, SessionIdle, s.State())

	// ResetToIdle increments seq and returns to Idle
	seq2, ok := s.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Greater(t, seq2, seq)
	s.ResetToIdle()
	assert.Equal(t, SessionIdle, s.State())
	assert.False(t, s.ResetIfSeq(seq2))
}

func TestPeerReconcileSession_InboundRefCountForConcurrentSubStores(t *testing.T) {
	s := NewPeerReconcileSession("peer-inbound")

	// Control stream ("certs") acquires inbound session
	seq1, ok, err := s.TryStartInboundReconciling("self-node", "peer-inbound")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, SessionInboundReconciling, s.State())

	// Concurrent "data" sub-store stream from the SAME winning peer shares the inbound session
	seq2, ok, err := s.TryStartInboundReconciling("self-node", "peer-inbound")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, seq1, seq2)
	assert.Equal(t, SessionInboundReconciling, s.State())

	// Outbound initiation is blocked while inbound streams are active
	_, outOK := s.TryStartOutboundReconciling()
	assert.False(t, outOK)

	// Releasing first stream leaves session in InboundReconciling until second stream finishes
	assert.True(t, s.ReleaseInbound(seq1))
	assert.Equal(t, SessionInboundReconciling, s.State())

	// Releasing second stream transitions back to SessionIdle
	assert.True(t, s.ReleaseInbound(seq2))
	assert.Equal(t, SessionIdle, s.State())
}

func TestPeerReconcileSession_TieBreaker_HigherPeerYieldsToLowerPeer(t *testing.T) {
	idA := "0001"
	idB := "0002"

	// SCENARIO 1: Node B (higher ID) is dialing A (lower ID) when inbound from A arrives.
	// Higher peer B must yield to lower peer A!
	sessOnB := NewPeerReconcileSession(idA)
	seqOutB, ok := sessOnB.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, SessionOutboundReconciling, sessOnB.State())

	seqInA, ok, err := sessOnB.TryStartInboundReconciling(idB, idA)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Greater(t, seqInA, seqOutB)
	assert.Equal(t, SessionInboundReconciling, sessOnB.State())

	// Stale outbound goroutine finishing on B with seqOutB must NOT clobber A's inbound session.
	assert.False(t, sessOnB.ResetIfSeq(seqOutB))
	assert.Equal(t, SessionInboundReconciling, sessOnB.State())

	// Releasing inbound finishes cleanly to Idle.
	assert.True(t, sessOnB.ReleaseInbound(seqInA))
	assert.Equal(t, SessionIdle, sessOnB.State())

	// SCENARIO 2: Node A (lower ID) is dialing B (higher ID) when inbound from B arrives.
	// Lower peer A holds priority and rejects B with ErrSessionBusy!
	sessOnA := NewPeerReconcileSession(idB)
	seqOutA, ok := sessOnA.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, SessionOutboundReconciling, sessOnA.State())

	_, ok, err = sessOnA.TryStartInboundReconciling(idA, idB)
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrSessionBusy)
	assert.Equal(t, SessionOutboundReconciling, sessOnA.State())

	assert.True(t, sessOnA.ResetIfSeq(seqOutA))
	assert.Equal(t, SessionIdle, sessOnA.State())
}

func TestPeerReconcileSession_StaleSeqRejection(t *testing.T) {
	s := NewPeerReconcileSession("peer-stale")

	seq1, ok := s.TryStartOutboundReconciling()
	require.True(t, ok)
	assert.Equal(t, uint64(1), seq1)

	// Sweep invalidates seq1 by incrementing seq
	swept := s.SweepIfStale(0)
	assert.True(t, swept)
	assert.Equal(t, SessionIdle, s.State())
	assert.Equal(t, uint64(2), s.Seq())

	// Old goroutine waking up with seq1 cannot reset or release newer generation
	assert.False(t, s.ResetIfSeq(seq1))
	assert.False(t, s.ReleaseInbound(seq1))
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

	// s1 finishes normally
	assert.True(t, s1.ResetIfSeq(seq1))
	assert.Equal(t, SessionIdle, s1.State())

	// s2 remains stuck in OutboundReconciling until swept
	time.Sleep(70 * time.Millisecond)

	swept := mgr.SweepStaleSessions()
	assert.Equal(t, 1, swept)
	assert.Equal(t, SessionIdle, s2.State())
}
