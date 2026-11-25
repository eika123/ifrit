package core

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerGate_OutboundLifecycleAndPruning(t *testing.T) {
	g := NewPeerGate()
	assert.True(t, g.IsIdle("peer-1"))
	assert.Equal(t, 0, g.Len())

	require.True(t, g.TryAquireOutbound("peer-1"))
	assert.False(t, g.IsIdle("peer-1"))
	assert.Equal(t, 1, g.Len())

	// Mutual exclusion: simultaneous outbound initiation is rejected.
	assert.False(t, g.TryAquireOutbound("peer-1"))

	// Release prunes the idle entry back to Len() == 0.
	g.ReleaseOutbound("peer-1")
	assert.True(t, g.IsIdle("peer-1"))
	assert.Equal(t, 0, g.Len())
}

func TestPeerGate_InboundRefCountForConcurrentSubStores(t *testing.T) {
	g := NewPeerGate()

	require.NoError(t, g.TryAquireInbound("self-node", "peer-inbound"))
	assert.False(t, g.IsIdle("peer-inbound"))

	// Concurrent "data" sub-store stream from the SAME winning peer shares the inbound gate.
	require.NoError(t, g.TryAquireInbound("self-node", "peer-inbound"))

	// Outbound initiation is blocked while inbound streams are active.
	assert.False(t, g.TryAquireOutbound("peer-inbound"))

	// Releasing first stream keeps gate active until second stream finishes.
	g.ReleaseInbound("peer-inbound")
	assert.False(t, g.IsIdle("peer-inbound"))
	assert.False(t, g.TryAquireOutbound("peer-inbound"))

	// Releasing second stream returns to idle and prunes entry.
	g.ReleaseInbound("peer-inbound")
	assert.True(t, g.IsIdle("peer-inbound"))
	assert.Equal(t, 0, g.Len())
}

func TestPeerGate_TieBreaker_HigherPeerYieldsToLowerPeer(t *testing.T) {
	idA := "0001"
	idB := "0002"

	// SCENARIO 1a: Node B (higher ID) dialing A (lower ID); B yields to A, outbound exits first.
	gateB := NewPeerGate()
	require.True(t, gateB.TryAquireOutbound(idA))
	require.NoError(t, gateB.TryAquireInbound(idB, idA))

	// B's aborted outbound goroutine exits first: must NOT disturb A's active inbound stream.
	gateB.ReleaseOutbound(idA)
	assert.False(t, gateB.IsIdle(idA))
	assert.False(t, gateB.TryAquireOutbound(idA))

	// A's inbound stream completes -> gate returns to idle and prunes.
	gateB.ReleaseInbound(idA)
	assert.True(t, gateB.IsIdle(idA))
	assert.Equal(t, 0, gateB.Len())

	// SCENARIO 1b: Node B yields to A, inbound finishes BEFORE B's yielded outbound exits.
	require.True(t, gateB.TryAquireOutbound(idA))
	require.NoError(t, gateB.TryAquireInbound(idB, idA))
	gateB.ReleaseInbound(idA)
	// No second outbound may overlap the still-exiting outbound goroutine.
	assert.False(t, gateB.TryAquireOutbound(idA))
	gateB.ReleaseOutbound(idA)
	assert.True(t, gateB.IsIdle(idA))
	assert.Equal(t, 0, gateB.Len())

	// SCENARIO 2: Node A (lower ID) dialing B (higher ID); A holds priority and rejects B.
	gateA := NewPeerGate()
	require.True(t, gateA.TryAquireOutbound(idB))
	err := gateA.TryAquireInbound(idA, idB)
	assert.ErrorIs(t, err, ErrSessionBusy)
	assert.False(t, gateA.IsIdle(idB))

	gateA.ReleaseOutbound(idB)
	assert.True(t, gateA.IsIdle(idB))
	assert.Equal(t, 0, gateA.Len())
}

func TestPeerGate_ConcurrentAcquisitionRace(t *testing.T) {
	g := NewPeerGate()

	const numGoroutines = 50
	var wg sync.WaitGroup
	acquiredCount := 0
	var mu sync.Mutex

	wg.Add(numGoroutines)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			if g.TryAquireOutbound("peer-2") {
				mu.Lock()
				acquiredCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, acquiredCount)
	assert.False(t, g.IsIdle("peer-2"))
	g.ReleaseOutbound("peer-2")
	assert.Equal(t, 0, g.Len())
}
