package core

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testItem struct {
	ID    string `json:"id"`
	Value int    `json:"value"`
}

func TestGossipSet_BasicOperations(t *testing.T) {
	gs := NewNaiveGossipSet[testItem](nil, nil)
	defer gs.Close()

	assert.True(t, gs.Empty())
	assert.Equal(t, 0, gs.Size())

	// Add single element
	item1 := testItem{ID: "item-1", Value: 100}
	added := gs.AddElement(item1)
	assert.True(t, added)
	assert.Equal(t, 1, gs.Size())
	assert.False(t, gs.Empty())
	assert.True(t, gs.Contains(item1))

	// Duplicate addition should return false
	addedAgain := gs.AddElement(item1)
	assert.False(t, addedAgain)
	assert.Equal(t, 1, gs.Size())

	// Batch add
	item2 := testItem{ID: "item-2", Value: 200}
	item3 := testItem{ID: "item-3", Value: 300}
	addedCount := gs.AddElements(item1, item2, item3) // item1 duplicate, item2 & item3 new
	assert.Equal(t, 2, addedCount)
	assert.Equal(t, 3, gs.Size())

	// JSON serialization via Copy
	raw, err := json.Marshal(gs.Copy())
	require.NoError(t, err)
	var decoded []testItem
	err = json.Unmarshal(raw, &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 3)

	// Elements
	elems := gs.Elements()
	assert.Len(t, elems, 3)
}

func TestGossipSet_DigestAndReconciliationMethods(t *testing.T) {
	gs := NewNaiveGossipSet[testItem](nil, nil)
	defer gs.Close()

	item1 := testItem{ID: "item-1", Value: 100}
	item2 := testItem{ID: "item-2", Value: 200}
	gs.AddElements(item1, item2)

	digests := gs.Digests()
	assert.Len(t, digests, 2)

	// ContainsDigest and GetByDigest
	hasher := DefaultHasher[testItem]()
	d1 := hasher(item1)
	d2 := hasher(item2)

	assert.True(t, gs.ContainsDigest(d1))
	assert.True(t, gs.ContainsDigest(d2))
	assert.False(t, gs.ContainsDigest(9999999))

	retrieved, found := gs.GetByDigest(d1)
	assert.True(t, found)
	assert.Equal(t, item1, retrieved)

	_, foundNotFound := gs.GetByDigest(9999999)
	assert.False(t, foundNotFound)

	// Fingerprint
	fp := gs.Fingerprint()
	assert.Equal(t, d1^d2, fp)
}

func TestGossipSet_CopyIsolation(t *testing.T) {
	gs := NewNaiveGossipSet[testItem](nil, nil)
	defer gs.Close()

	gs.AddElement(testItem{ID: "orig", Value: 1})

	// Get a copy
	cp := gs.Copy()
	assert.Equal(t, 1, cp.Size())
	assert.True(t, cp.Contains(testItem{ID: "orig", Value: 1}))

	// Mutate the copied set directly
	cp.AddElement(testItem{ID: "mutated-outside", Value: 999})

	// Internal GossipSet state MUST remain unaffected
	assert.Equal(t, 1, gs.Size())
	assert.True(t, gs.Contains(testItem{ID: "orig", Value: 1}))
	assert.False(t, gs.Contains(testItem{ID: "mutated-outside", Value: 999}))
	assert.Equal(t, 2, cp.Size())
	assert.True(t, cp.Contains(testItem{ID: "mutated-outside", Value: 999}))
}

func TestGossipSet_RemoteMerge(t *testing.T) {
	gs := NewNaiveGossipSet[testItem](nil, nil)
	defer gs.Close()

	gs.AddElement(testItem{ID: "local-1", Value: 10})

	// Prepare remote gossip payload
	remoteSet := NewDigestSet[testItem]()
	remoteSet.AddElement(testItem{ID: "local-1", Value: 10})  // duplicate
	remoteSet.AddElement(testItem{ID: "remote-1", Value: 20}) // new
	remoteSet.AddElement(testItem{ID: "remote-2", Value: 30}) // new
	remoteBytes, err := json.Marshal(remoteSet)
	require.NoError(t, err)

	// Simulate receiving remote gossip
	internalGS := gs.(*naiveGossipSet[testItem])
	reply, err := internalGS.handleGossip(remoteBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, reply)

	// Verify merged state
	assert.Eventually(t, func() bool {
		return gs.Size() == 3 &&
			gs.Contains(testItem{ID: "remote-1", Value: 20}) &&
			gs.Contains(testItem{ID: "remote-2", Value: 30})
	}, 2*time.Second, 10*time.Millisecond)
}

func TestGossipSet_ConcurrentAccessAndRaceDetector(t *testing.T) {
	gs := NewNaiveGossipSet[string](nil, nil)
	defer gs.Close()

	var wg sync.WaitGroup
	const writers = 8
	const readers = 8
	const itemsPerWriter = 100

	// Concurrent local additions
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < itemsPerWriter; i++ {
				gs.AddElement(fmt.Sprintf("item-%d-%d", workerID, i))
			}
		}(w)
	}

	// Concurrent remote gossip injections
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(remoteID int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				remSet := NewDigestSet[string]()
				for j := 0; j < 5; j++ {
					remSet.AddElement(fmt.Sprintf("remote-%d-%d-%d", remoteID, i, j))
				}
				raw, _ := json.Marshal(remSet)
				internalGS := gs.(*naiveGossipSet[string])
				_, _ = internalGS.handleGossip(raw)
			}
		}(r)
	}

	// Concurrent readers using Copy(), Elements(), Size(), Contains(), Digests(), GetByDigest()
	stopReaders := make(chan struct{})
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_ = gs.Copy()
					_ = gs.Size()
					_ = gs.Contains("some-item")
					_ = gs.Digests()
					_ = gs.Fingerprint()
					_ = gs.Elements()
				}
			}
		}()
	}

	// Wait for writers to finish
	time.Sleep(300 * time.Millisecond)
	close(stopReaders)
	wg.Wait()

	// Verify set size is at least writers * itemsPerWriter
	assert.GreaterOrEqual(t, gs.Size(), writers*itemsPerWriter)
}
