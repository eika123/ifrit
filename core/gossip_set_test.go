package core

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testItem struct {
	ID    string `json:"id"`
	Value int    `json:"value"`
}

func TestGossipSet_BasicOperations(t *testing.T) {
	gs := NewGossipSet[testItem](nil)
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

	// RawBytes
	raw := gs.RawBytes()
	var decoded []testItem
	err := json.Unmarshal(raw, &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 3)
}

func TestGossipSet_CopyIsolation(t *testing.T) {
	gs := NewGossipSet[testItem](nil)
	defer gs.Close()

	gs.AddElement(testItem{ID: "orig", Value: 1})

	// Get a copy
	cp := gs.Copy()
	assert.Equal(t, 1, cp.Size())
	assert.True(t, cp.Contains(testItem{ID: "orig", Value: 1}))

	// Mutate the copied set directly
	cp.Insert(testItem{ID: "mutated-outside", Value: 999})
	cp.Remove(testItem{ID: "orig", Value: 1})

	// Internal GossipSet state MUST remain unaffected
	assert.Equal(t, 1, gs.Size())
	assert.True(t, gs.Contains(testItem{ID: "orig", Value: 1}))
	assert.False(t, gs.Contains(testItem{ID: "mutated-outside", Value: 999}))
}

func TestGossipSet_RemoteMergeAndOnUpdate(t *testing.T) {
	gs := NewGossipSet[testItem](nil)
	defer gs.Close()

	gs.AddElement(testItem{ID: "local-1", Value: 10})

	updateChan := make(chan struct {
		newItems []testItem
		total    int
	}, 10)

	gs.OnUpdate(func(newElements []testItem, total int) {
		updateChan <- struct {
			newItems []testItem
			total    int
		}{newElements, total}
	})

	// Prepare remote gossip payload
	remoteSet := set.New[testItem](2)
	remoteSet.Insert(testItem{ID: "local-1", Value: 10})  // duplicate
	remoteSet.Insert(testItem{ID: "remote-1", Value: 20}) // new
	remoteSet.Insert(testItem{ID: "remote-2", Value: 30}) // new
	remoteBytes, err := remoteSet.MarshalJSON()
	require.NoError(t, err)

	// Simulate receiving remote gossip
	internalGS := gs.(*gossipSet[testItem])
	reply, err := internalGS.handleGossip(remoteBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, reply)

	// Wait for merge callback
	select {
	case update := <-updateChan:
		assert.Equal(t, 3, update.total)
		assert.Len(t, update.newItems, 3)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for OnUpdate callback")
	}

	assert.Equal(t, 3, gs.Size())
	assert.True(t, gs.Contains(testItem{ID: "remote-1", Value: 20}))
	assert.True(t, gs.Contains(testItem{ID: "remote-2", Value: 30}))

	// Sending the same remote bytes again should NOT trigger OnUpdate
	_, _ = internalGS.handleGossip(remoteBytes)
	select {
	case <-updateChan:
		t.Fatal("OnUpdate should not have been called for duplicate gossip")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestGossipSet_ConcurrentAccessAndRaceDetector(t *testing.T) {
	gs := NewGossipSet[string](nil)
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
				remSet := set.New[string](5)
				for j := 0; j < 5; j++ {
					remSet.Insert(fmt.Sprintf("remote-%d-%d-%d", remoteID, i, j))
				}
				raw, _ := remSet.MarshalJSON()
				internalGS := gs.(*gossipSet[string])
				_, _ = internalGS.handleGossip(raw)
			}
		}(r)
	}

	// Concurrent readers using Copy(), Elements(), Size(), Contains()
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
					_ = gs.RawBytes()
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
