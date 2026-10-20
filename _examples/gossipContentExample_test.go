package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/joonnna/ifrit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetUnionMerging(t *testing.T) {
	hasher := ifrit.DefaultHasher[user]()
	s1, err := ifrit.NewDigestSet(hasher)
	require.NoError(t, err)
	s1.AddElement(user{ID: "node1-1", FirstName: "User-1", AddedBy: "node1"})
	s1.AddElement(user{ID: "node1-2", FirstName: "User-2", AddedBy: "node1"})

	s2, err := ifrit.NewDigestSet(hasher)
	require.NoError(t, err)
	s2.AddElement(user{ID: "node1-2", FirstName: "User-2", AddedBy: "node1"}) // Duplicate
	s2.AddElement(user{ID: "node2-1", FirstName: "User-1", AddedBy: "node2"})

	// Verify delta merging into an independent copy
	merged := s1.Copy()
	added := merged.AddElements(s2.Elements()...)
	assert.Equal(t, 1, added) // Only s2's node2-1 is new
	assert.Equal(t, 3, merged.Size())
	assert.Equal(t, 2, s1.Size()) // s1 remains untouched

	// Verify JSON serialization and deserialization
	raw1, err := json.Marshal(s1)
	require.NoError(t, err)

	decoded, err := ifrit.NewDigestSet(hasher)
	require.NoError(t, err)
	err = json.Unmarshal(raw1, decoded)
	require.NoError(t, err)
	assert.Equal(t, 2, decoded.Size())
}

func TestApplicationGossipSetIntegration(t *testing.T) {
	gSet := ifrit.NewNaiveGossipSet[user](nil, nil)
	defer gSet.Close()

	app := &application{
		store:    gSet,
		exitChan: make(chan struct{}),
		hostname: "test-node",
	}

	// Add local users
	app.addRandomUser()
	app.addRandomUser()
	assert.Equal(t, 2, app.store.Size())

	// Simulate 10 concurrent peers bombarding the node with overlapping sets
	var wgPeers sync.WaitGroup
	peerCount := 10
	itemsPerPeer := 5

	for p := 0; p < peerCount; p++ {
		wgPeers.Add(1)
		go func(peerIdx int) {
			defer wgPeers.Done()
			peerSet, err := ifrit.NewDigestSet(ifrit.DefaultHasher[user]())
			require.NoError(t, err)
			for i := 0; i < itemsPerPeer; i++ {
				peerSet.AddElement(user{
					ID:        fmt.Sprintf("node-%d-item-%d", peerIdx, i),
					FirstName: fmt.Sprintf("User-%d", i),
					AddedBy:   fmt.Sprintf("node-%d", peerIdx),
				})
			}
			// Add an overlap element shared across all peers
			peerSet.AddElement(user{
				ID:        "shared-user",
				FirstName: "Shared",
				AddedBy:   "common",
			})

			raw, err := json.Marshal(peerSet)
			if err == nil {
				// Inject gossip bytes directly into the node's store
				var items []user
				_ = json.Unmarshal(raw, &items)
				app.store.AddElements(items...)
			}
		}(p)
	}

	wgPeers.Wait()

	// Total expected unique items: 2 local items + 10 peers * 5 items + 1 shared item = 53 items
	expectedTotal := 2 + (peerCount * itemsPerPeer) + 1
	assert.Equal(t, expectedTotal, app.store.Size())

	// Verify Elements() returns all elements
	elems := app.store.Elements()
	assert.Equal(t, expectedTotal, len(elems))
}
