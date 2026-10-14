package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/go-set/v2"
	"github.com/joonnna/ifrit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetUnionMerging(t *testing.T) {
	s1 := set.New[user](10)
	s1.Insert(user{ID: "node1-1", FirstName: "User-1", AddedBy: "node1"})
	s1.Insert(user{ID: "node1-2", FirstName: "User-2", AddedBy: "node1"})

	s2 := set.New[user](10)
	s2.Insert(user{ID: "node1-2", FirstName: "User-2", AddedBy: "node1"}) // Duplicate
	s2.Insert(user{ID: "node2-1", FirstName: "User-1", AddedBy: "node2"})

	// Verify mathematical set union
	unionCol := s1.Union(s2)
	assert.Equal(t, 3, unionCol.Size())

	// Verify JSON serialization and deserialization
	raw1, err := s1.MarshalJSON()
	require.NoError(t, err)

	decoded := set.New[user](0)
	err = json.Unmarshal(raw1, decoded)
	require.NoError(t, err)
	assert.Equal(t, 2, decoded.Size())
}

func TestApplicationGossipSetIntegration(t *testing.T) {
	gSet := ifrit.NewGossipSet[user](nil)
	defer gSet.Close()

	app := &application{
		gossipSet: gSet,
		exitChan:  make(chan struct{}),
		hostname:  "test-node",
	}

	// Add local users
	app.addRandomUser()
	app.addRandomUser()
	assert.Equal(t, 2, app.gossipSet.Size())

	// Simulate 10 concurrent peers bombarding the node with overlapping sets
	var wgPeers sync.WaitGroup
	peerCount := 10
	itemsPerPeer := 5

	for p := 0; p < peerCount; p++ {
		wgPeers.Add(1)
		go func(peerIdx int) {
			defer wgPeers.Done()
			peerSet := set.New[user](itemsPerPeer)
			for i := 0; i < itemsPerPeer; i++ {
				peerSet.Insert(user{
					ID:        fmt.Sprintf("node-%d-item-%d", peerIdx, i),
					FirstName: fmt.Sprintf("User-%d", i),
					AddedBy:   fmt.Sprintf("node-%d", peerIdx),
				})
			}
			// Add an overlap element shared across all peers
			peerSet.Insert(user{
				ID:        "shared-user",
				FirstName: "Shared",
				AddedBy:   "common",
			})

			raw, err := peerSet.MarshalJSON()
			if err == nil {
				// Inject gossip bytes directly into the node's GossipSet
				var items []user
				_ = json.Unmarshal(raw, &items)
				app.gossipSet.AddElements(items...)
			}
		}(p)
	}

	wgPeers.Wait()

	// Total expected unique items: 2 local items + 10 peers * 5 items + 1 shared item = 53 items
	expectedTotal := 2 + (peerCount * itemsPerPeer) + 1
	assert.Equal(t, expectedTotal, app.gossipSet.Size())

	// Verify Copy() snapshot returns an independent copy
	snapshot := app.gossipSet.Copy()
	assert.Equal(t, expectedTotal, snapshot.Size())
}
