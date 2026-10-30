package versionvector

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMutableKeyFunc(item testEntity) DigestSymbol {
	return DigestSymbol(testHasher(VersionedItem[testEntity]{Item: testEntity{ID: item.ID}, Version: 0}))
}

func TestVersionVectorMutable_BasicOperations(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	assert.True(t, vv.Empty())
	assert.Equal(t, 0, vv.Size())
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint())
	assert.Empty(t, vv.Elements())
	assert.Empty(t, vv.DigestsCopy())

	e1 := testEntity{ID: "node-1", Payload: "initial"}
	vItem1 := VersionedItem[testEntity]{Item: e1, Version: 1}
	key1 := testMutableKeyFunc(e1)
	expectedDigest1 := testHasher(vItem1)

	added, ok := vv.AddItem(vItem1)
	require.True(t, ok)
	require.NotNil(t, added)
	assert.Equal(t, vItem1, *added)
	assert.False(t, vv.Empty())
	assert.Equal(t, 1, vv.Size())

	assert.True(t, vv.ContainsKey(key1))
	assert.True(t, vv.ContainsKeyVersion(key1, 1))
	assert.False(t, vv.ContainsKeyVersion(key1, 2))
	assert.False(t, vv.ContainsKeyVersion(DigestSymbol(999999), 1))

	retrieved, found := vv.GetOne(key1)
	assert.True(t, found)
	assert.Equal(t, "initial", retrieved.Item.Payload)
	assert.Equal(t, uint64(1), retrieved.Version)
	assert.Equal(t, uint64(1), vv.Versions()[key1])

	assert.Equal(t, expectedDigest1, vv.Fingerprint())
	assert.ElementsMatch(t, []DigestSymbol{expectedDigest1}, vv.DigestsCopy())

	// GetMany batch retrieval
	items := vv.GetMany([]DigestSymbol{key1})
	assert.Equal(t, []VersionedItem[testEntity]{vItem1}, items)

	// Partial / missing batch retrieval ignores missing keys
	items = vv.GetMany([]DigestSymbol{key1, DigestSymbol(999999)})
	assert.Equal(t, []VersionedItem[testEntity]{vItem1}, items)
}

func TestVersionVectorMutable_MonotonicAdvancement(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	e1 := testEntity{ID: "node-1", Payload: "v1"}
	key1 := testMutableKeyFunc(e1)

	vItem1 := VersionedItem[testEntity]{Item: e1, Version: 1}
	vv.AddItem(vItem1)
	fp1 := vv.Fingerprint()

	// Advancing to version 2
	e1v2 := testEntity{ID: "node-1", Payload: "v2"}
	vItem2 := VersionedItem[testEntity]{Item: e1v2, Version: 2}
	advanced, ok := vv.AddItem(vItem2)
	require.True(t, ok)
	require.NotNil(t, advanced)
	assert.Equal(t, vItem2, *advanced)
	assert.Equal(t, 1, vv.Size(), "Size must remain 1 for the same key")

	fp2 := vv.Fingerprint()
	assert.NotEqual(t, fp1, fp2, "Fingerprint must change when version advances")

	retrieved, found := vv.GetOne(key1)
	assert.True(t, found)
	assert.Equal(t, uint64(2), vv.Versions()[key1])
	assert.Equal(t, "v2", retrieved.Item.Payload)

	// Mathematical verification: fp2 == fp1 XOR digest(v1) XOR digest(v2)
	expectedFP2 := fp1.XOR(testHasher(vItem1)).XOR(testHasher(vItem2))
	assert.Equal(t, expectedFP2, fp2)
}

func TestVersionVectorMutable_RejectsStaleAndEqualVersions(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	e1 := testEntity{ID: "node-1", Payload: "v5"}
	key1 := testMutableKeyFunc(e1)

	vItem5 := VersionedItem[testEntity]{Item: e1, Version: 5}
	vv.AddItem(vItem5)
	fpCurrent := vv.Fingerprint()

	// Attempt to add equal version 5
	appliedEqual, okEqual := vv.AddItem(VersionedItem[testEntity]{
		Item:    testEntity{ID: "node-1", Payload: "v5-duplicate"},
		Version: 5,
	})
	assert.False(t, okEqual, "Equal version must be rejected")
	assert.Nil(t, appliedEqual)
	assert.Equal(t, fpCurrent, vv.Fingerprint(), "Fingerprint must be unchanged on rejection")

	// Attempt to add stale version 4
	appliedStale, okStale := vv.AddItem(VersionedItem[testEntity]{
		Item:    testEntity{ID: "node-1", Payload: "v4-stale"},
		Version: 4,
	})
	assert.False(t, okStale, "Stale version must be rejected")
	assert.Nil(t, appliedStale)
	assert.Equal(t, fpCurrent, vv.Fingerprint(), "Fingerprint must be unchanged on rejection")

	// Verify state was not modified
	retrieved, found := vv.GetOne(key1)
	assert.True(t, found)
	assert.Equal(t, uint64(5), vv.Versions()[key1])
	assert.Equal(t, "v5", retrieved.Item.Payload)
}

func TestVersionVectorMutable_RemovalAndClear(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	vItem1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v1"}, Version: 1}
	vItem2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-2", Payload: "v1"}, Version: 1}

	vv.AddItem(vItem1)
	vv.AddItem(vItem2)
	assert.Equal(t, 2, vv.Size())

	key1 := testMutableKeyFunc(vItem1.Item)

	// Removing node-1 should leave only node-2's digest
	removedItem, removed := vv.Remove(key1)
	assert.True(t, removed)
	assert.Equal(t, vItem1, removedItem)
	assert.Equal(t, 1, vv.Size())
	assert.False(t, vv.ContainsKey(key1))
	assert.Equal(t, testHasher(vItem2), vv.Fingerprint())

	// Removing non-existent key
	_, removedMissing := vv.Remove(key1)
	assert.False(t, removedMissing)

	// Clear resets everything
	vv.Clear()
	assert.Equal(t, 0, vv.Size())
	assert.True(t, vv.Empty())
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint())
}

func TestVersionVectorMutable_RemoveVersion(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	vItem := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v5"}, Version: 5}
	key := testMutableKeyFunc(vItem.Item)

	vv.AddItem(vItem)

	// Removing wrong version does not remove the item
	assert.False(t, vv.RemoveVersion(key, 4))
	assert.False(t, vv.RemoveVersion(key, 6))
	assert.Equal(t, 1, vv.Size())
	assert.True(t, vv.ContainsKey(key))

	// Removing correct version succeeds
	assert.True(t, vv.RemoveVersion(key, 5))
	assert.Equal(t, 0, vv.Size())
	assert.False(t, vv.ContainsKey(key))
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint())

	// Removing from empty vector
	assert.False(t, vv.RemoveVersion(key, 5))
}

func TestVersionVectorMutable_Commutativity(t *testing.T) {
	vv1 := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	vv2 := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)

	items := []VersionedItem[testEntity]{
		{Item: testEntity{ID: "node-A", Payload: "data-A"}, Version: 1},
		{Item: testEntity{ID: "node-B", Payload: "data-B"}, Version: 2},
		{Item: testEntity{ID: "node-C", Payload: "data-C"}, Version: 3},
	}

	// Insert in forward order in vv1
	for _, item := range items {
		vv1.AddItem(item)
	}

	// Insert in reverse order in vv2
	for i := len(items) - 1; i >= 0; i-- {
		vv2.AddItem(items[i])
	}

	assert.Equal(t, vv1.Fingerprint(), vv2.Fingerprint(),
		"Commutative XOR fingerprints must be identical regardless of insertion order")
	assert.ElementsMatch(t, vv1.DigestsCopy(), vv2.DigestsCopy())
}

func TestVersionVectorMutable_ElementsAndVersions(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	v1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "p1"}, Version: 10}
	v2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-2", Payload: "p2"}, Version: 20}

	vv.AddItem(v1)
	vv.AddItem(v2)

	elements := vv.Elements()
	require.Len(t, elements, 2)
	assert.ElementsMatch(t, []VersionedItem[testEntity]{v1, v2}, elements)

	versions := vv.Versions()
	require.Len(t, versions, 2)
	assert.Equal(t, uint64(10), versions[testMutableKeyFunc(v1.Item)])
	assert.Equal(t, uint64(20), versions[testMutableKeyFunc(v2.Item)])
}

func TestVersionVectorMutable_ConcurrentAccessAndRaceDetector(t *testing.T) {
	vv := NewVersionVectorMutable[testEntity, DigestSymbol](testMutableKeyFunc, testHasher)
	var wg sync.WaitGroup

	numGoroutines := 20
	opsPerGoroutine := 50

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			nodeID := fmt.Sprintf("node-%d", gid%5)
			itemEntity := testEntity{ID: nodeID}
			key := testMutableKeyFunc(itemEntity)

			for i := 1; i <= opsPerGoroutine; i++ {
				// Concurrent additions / upgrades
				vv.AddItem(VersionedItem[testEntity]{
					Item: testEntity{
						ID:      nodeID,
						Payload: fmt.Sprintf("goroutine-%d-op-%d", gid, i),
					},
					Version: uint64(i),
				})

				// Concurrent reads
				vv.GetOne(key)
				vv.GetMany([]DigestSymbol{key})
				vv.ContainsKey(key)
				vv.ContainsKeyVersion(key, uint64(i))
				vv.Fingerprint()
				vv.Size()
				vv.Empty()
				vv.Versions()
				vv.Elements()
				vv.DigestsCopy()
			}
		}(g)
	}

	wg.Wait()
	assert.Equal(t, 5, vv.Size(), "Should have exactly 5 unique nodes")
	assert.NotEqual(t, DigestSymbol(0), vv.Fingerprint())
}
