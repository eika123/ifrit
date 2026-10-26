package versionvector

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEntity struct {
	ID      string
	Payload string
}

func testKeyFunc(item testEntity) DigestSymbol {
	h := fnv.New64a()
	h.Write([]byte(item.ID))
	return DigestSymbol(h.Sum64())
}

func testHasher(key DigestSymbol, item testEntity, version uint64) DigestSymbol {
	h := fnv.New64a()
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(key))
	binary.BigEndian.PutUint64(buf[8:16], version)
	h.Write(buf[:])
	h.Write([]byte(item.Payload))
	return DigestSymbol(h.Sum64())
}

func TestVersionVector_BasicOperations(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	assert.True(t, vv.Empty())
	assert.Equal(t, 0, vv.Size())
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint())

	e1 := testEntity{ID: "node-1", Payload: "initial"}
	added := vv.AddItem(e1, 1)
	assert.True(t, added)
	assert.False(t, vv.Empty())
	assert.Equal(t, 1, vv.Size())

	key1 := testKeyFunc(e1)
	assert.True(t, vv.ContainsKey(key1))

	retrieved, ver, found := vv.Get(key1)
	assert.True(t, found)
	assert.Equal(t, uint64(1), ver)
	assert.Equal(t, "initial", retrieved.Payload)

	// Fingerprint should equal the single digest
	expectedDigest := testHasher(key1, e1, 1)
	assert.Equal(t, expectedDigest, vv.Fingerprint())
}

func TestVersionVector_MonotonicAdvancement(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	e1 := testEntity{ID: "node-1", Payload: "v1"}
	key1 := testKeyFunc(e1)

	vv.AddItem(e1, 1)
	fp1 := vv.Fingerprint()

	// Advancing to version 2
	e1v2 := testEntity{ID: "node-1", Payload: "v2"}
	advanced := vv.AddItem(e1v2, 2)
	assert.True(t, advanced)
	assert.Equal(t, 1, vv.Size(), "Size must remain 1 for the same key")

	fp2 := vv.Fingerprint()
	assert.NotEqual(t, fp1, fp2, "Fingerprint must change when version advances")

	retrieved, ver, found := vv.Get(key1)
	assert.True(t, found)
	assert.Equal(t, uint64(2), ver)
	assert.Equal(t, "v2", retrieved.Payload)

	// Mathematical verification: fp2 == fp1 XOR digest(v1) XOR digest(v2)
	expectedFP2 := fp1.XOR(testHasher(key1, e1, 1)).XOR(testHasher(key1, e1v2, 2))
	assert.Equal(t, expectedFP2, fp2)
}

func TestVersionVector_DifferentVersionsProduceDistinctFingerprints(t *testing.T) {
	// Vector A with node-1 at version 1
	vvA := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	vvA.AddItem(testEntity{ID: "node-1", Payload: "state"}, 1)

	// Vector B with node-1 at version 2 (rebuttal)
	vvB := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	vvB.AddItem(testEntity{ID: "node-1", Payload: "state"}, 2)

	assert.NotEqual(t, vvA.Fingerprint(), vvB.Fingerprint(),
		"Vectors with identical keys but different versions MUST have different fingerprints")
}

func TestVersionVector_RejectsStaleAndEqualVersions(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	e1 := testEntity{ID: "node-1", Payload: "v5"}
	key1 := testKeyFunc(e1)

	vv.AddItem(e1, 5)
	fpCurrent := vv.Fingerprint()

	// Attempt to add equal version 5
	appliedEqual := vv.AddItem(testEntity{ID: "node-1", Payload: "v5-duplicate"}, 5)
	assert.False(t, appliedEqual, "Equal version must be rejected")
	assert.Equal(t, fpCurrent, vv.Fingerprint(), "Fingerprint must be unchanged on rejection")

	// Attempt to add stale version 4
	appliedStale := vv.AddItem(testEntity{ID: "node-1", Payload: "v4-stale"}, 4)
	assert.False(t, appliedStale, "Stale version must be rejected")
	assert.Equal(t, fpCurrent, vv.Fingerprint(), "Fingerprint must be unchanged on rejection")

	// Verify state was not modified
	retrieved, ver, _ := vv.Get(key1)
	assert.Equal(t, uint64(5), ver)
	assert.Equal(t, "v5", retrieved.Payload)
}

func TestVersionVector_RemovalAndClear(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	e1 := testEntity{ID: "node-1", Payload: "v1"}
	e2 := testEntity{ID: "node-2", Payload: "v1"}

	vv.AddItem(e1, 1)
	vv.AddItem(e2, 1)
	assert.Equal(t, 2, vv.Size())

	key1 := testKeyFunc(e1)
	key2 := testKeyFunc(e2)

	// Removing node-1 should leave only node-2's digest
	removed := vv.Remove(key1)
	assert.True(t, removed)
	assert.Equal(t, 1, vv.Size())
	assert.False(t, vv.ContainsKey(key1))
	assert.Equal(t, testHasher(key2, e2, 1), vv.Fingerprint())

	// Removing non-existent key
	assert.False(t, vv.Remove(key1))

	// Clear resets everything
	vv.Clear()
	assert.Equal(t, 0, vv.Size())
	assert.True(t, vv.Empty())
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint())
}

func TestVersionVector_Commutativity(t *testing.T) {
	vv1 := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	vv2 := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)

	items := []testEntity{
		{ID: "node-A", Payload: "data-A"},
		{ID: "node-B", Payload: "data-B"},
		{ID: "node-C", Payload: "data-C"},
	}

	// Insert in forward order in vv1
	for i, item := range items {
		vv1.AddItem(item, uint64(i+1))
	}

	// Insert in reverse order in vv2
	for i := len(items) - 1; i >= 0; i-- {
		vv2.AddItem(items[i], uint64(i+1))
	}

	assert.Equal(t, vv1.Fingerprint(), vv2.Fingerprint(),
		"Commutative XOR fingerprints must be identical regardless of insertion order")
}

func TestVersionVector_ElementsAndVersions(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	vv.AddItem(testEntity{ID: "node-1", Payload: "p1"}, 10)
	vv.AddItem(testEntity{ID: "node-2", Payload: "p2"}, 20)

	elements := vv.Elements()
	require.Len(t, elements, 2)

	versions := vv.Versions()
	require.Len(t, versions, 2)
	assert.Equal(t, uint64(10), versions[testKeyFunc(testEntity{ID: "node-1"})])
	assert.Equal(t, uint64(20), versions[testKeyFunc(testEntity{ID: "node-2"})])
}

func TestVersionVector_ConcurrentAccessAndRaceDetector(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testKeyFunc, testHasher)
	var wg sync.WaitGroup

	numGoroutines := 20
	opsPerGoroutine := 50

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			nodeID := fmt.Sprintf("node-%d", gid%5)
			key := testKeyFunc(testEntity{ID: nodeID})

			for i := 1; i <= opsPerGoroutine; i++ {
				// Concurrent additions / upgrades
				vv.AddItem(testEntity{
					ID:      nodeID,
					Payload: fmt.Sprintf("goroutine-%d-op-%d", gid, i),
				}, uint64(i))

				// Concurrent reads
				vv.Get(key)
				vv.ContainsKey(key)
				vv.Fingerprint()
				vv.Size()
				vv.Empty()
				vv.Versions()
			}
		}(g)
	}

	wg.Wait()
	assert.Equal(t, 5, vv.Size(), "Should have exactly 5 unique nodes")
	assert.NotEqual(t, DigestSymbol(0), vv.Fingerprint())
}
