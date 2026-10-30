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

func testHasher(item VersionedItem[testEntity]) DigestSymbol {
	h := fnv.New64a()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], item.Version)
	h.Write(buf[:])
	h.Write([]byte(item.Item.ID))
	h.Write([]byte(item.Item.Payload))
	return DigestSymbol(h.Sum64())
}

func TestVersionVector_BasicOperations(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testHasher)
	assert.True(t, vv.Empty())
	assert.Equal(t, 0, vv.Size())
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint())
	assert.Empty(t, vv.Elements())
	assert.Empty(t, vv.DigestsCopy())

	v1 := VersionedItem[testEntity]{
		Item:    testEntity{ID: "node-1", Payload: "initial"},
		Version: 1,
	}
	d1 := testHasher(v1)

	// AddItem returns a new VersionVector; original must remain unmodified.
	vv2 := vv.AddItem(v1)

	// Verify immutability of original vector
	assert.True(t, vv.Empty(), "Original vector must remain empty")
	assert.Equal(t, 0, vv.Size(), "Original vector size must remain 0")
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint(), "Original fingerprint must remain zero")
	assert.False(t, vv.ContainsDigest(d1))

	// Verify newly derived vector
	assert.False(t, vv2.Empty())
	assert.Equal(t, 1, vv2.Size())
	assert.True(t, vv2.ContainsDigest(d1))

	retrieved, found := vv2.GetByDigest(d1)
	assert.True(t, found)
	assert.Equal(t, v1, retrieved)
	assert.Equal(t, "initial", retrieved.Item.Payload)
	assert.Equal(t, uint64(1), retrieved.Version)

	// Fingerprint should equal the single item's digest
	assert.Equal(t, d1, vv2.Fingerprint())
	assert.ElementsMatch(t, []DigestSymbol{d1}, vv2.DigestsCopy())

	// Missing digest retrieval
	missingDigest := DigestSymbol(999999)
	_, foundMissing := vv2.GetByDigest(missingDigest)
	assert.False(t, foundMissing)
	assert.False(t, vv2.ContainsDigest(missingDigest))

	// GetByDigests batch retrieval
	byDigs, allFound := vv2.GetByDigests([]DigestSymbol{d1})
	assert.True(t, allFound)
	assert.Equal(t, []VersionedItem[testEntity]{v1}, byDigs)

	// Partial / missing batch retrieval
	byDigs, allFound = vv2.GetByDigests([]DigestSymbol{d1, missingDigest})
	assert.False(t, allFound)
	assert.Equal(t, []VersionedItem[testEntity]{v1}, byDigs)
}

func TestVersionVector_ImmutabilityAndBranching(t *testing.T) {
	root := NewVersionVector[testEntity, DigestSymbol](testHasher)

	itemA := VersionedItem[testEntity]{Item: testEntity{ID: "node-A", Payload: "A"}, Version: 1}
	itemB := VersionedItem[testEntity]{Item: testEntity{ID: "node-B", Payload: "B"}, Version: 1}
	itemC := VersionedItem[testEntity]{Item: testEntity{ID: "node-C", Payload: "C"}, Version: 1}

	digA := testHasher(itemA)
	digB := testHasher(itemB)
	digC := testHasher(itemC)

	// Branch 1: root -> branchA (has A)
	branchA := root.AddItem(itemA)

	// Sub-branch 1a: branchA -> branchAB (has A, B)
	branchAB := branchA.AddItem(itemB)

	// Sub-branch 1b: branchA -> branchAC (has A, C)
	branchAC := branchA.AddItem(itemC)

	// Verify root remains empty
	assert.Equal(t, 0, root.Size())
	assert.True(t, root.Empty())

	// Verify branchA has only A
	assert.Equal(t, 1, branchA.Size())
	assert.True(t, branchA.ContainsDigest(digA))
	assert.False(t, branchA.ContainsDigest(digB))
	assert.False(t, branchA.ContainsDigest(digC))
	assert.Equal(t, digA, branchA.Fingerprint())

	// Verify branchAB has A and B, but not C
	assert.Equal(t, 2, branchAB.Size())
	assert.True(t, branchAB.ContainsDigest(digA))
	assert.True(t, branchAB.ContainsDigest(digB))
	assert.False(t, branchAB.ContainsDigest(digC))
	assert.Equal(t, digA.XOR(digB), branchAB.Fingerprint())

	// Verify branchAC has A and C, but not B
	assert.Equal(t, 2, branchAC.Size())
	assert.True(t, branchAC.ContainsDigest(digA))
	assert.False(t, branchAC.ContainsDigest(digB))
	assert.True(t, branchAC.ContainsDigest(digC))
	assert.Equal(t, digA.XOR(digC), branchAC.Fingerprint())
}

func TestVersionVector_AddIdempotency(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testHasher)
	item := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v1"}, Version: 1}

	vv1 := vv.AddItem(item)
	vv2 := vv1.AddItem(item)

	assert.Equal(t, 1, vv2.Size(), "Adding duplicate item must not increase size")
	assert.Equal(t, vv1.Fingerprint(), vv2.Fingerprint(), "Adding duplicate item must not alter fingerprint")
	assert.ElementsMatch(t, vv1.DigestsCopy(), vv2.DigestsCopy())
}

func TestVersionVector_DifferentVersionsProduceDistinctFingerprints(t *testing.T) {
	// Vector A with node-1 at version 1
	itemV1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "state"}, Version: 1}
	vvA := NewVersionVector[testEntity, DigestSymbol](testHasher).AddItem(itemV1)

	// Vector B with node-1 at version 2 (rebuttal / update)
	itemV2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "state"}, Version: 2}
	vvB := NewVersionVector[testEntity, DigestSymbol](testHasher).AddItem(itemV2)

	assert.NotEqual(t, vvA.Fingerprint(), vvB.Fingerprint(),
		"Vectors with identical item payloads but different versions MUST have different fingerprints")
}

func TestVersionVector_VersionUpgradePattern(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testHasher)
	e1v1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v1"}, Version: 1}
	digV1 := testHasher(e1v1)

	vv1 := vv.AddItem(e1v1)
	fp1 := vv1.Fingerprint()
	assert.Equal(t, digV1, fp1)

	// Upgrading node-1 to version 2: add new version and evict previous version digest
	e1v2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v2"}, Version: 2}
	digV2 := testHasher(e1v2)

	vv2, removed := vv1.AddItem(e1v2).Remove(digV1)
	assert.True(t, removed, "Removing old version digest should succeed")
	assert.Equal(t, 1, vv2.Size(), "Size must remain 1 after replacing old version")
	assert.False(t, vv2.ContainsDigest(digV1))
	assert.True(t, vv2.ContainsDigest(digV2))

	// Mathematical verification: fp2 == fp1 XOR digV1 XOR digV2 == digV2
	expectedFP2 := fp1.XOR(digV1).XOR(digV2)
	assert.Equal(t, expectedFP2, vv2.Fingerprint())
	assert.Equal(t, digV2, vv2.Fingerprint())

	// Original vv1 must remain untouched
	assert.Equal(t, 1, vv1.Size())
	assert.True(t, vv1.ContainsDigest(digV1))
	assert.False(t, vv1.ContainsDigest(digV2))
}

func TestVersionVector_Removal(t *testing.T) {
	vv0 := NewVersionVector[testEntity, DigestSymbol](testHasher)
	e1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v1"}, Version: 1}
	e2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-2", Payload: "v1"}, Version: 1}

	dig1 := testHasher(e1)
	dig2 := testHasher(e2)

	vv := vv0.AddItem(e1).AddItem(e2)
	assert.Equal(t, 2, vv.Size())

	// Removing node-1 should leave only node-2
	vvAfterRemove1, removed := vv.Remove(dig1)
	assert.True(t, removed)
	assert.Equal(t, 1, vvAfterRemove1.Size())
	assert.False(t, vvAfterRemove1.ContainsDigest(dig1))
	assert.True(t, vvAfterRemove1.ContainsDigest(dig2))
	assert.Equal(t, dig2, vvAfterRemove1.Fingerprint())

	// Prior vector vv must remain untouched
	assert.Equal(t, 2, vv.Size())
	assert.True(t, vv.ContainsDigest(dig1))
	assert.True(t, vv.ContainsDigest(dig2))

	// Removing non-existent digest returns nil and false
	vvMissing, removedMissing := vvAfterRemove1.Remove(DigestSymbol(999999))
	assert.False(t, removedMissing)
	assert.Nil(t, vvMissing)

	// Removing the remaining element results in an empty vector with fingerprint 0
	vvEmpty, removed2 := vvAfterRemove1.Remove(dig2)
	assert.True(t, removed2)
	assert.Equal(t, 0, vvEmpty.Size())
	assert.True(t, vvEmpty.Empty())
	assert.Equal(t, DigestSymbol(0), vvEmpty.Fingerprint())
}

func TestVersionVector_Commutativity(t *testing.T) {
	items := []VersionedItem[testEntity]{
		{Item: testEntity{ID: "node-A", Payload: "data-A"}, Version: 1},
		{Item: testEntity{ID: "node-B", Payload: "data-B"}, Version: 2},
		{Item: testEntity{ID: "node-C", Payload: "data-C"}, Version: 3},
	}

	// Insert in forward order
	vvForward := NewVersionVector[testEntity, DigestSymbol](testHasher)
	for _, item := range items {
		vvForward = vvForward.AddItem(item)
	}

	// Insert in reverse order
	vvReverse := NewVersionVector[testEntity, DigestSymbol](testHasher)
	for i := len(items) - 1; i >= 0; i-- {
		vvReverse = vvReverse.AddItem(items[i])
	}

	assert.Equal(t, vvForward.Fingerprint(), vvReverse.Fingerprint(),
		"Commutative XOR fingerprints must be identical regardless of insertion order")
	assert.ElementsMatch(t, vvForward.DigestsCopy(), vvReverse.DigestsCopy())
	assert.ElementsMatch(t, vvForward.Elements(), vvReverse.Elements())
}

func TestVersionVector_Elements(t *testing.T) {
	vv := NewVersionVector[testEntity, DigestSymbol](testHasher)
	item1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "p1"}, Version: 10}
	item2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-2", Payload: "p2"}, Version: 20}

	vv = vv.AddItem(item1).AddItem(item2)

	elements := vv.Elements()
	require.Len(t, elements, 2)
	assert.ElementsMatch(t, []VersionedItem[testEntity]{item1, item2}, elements)
}

func TestVersionVector_ConcurrentAccessAndRaceDetector(t *testing.T) {
	baseVV := NewVersionVector[testEntity, DigestSymbol](testHasher)

	// Pre-populate with base items
	numBaseItems := 10
	baseDigests := make([]DigestSymbol, numBaseItems)
	for i := 0; i < numBaseItems; i++ {
		item := VersionedItem[testEntity]{
			Item:    testEntity{ID: fmt.Sprintf("base-node-%d", i), Payload: "init"},
			Version: uint64(i + 1),
		}
		baseDigests[i] = testHasher(item)
		baseVV = baseVV.AddItem(item)
	}

	var wg sync.WaitGroup
	numGoroutines := 20
	opsPerGoroutine := 50

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			localVV := baseVV

			for i := 1; i <= opsPerGoroutine; i++ {
				newItem := VersionedItem[testEntity]{
					Item:    testEntity{ID: fmt.Sprintf("node-%d", gid%5), Payload: fmt.Sprintf("goroutine-%d-op-%d", gid, i)},
					Version: uint64(i),
				}
				newDig := testHasher(newItem)

				// Concurrent derivation via AddItem
				derived := localVV.AddItem(newItem)
				assert.True(t, derived.ContainsDigest(newDig))
				assert.Equal(t, localVV.Size()+1, derived.Size())

				// Concurrent reads on shared baseVV
				baseVV.GetByDigest(baseDigests[gid%numBaseItems])
				baseVV.GetByDigests(baseDigests[:3])
				baseVV.ContainsDigest(baseDigests[gid%numBaseItems])
				baseVV.Fingerprint()
				baseVV.Size()
				baseVV.Empty()
				baseVV.Elements()
				baseVV.DigestsCopy()

				// Concurrent removal on derived vector
				removedVV, ok := derived.Remove(newDig)
				assert.True(t, ok)
				assert.Equal(t, localVV.Fingerprint(), removedVV.Fingerprint())
			}
		}(g)
	}

	wg.Wait()
	assert.Equal(t, numBaseItems, baseVV.Size(), "Shared baseVV size must remain unchanged")
}
