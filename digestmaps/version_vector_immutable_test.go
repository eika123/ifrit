package digestmaps

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

func testKeyFunc(item testEntity) string {
	return item.ID
}

func TestVersionVectorImmutable_BasicOperations(t *testing.T) {
	vv := NewVersionVectorImmutable(testKeyFunc, testHasher)
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

	// AddItem returns a new VersionVectorImmutable; original must remain unmodified.
	vv2, ok := vv.AddItem(v1)
	require.True(t, ok)

	// Verify immutability of original vector
	assert.True(t, vv.Empty(), "Original vector must remain empty")
	assert.Equal(t, 0, vv.Size(), "Original vector size must remain 0")
	assert.Equal(t, DigestSymbol(0), vv.Fingerprint(), "Original fingerprint must remain zero")
	assert.False(t, vv.ContainsKey("node-1"))

	// Verify newly derived vector
	assert.False(t, vv2.Empty())
	assert.Equal(t, 1, vv2.Size())
	assert.True(t, vv2.ContainsKey("node-1"))
	assert.True(t, vv2.ContainsKeyVersion("node-1", 1))
	assert.False(t, vv2.ContainsKeyVersion("node-1", 2))

	retrieved, found := vv2.GetOne("node-1")
	assert.True(t, found)
	assert.Equal(t, v1, retrieved)
	assert.Equal(t, "initial", retrieved.Item.Payload)
	assert.Equal(t, uint64(1), retrieved.Version)

	// Fingerprint should equal the single item's digest
	assert.Equal(t, d1, vv2.Fingerprint())
	assert.ElementsMatch(t, []DigestSymbol{d1}, vv2.DigestsCopy())

	// Missing key retrieval
	_, foundMissing := vv2.GetOne("missing-node")
	assert.False(t, foundMissing)
	assert.False(t, vv2.ContainsKey("missing-node"))

	// GetMany batch retrieval
	items := vv2.GetMany([]string{"node-1", "missing-node"})
	assert.Equal(t, []VersionedItem[testEntity]{v1}, items)
}

func TestVersionVectorImmutable_ImmutabilityAndBranching(t *testing.T) {
	root := NewVersionVectorImmutable(testKeyFunc, testHasher)

	itemA := VersionedItem[testEntity]{Item: testEntity{ID: "node-A", Payload: "A"}, Version: 1}
	itemB := VersionedItem[testEntity]{Item: testEntity{ID: "node-B", Payload: "B"}, Version: 1}
	itemC := VersionedItem[testEntity]{Item: testEntity{ID: "node-C", Payload: "C"}, Version: 1}

	digA := testHasher(itemA)
	digB := testHasher(itemB)
	digC := testHasher(itemC)

	// Branch 1: root -> branchA (has A)
	branchA, okA := root.AddItem(itemA)
	require.True(t, okA)

	// Sub-branch 1a: branchA -> branchAB (has A, B)
	branchAB, okB := branchA.AddItem(itemB)
	require.True(t, okB)

	// Sub-branch 1b: branchA -> branchAC (has A, C)
	branchAC, okC := branchA.AddItem(itemC)
	require.True(t, okC)

	// Verify root remains empty
	assert.Equal(t, 0, root.Size())
	assert.True(t, root.Empty())

	// Verify branchA has only A
	assert.Equal(t, 1, branchA.Size())
	assert.True(t, branchA.ContainsKey("node-A"))
	assert.False(t, branchA.ContainsKey("node-B"))
	assert.False(t, branchA.ContainsKey("node-C"))
	assert.Equal(t, digA, branchA.Fingerprint())

	// Verify branchAB has A and B, but not C
	assert.Equal(t, 2, branchAB.Size())
	assert.True(t, branchAB.ContainsKey("node-A"))
	assert.True(t, branchAB.ContainsKey("node-B"))
	assert.False(t, branchAB.ContainsKey("node-C"))
	assert.Equal(t, digA.XOR(digB), branchAB.Fingerprint())

	// Verify branchAC has A and C, but not B
	assert.Equal(t, 2, branchAC.Size())
	assert.True(t, branchAC.ContainsKey("node-A"))
	assert.False(t, branchAC.ContainsKey("node-B"))
	assert.True(t, branchAC.ContainsKey("node-C"))
	assert.Equal(t, digA.XOR(digC), branchAC.Fingerprint())
}

func TestVersionVectorImmutable_AddIdempotencyAndStaleRejection(t *testing.T) {
	vv := NewVersionVectorImmutable(testKeyFunc, testHasher)
	itemV2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v2"}, Version: 2}

	vv1, ok := vv.AddItem(itemV2)
	require.True(t, ok)

	// 1. Equal version must be rejected
	vvSame, okSame := vv1.AddItem(itemV2)
	assert.False(t, okSame)
	assert.Equal(t, vv1, vvSame)
}

func TestVersionVectorImmutable_DifferentVersionsProduceDistinctFingerprints(t *testing.T) {
	// Vector A with node-1 at version 1
	itemV1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "state"}, Version: 1}
	vvA0 := NewVersionVectorImmutable(testKeyFunc, testHasher)
	vvA, okA := vvA0.AddItem(itemV1)
	require.True(t, okA)

	// Vector B with node-1 at version 2 (rebuttal / update)
	itemV2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "state"}, Version: 2}
	vvB0 := NewVersionVectorImmutable(testKeyFunc, testHasher)
	vvB, okB := vvB0.AddItem(itemV2)
	require.True(t, okB)

	assert.NotEqual(t, vvA.Fingerprint(), vvB.Fingerprint(),
		"Vectors with identical item payloads but different versions MUST have different fingerprints")
}

func TestVersionVectorImmutable_VersionUpgradePattern(t *testing.T) {
	vv := NewVersionVectorImmutable(testKeyFunc, testHasher)
	e1v1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v1"}, Version: 1}
	digV1 := testHasher(e1v1)

	vv1, ok1 := vv.AddItem(e1v1)
	require.True(t, ok1)
	fp1 := vv1.Fingerprint()
	assert.Equal(t, digV1, fp1)

	// Upgrading node-1 to version 2: automatically replaces e1v1 and updates fingerprint
	e1v2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v2"}, Version: 2}
	digV2 := testHasher(e1v2)

	vv2, ok2 := vv1.AddItem(e1v2)
	require.True(t, ok2)
	assert.Equal(t, 1, vv2.Size(), "Size must remain 1 after replacing old version")
	assert.True(t, vv2.ContainsKey("node-1"))
	assert.True(t, vv2.ContainsKeyVersion("node-1", 2))
	assert.False(t, vv2.ContainsKeyVersion("node-1", 1))

	// Mathematical check: fp2 == fp1 XOR digV1 XOR digV2 == digV2
	expectedFP2 := fp1.XOR(digV1).XOR(digV2)
	assert.Equal(t, expectedFP2, vv2.Fingerprint())
	assert.Equal(t, digV2, vv2.Fingerprint())

	// Prior vv1 remains untouched with version 1
	e1, found1 := vv1.GetOne("node-1")
	assert.True(t, found1)
	assert.Equal(t, uint64(1), e1.Version)
	assert.Equal(t, digV1, vv1.Fingerprint())

	// Derived vv2 has version 2
	e2, found2 := vv2.GetOne("node-1")
	assert.True(t, found2)
	assert.Equal(t, uint64(2), e2.Version)
}

func TestVersionVectorImmutable_Removal(t *testing.T) {
	vv0 := NewVersionVectorImmutable(testKeyFunc, testHasher)
	e1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "v1"}, Version: 1}
	e2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-2", Payload: "v1"}, Version: 1}

	dig2 := testHasher(e2)

	vv, _ := vv0.AddItem(e1)
	vv, _ = vv.AddItem(e2)
	assert.Equal(t, 2, vv.Size())

	// Removing node-1 should leave only node-2
	vvAfterRemove1, removed := vv.Remove("node-1")
	assert.True(t, removed)
	assert.Equal(t, 1, vvAfterRemove1.Size())
	assert.False(t, vvAfterRemove1.ContainsKey("node-1"))
	assert.True(t, vvAfterRemove1.ContainsKey("node-2"))
	assert.Equal(t, dig2, vvAfterRemove1.Fingerprint())

	// Prior vector vv must remain untouched
	assert.Equal(t, 2, vv.Size())
	assert.True(t, vv.ContainsKey("node-1"))
	assert.True(t, vv.ContainsKey("node-2"))

	// Removing non-existent key returns unchanged vector and false
	vvMissing, removedMissing := vvAfterRemove1.Remove("missing-node")
	assert.False(t, removedMissing)
	assert.Equal(t, vvAfterRemove1, vvMissing)

	// RemoveVersion check: mismatching version returns unchanged and false
	vvWrongVer, remWrong := vvAfterRemove1.RemoveVersion("node-2", 999)
	assert.False(t, remWrong)
	assert.Equal(t, vvAfterRemove1, vvWrongVer)

	// RemoveVersion matching version succeeds
	vvEmpty, remVer := vvAfterRemove1.RemoveVersion("node-2", 1)
	assert.True(t, remVer)
	assert.Equal(t, 0, vvEmpty.Size())
	assert.True(t, vvEmpty.Empty())
	assert.Equal(t, DigestSymbol(0), vvEmpty.Fingerprint())
}

func TestVersionVectorImmutable_Commutativity(t *testing.T) {
	items := []VersionedItem[testEntity]{
		{Item: testEntity{ID: "node-A", Payload: "data-A"}, Version: 1},
		{Item: testEntity{ID: "node-B", Payload: "data-B"}, Version: 2},
		{Item: testEntity{ID: "node-C", Payload: "data-C"}, Version: 3},
	}

	// Insert in forward order
	vvForward := NewVersionVectorImmutable(testKeyFunc, testHasher)
	for _, item := range items {
		vvForward, _ = vvForward.AddItem(item)
	}

	// Insert in reverse order
	vvReverse := NewVersionVectorImmutable(testKeyFunc, testHasher)
	for i := len(items) - 1; i >= 0; i-- {
		vvReverse, _ = vvReverse.AddItem(items[i])
	}

	assert.Equal(t, vvForward.Fingerprint(), vvReverse.Fingerprint(),
		"Commutative XOR fingerprints must be identical regardless of insertion order")
	assert.ElementsMatch(t, vvForward.DigestsCopy(), vvReverse.DigestsCopy())
	assert.ElementsMatch(t, vvForward.Elements(), vvReverse.Elements())
	assert.Equal(t, vvForward.Versions(), vvReverse.Versions())
}

func TestVersionVectorImmutable_ElementsAndVersions(t *testing.T) {
	vv := NewVersionVectorImmutable(testKeyFunc, testHasher)
	item1 := VersionedItem[testEntity]{Item: testEntity{ID: "node-1", Payload: "p1"}, Version: 10}
	item2 := VersionedItem[testEntity]{Item: testEntity{ID: "node-2", Payload: "p2"}, Version: 20}

	vv, _ = vv.AddItem(item1)
	vv, _ = vv.AddItem(item2)

	elements := vv.Elements()
	require.Len(t, elements, 2)
	assert.ElementsMatch(t, []VersionedItem[testEntity]{item1, item2}, elements)

	versions := vv.Versions()
	assert.Equal(t, map[string]uint64{
		"node-1": 10,
		"node-2": 20,
	}, versions)
}

func TestVersionVectorImmutable_ConcurrentAccessAndRaceDetector(t *testing.T) {
	baseVV := NewVersionVectorImmutable(testKeyFunc, testHasher)

	numBaseItems := 10
	for i := 0; i < numBaseItems; i++ {
		item := VersionedItem[testEntity]{
			Item:    testEntity{ID: fmt.Sprintf("base-node-%d", i), Payload: "init"},
			Version: uint64(i + 1),
		}
		baseVV, _ = baseVV.AddItem(item)
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
					Version: uint64(i + 100), // higher version
				}

				// Concurrent derivation via AddItem
				derived, ok := localVV.AddItem(newItem)
				assert.True(t, ok)
				assert.True(t, derived.ContainsKey(newItem.Item.ID))

				// Concurrent reads on shared baseVV
				baseVV.GetOne(fmt.Sprintf("base-node-%d", gid%numBaseItems))
				baseVV.GetMany([]string{"base-node-0", "base-node-1"})
				baseVV.ContainsKey("base-node-0")
				baseVV.ContainsKeyVersion("base-node-0", 1)
				baseVV.Fingerprint()
				baseVV.Size()
				baseVV.Empty()
				baseVV.Elements()
				baseVV.Versions()
				baseVV.DigestsCopy()

				// Concurrent removal on derived vector
				removedVV, removed := derived.Remove(newItem.Item.ID)
				assert.True(t, removed)
				assert.Equal(t, localVV.Fingerprint(), removedVV.Fingerprint())
			}
		}(g)
	}

	wg.Wait()
	assert.Equal(t, numBaseItems, baseVV.Size(), "Shared baseVV size must remain unchanged")
}

func TestVersionVectorImmutable_SliceIsolationAndConcurrentMutation(t *testing.T) {
	baseVV := NewVersionVectorImmutable(testKeyFunc, testHasher)

	numItems := 50
	for i := 0; i < numItems; i++ {
		item := VersionedItem[testEntity]{
			Item:    testEntity{ID: fmt.Sprintf("node-%d", i), Payload: fmt.Sprintf("payload-%d", i)},
			Version: uint64(i + 1),
		}
		baseVV, _ = baseVV.AddItem(item)
	}

	// Extract slices concurrently with removal and in-place slice mutation
	var wg sync.WaitGroup
	iterations := 200

	wg.Add(2)

	// Goroutine 1: extracts Elements() and DigestsCopy() slices and aggressively mutates them in place
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			elems := baseVV.Elements()
			for j := range elems {
				elems[j].Version = 999999
				elems[j].Item.Payload = "mutated-in-place"
			}

			digests := baseVV.DigestsCopy()
			for j := range digests {
				digests[j] = DigestSymbol(0xDEADBEEF)
			}
		}
	}()

	// Goroutine 2: repeatedly derives new vectors via Remove, AddItem, and reads on baseVV
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			removeKey := fmt.Sprintf("node-%d", i%numItems)
			derivedVV, removed := baseVV.Remove(removeKey)
			assert.True(t, removed)
			assert.Equal(t, numItems-1, derivedVV.Size())
			assert.False(t, derivedVV.ContainsKey(removeKey))

			// Verify baseVV integrity was not contaminated by in-place slice mutation
			entry, found := baseVV.GetOne(removeKey)
			assert.True(t, found)
			assert.NotEqual(t, uint64(999999), entry.Version)
			assert.NotEqual(t, "mutated-in-place", entry.Item.Payload)
		}
	}()

	wg.Wait()

	// Final verification of baseVV immutability
	assert.Equal(t, numItems, baseVV.Size())
	for i := 0; i < numItems; i++ {
		entry, found := baseVV.GetOne(fmt.Sprintf("node-%d", i))
		assert.True(t, found)
		assert.Equal(t, uint64(i+1), entry.Version)
		assert.Equal(t, fmt.Sprintf("payload-%d", i), entry.Item.Payload)
	}
}
