package core

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type userItem struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (u userItem) IDGetter() string {
	return u.ID
}

func TestDigestSet_BasicOperationsAndGetByDigest(t *testing.T) {
	var hasher = DefaultHasher[userItem]()
	s := newDigestSet[userItem](hasher)

	assert.True(t, s.Empty())
	assert.Equal(t, 0, s.Size())
	assert.Equal(t, DigestSymbol(0), s.Fingerprint())

	u1 := userItem{ID: "alice", FirstName: "Alice", LastName: "Smith"}
	d1, added := s.Insert(u1)
	assert.True(t, added)
	assert.NotZero(t, d1)
	assert.Equal(t, 1, s.Size())
	assert.False(t, s.Empty())
	assert.True(t, s.Contains(u1))
	assert.True(t, s.ContainsDigest(d1))
	assert.Equal(t, d1, s.Fingerprint())

	// Test GetByDigest: retrieve element by digest
	retrieved, found := s.GetByDigest(d1)
	assert.True(t, found)
	assert.Equal(t, u1, retrieved)

	// Duplicate insert
	d1Again, addedAgain := s.Insert(u1)
	assert.False(t, addedAgain)
	assert.Equal(t, d1, d1Again)
	assert.Equal(t, 1, s.Size())

	// Batch insert
	u2 := userItem{ID: "bob", FirstName: "Bob", LastName: "Jones"}
	u3 := userItem{ID: "charlie", FirstName: "Charlie", LastName: "Brown"}
	addedCount := s.AddElements(u1, u2, u3)
	assert.Equal(t, 2, addedCount)
	assert.Equal(t, 3, s.Size())

	digests := s.Digests()
	assert.Len(t, digests, 3)
}

func TestDigestSet_DeterministicFingerprintAndCrossMachineEquivalence(t *testing.T) {

	var hasher = DefaultHasher[userItem]()
	s1 := newDigestSet[userItem](hasher)
	s2 := newDigestSet[userItem](hasher)

	u1 := userItem{ID: "user-1", FirstName: "One"}
	u2 := userItem{ID: "user-2", FirstName: "Two"}
	u3 := userItem{ID: "user-3", FirstName: "Three"}

	// Insert in different orders
	s1.Insert(u1)
	s1.Insert(u2)
	s1.Insert(u3)

	s2.Insert(u3)
	s2.Insert(u1)
	s2.Insert(u2)

	// Commutative XOR fingerprint must be exactly identical
	assert.Equal(t, s1.Fingerprint(), s2.Fingerprint())
	assert.Equal(t, s1.Size(), s2.Size())

	// Divergence: adding an extra item must change the fingerprint
	u4 := userItem{ID: "user-4", FirstName: "Four"}
	s1.Insert(u4)
	assert.NotEqual(t, s1.Fingerprint(), s2.Fingerprint())
}

func TestDigestSet_CopyIsolation(t *testing.T) {
	var hasher = DefaultHasher[string]()
	s := newDigestSet[string](hasher)
	s.Insert("alpha")
	s.Insert("beta")

	cp := s.Copy()
	assert.Equal(t, s.Fingerprint(), cp.Fingerprint())
	assert.Equal(t, s.Size(), cp.Size())

	cp.AddElement("gamma")
	assert.Equal(t, 3, cp.Size())
	assert.Equal(t, 2, s.Size())
	assert.False(t, s.Contains("gamma"))
	assert.NotEqual(t, s.Fingerprint(), cp.Fingerprint())
}

func TestDigestSet_DeltaMergingAndSymmetricDifference(t *testing.T) {
	var hasher = DefaultHasher[string]()
	s1 := newDigestSet[string](hasher)
	s1.Insert("alpha")
	s1.Insert("beta")

	s2 := newDigestSet[string](hasher)
	s2.Insert("beta")
	s2.Insert("gamma")

	// Symmetric difference XOR property:
	// A = {alpha, beta}, B = {beta, gamma}
	// dA ^ dB = h(alpha) ^ h(gamma)
	expectedDiffFP := hasher("alpha") ^ hasher("gamma")
	actualDiffFP := s1.Fingerprint() ^ s2.Fingerprint()
	assert.Equal(t, expectedDiffFP, actualDiffFP)

	// In-place delta merging via AddElements
	added := s1.AddElements(s2.Elements()...)
	assert.Equal(t, 1, added) // Only "gamma" is new
	assert.Equal(t, 3, s1.Size())
	assert.True(t, s1.Contains("alpha"))
	assert.True(t, s1.Contains("beta"))
	assert.True(t, s1.Contains("gamma"))
	assert.Equal(t, s1.Fingerprint(), s2.Fingerprint()^hasher("alpha"))
}

func TestDigestSet_JSONSerialization(t *testing.T) {
	hasher := DefaultHasher[userItem]()
	s := newDigestSet[userItem](hasher)
	u1 := userItem{ID: "u1", FirstName: "User1"}
	u2 := userItem{ID: "u2", FirstName: "User2"}
	s.Insert(u1)
	s.Insert(u2)

	raw, err := s.MarshalJSON()
	require.NoError(t, err)

	decoded := newDigestSet[userItem](hasher)
	err = json.Unmarshal(raw, decoded)
	require.NoError(t, err)

	assert.Equal(t, 2, decoded.Size())
	assert.True(t, decoded.Contains(u1))
	assert.True(t, decoded.Contains(u2))
	assert.Equal(t, s.Fingerprint(), decoded.Fingerprint())
}

func TestDigestSet_ConcurrentAccessAndRaceDetector(t *testing.T) {
	hasher := DefaultHasher[string]()
	s := newDigestSet[string](hasher)
	const writers = 8
	const readers = 8
	const itemsPerWriter = 100

	var wgWriters sync.WaitGroup
	for w := 0; w < writers; w++ {
		wgWriters.Add(1)
		go func(workerID int) {
			defer wgWriters.Done()
			for i := 0; i < itemsPerWriter; i++ {
				s.Insert(fmt.Sprintf("worker-%d-item-%d", workerID, i))
			}
		}(w)
	}

	stopReaders := make(chan struct{})
	var wgReaders sync.WaitGroup
	for r := 0; r < readers; r++ {
		wgReaders.Add(1)
		go func() {
			defer wgReaders.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_ = s.Size()
					_ = s.Empty()
					_ = s.Fingerprint()
					_ = s.Digests()
					_ = s.Slice()
					_ = s.Copy()
				}
			}
		}()
	}

	wgWriters.Wait()
	close(stopReaders)
	wgReaders.Wait()

	assert.Equal(t, writers*itemsPerWriter, s.Size())
}

func TestDigestSet_OpaqueReverseIndexStoreFactory(t *testing.T) {
	// Verify NewDigestSet returns ReverseIndexStore interface
	var hasher = DefaultHasher[userItem]()
	var store ReverseIndexStore[userItem, DigestSymbol] = NewDigestSet[userItem, DigestSymbol](hasher)
	defer store.Close()

	assert.True(t, store.Empty())
	assert.Equal(t, 0, store.Size())

	u1 := userItem{ID: "alice", FirstName: "Alice"}
	assert.True(t, store.AddElement(u1))
	assert.False(t, store.AddElement(u1)) // duplicate
	assert.Equal(t, 1, store.Size())
	assert.True(t, store.Contains(u1))

	u2 := userItem{ID: "bob", FirstName: "Bob"}
	assert.Equal(t, 1, store.AddElements(u1, u2))
	assert.Equal(t, 2, store.Size())

	// digests
	digests := store.Digests()
	assert.Len(t, digests, 2)
	assert.True(t, store.ContainsDigest(digests[0]))

	retrieved, found := store.GetByDigest(digests[0])
	assert.True(t, found)
	assert.NotEmpty(t, retrieved.ID)

	// Copy isolation through interface
	cp := store.Copy()
	assert.Equal(t, store.Size(), cp.Size())
	assert.Equal(t, store.Fingerprint(), cp.Fingerprint())

	cp.AddElement(userItem{ID: "charlie", FirstName: "Charlie"})
	assert.Equal(t, 3, cp.Size())
	assert.Equal(t, 2, store.Size())

	// JSON serialization via json.Marshal
	raw, err := json.Marshal(store)
	require.NoError(t, err)
	var decoded []userItem
	err = json.Unmarshal(raw, &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 2)
}
