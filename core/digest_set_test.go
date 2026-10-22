package core

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type userItem struct {
	UserID    string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
}

func (u userItem) ID() string {
	return u.UserID
}


type itemWithUint64Digest struct {
	val uint64
}

func (i itemWithUint64Digest) Digest() uint64 {
	return i.val
}

type itemWithSymbolDigest struct {
	val DigestSymbol
}

func (i itemWithSymbolDigest) Digest() DigestSymbol {
	return i.val
}

type itemPlain struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func TestDigestSet_BasicOperationsAndGetByDigest(t *testing.T) {
	var hasher = DefaultHasher[userItem]()
	s, err := newDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)

	assert.True(t, s.Empty())
	assert.Equal(t, 0, s.Size())
	assert.Equal(t, DigestSymbol(0), s.Fingerprint())

	u1 := userItem{UserID: "alice", FirstName: "Alice", LastName: "Smith"}
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
	u2 := userItem{UserID: "bob", FirstName: "Bob", LastName: "Jones"}
	u3 := userItem{UserID: "charlie", FirstName: "Charlie", LastName: "Brown"}
	addedCount := s.AddElements(u1, u2, u3)
	assert.Equal(t, 2, addedCount)
	assert.Equal(t, 3, s.Size())

	digests := s.Digests()
	assert.Len(t, digests, 3)
}

func TestDigestSet_DeterministicFingerprintAndCrossMachineEquivalence(t *testing.T) {

	var hasher = DefaultHasher[userItem]()
	s1, err := newDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)
	s2, err := newDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)

	u1 := userItem{UserID: "user-1", FirstName: "One"}
	u2 := userItem{UserID: "user-2", FirstName: "Two"}
	u3 := userItem{UserID: "user-3", FirstName: "Three"}

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
	u4 := userItem{UserID: "user-4", FirstName: "Four"}
	s1.Insert(u4)
	assert.NotEqual(t, s1.Fingerprint(), s2.Fingerprint())
}

func TestDigestSet_CopyIsolation(t *testing.T) {
	var hasher = DefaultHasher[string]()
	s, err := newDigestSet[string, DigestSymbol](hasher)
	require.NoError(t, err)
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
	s1, err := newDigestSet[string, DigestSymbol](hasher)
	require.NoError(t, err)
	s1.Insert("alpha")
	s1.Insert("beta")

	s2, err := newDigestSet[string, DigestSymbol](hasher)
	require.NoError(t, err)
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
	s, err := newDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)
	u1 := userItem{UserID: "u1", FirstName: "User1"}
	u2 := userItem{UserID: "u2", FirstName: "User2"}
	s.Insert(u1)
	s.Insert(u2)

	raw, err := s.MarshalJSON()
	require.NoError(t, err)

	decoded, err := newDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)
	err = json.Unmarshal(raw, decoded)
	require.NoError(t, err)

	assert.Equal(t, 2, decoded.Size())
	assert.True(t, decoded.Contains(u1))
	assert.True(t, decoded.Contains(u2))
	assert.Equal(t, s.Fingerprint(), decoded.Fingerprint())
}

func TestDigestSet_ConcurrentAccessAndRaceDetector(t *testing.T) {
	hasher := DefaultHasher[string]()
	s, err := newDigestSet[string, DigestSymbol](hasher)
	require.NoError(t, err)
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
	store, err := NewDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)
	defer store.Close()

	assert.True(t, store.Empty())
	assert.Equal(t, 0, store.Size())

	u1 := userItem{UserID: "alice", FirstName: "Alice"}
	assert.True(t, store.AddElement(u1))
	assert.False(t, store.AddElement(u1)) // duplicate
	assert.Equal(t, 1, store.Size())
	assert.True(t, store.Contains(u1))

	u2 := userItem{UserID: "bob", FirstName: "Bob"}
	assert.Equal(t, 1, store.AddElements(u1, u2))
	assert.Equal(t, 2, store.Size())

	// digests
	digests := store.Digests()
	assert.Len(t, digests, 2)
	assert.True(t, store.ContainsDigest(digests[0]))

	retrieved, found := store.GetByDigest(digests[0])
	assert.True(t, found)
	assert.NotEmpty(t, retrieved.ID())

	// Copy isolation through interface
	cp := store.Copy()
	assert.Equal(t, store.Size(), cp.Size())
	assert.Equal(t, store.Fingerprint(), cp.Fingerprint())

	cp.AddElement(userItem{UserID: "charlie", FirstName: "Charlie"})
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

func TestDigestSet_NilHasherErrors(t *testing.T) {
	// 1. Explicit nil hasher in NewDigestSet returns ErrNilHasher
	store, err := NewDigestSet[userItem, DigestSymbol](nil)
	assert.ErrorIs(t, err, ErrNilHasher)
	assert.Nil(t, store)

	// 2. newDigestSet with nil hasher returns ErrNilHasher
	internalStore, err := newDigestSet[userItem, DigestSymbol](nil)
	assert.ErrorIs(t, err, ErrNilHasher)
	assert.Nil(t, internalStore)
}

func TestDigestSet_UnmarshalJSONNilHasher(t *testing.T) {
	items := []userItem{
		{UserID: "user-1", FirstName: "Alice"},
		{UserID: "user-2", FirstName: "Bob"},
	}
	raw, err := json.Marshal(items)
	require.NoError(t, err)

	// 1. Unmarshaling into a zero-initialized digestSet struct with nil hasher MUST return ErrNilHasher
	var ds digestSet[userItem, DigestSymbol]
	err = json.Unmarshal(raw, &ds)
	assert.ErrorIs(t, err, ErrNilHasher)

	// 2. Unmarshaling into an initialized set succeeds
	hasher := DefaultHasher[userItem]()
	initialized, err := NewDigestSet[userItem, DigestSymbol](hasher)
	require.NoError(t, err)
	err = json.Unmarshal(raw, initialized)
	require.NoError(t, err)
	assert.Equal(t, 2, initialized.Size())
	assert.True(t, initialized.Contains(items[0]))
	assert.True(t, initialized.Contains(items[1]))
}

func TestDigestSet_ZeroValueStructPanicsOnMutations(t *testing.T) {
	var ds digestSet[string, DigestSymbol]

	// Read operations on empty nil-map zero struct
	assert.True(t, ds.Empty())
	assert.Equal(t, 0, ds.Size())
	assert.Empty(t, ds.Digests())
	assert.Empty(t, ds.Elements())

	// Mutation operations without hasher MUST panic with ErrNilHasher
	assert.PanicsWithError(t, ErrNilHasher.Error(), func() {
		ds.AddElement("hello")
	})
	assert.PanicsWithError(t, ErrNilHasher.Error(), func() {
		ds.Contains("hello")
	})
	assert.PanicsWithError(t, ErrNilHasher.Error(), func() {
		ds.Remove("hello")
	})
}

func TestDefaultHasher(t *testing.T) {
	// 1. DigestSymbol fast path
	dsHasher := DefaultHasher[DigestSymbol]()
	sym := DigestSymbol(0x12345678deadbeef)
	assert.Equal(t, sym, dsHasher(sym))

	// 2. Custom Digest() uint64 interface
	u64Hasher := DefaultHasher[itemWithUint64Digest]()
	assert.Equal(t, DigestSymbol(42), u64Hasher(itemWithUint64Digest{val: 42}))

	// 3. Custom Digest() DigestSymbol interface
	symHasher := DefaultHasher[itemWithSymbolDigest]()
	assert.Equal(t, DigestSymbol(99), symHasher(itemWithSymbolDigest{val: 99}))

	// 4. Custom ID() string interface (exercised by userItem)
	userHasher := DefaultHasher[userItem]()
	u := userItem{UserID: "test-user-id", FirstName: "Test"}
	hID := fnv.New64a()
	_, _ = hID.Write([]byte("test-user-id"))
	assert.Equal(t, DigestSymbol(hID.Sum64()), userHasher(u))

	// Ensure ID() path takes precedence over JSON serialization:
	// If it used JSON serialization, it would hash the full JSON string instead of just the ID.
	jsonBytes, err := json.Marshal(u)
	require.NoError(t, err)
	hJSON := fnv.New64a()
	_, _ = hJSON.Write(jsonBytes)
	assert.NotEqual(t, DigestSymbol(hJSON.Sum64()), userHasher(u), "DefaultHasher must use ID() fast-path rather than JSON fallback")

	// 5. Native string
	strHasher := DefaultHasher[string]()
	hStr := fnv.New64a()
	_, _ = hStr.Write([]byte("hello-world"))
	assert.Equal(t, DigestSymbol(hStr.Sum64()), strHasher("hello-world"))

	// 6. Plain struct fallback to deterministic JSON serialization
	plainHasher := DefaultHasher[itemPlain]()
	p := itemPlain{Name: "Alice", Age: 30}
	pBytes, err := json.Marshal(p)
	require.NoError(t, err)
	hPlain := fnv.New64a()
	_, _ = hPlain.Write(pBytes)
	assert.Equal(t, DigestSymbol(hPlain.Sum64()), plainHasher(p))

	// 7. Non-marshalable fallback to fmt.Sprintf("%v", item)
	ch := make(chan int)
	chHasher := DefaultHasher[chan int]()
	hCh := fnv.New64a()
	_, _ = hCh.Write([]byte(fmt.Sprintf("%v", ch)))
	assert.Equal(t, DigestSymbol(hCh.Sum64()), chHasher(ch))
}

