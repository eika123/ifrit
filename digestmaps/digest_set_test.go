package digestmaps_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sync"
	"testing"

	"github.com/joonnna/ifrit/digestmaps"
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
	val digestmaps.DigestSymbol
}

func (i itemWithSymbolDigest) Digest() digestmaps.DigestSymbol {
	return i.val
}

type itemPlain struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type itemWithCryptoBytes struct {
	payload []byte
}

func (i itemWithCryptoBytes) CryptographicIdentity() []byte {
	return i.payload
}

type itemWithCryptoString struct {
	id string
}

func (i itemWithCryptoString) CryptographicIdentity() string {
	return i.id
}

func TestDigestSet_BasicOperationsAndGetByDigest(t *testing.T) {
	hasher := digestmaps.MustDefaultHasher[userItem]()
	s, err := digestmaps.NewDigestSet[userItem, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	u1 := userItem{UserID: "u1", FirstName: "Alice"}
	u2 := userItem{UserID: "u2", FirstName: "Bob"}

	added := s.AddElements(u1, u2)
	assert.Equal(t, 2, added)
	assert.Equal(t, 2, s.Size())
	assert.False(t, s.Empty())

	d1 := hasher(u1)
	d2 := hasher(u2)

	got1FromContains, found1 := s.Contains(u1)
	assert.True(t, found1)
	assert.Equal(t, u1, got1FromContains)
	assert.True(t, s.ContainsDigest(d1))

	got1, found := s.GetByDigest(d1)
	assert.True(t, found)
	assert.Equal(t, u1, got1)

	got2, found := s.GetByDigest(d2)
	assert.True(t, found)
	assert.Equal(t, u2, got2)

	// Fingerprint check
	expectedFP := d1.XOR(d2)
	assert.Equal(t, expectedFP, s.Fingerprint())

	// Deletion
	removed := s.Remove(u1)
	assert.True(t, removed)
	assert.Equal(t, 1, s.Size())
	assert.Equal(t, d2, s.Fingerprint())

	_, found = s.GetByDigest(d1)
	assert.False(t, found)

	// Batch GetByDigests test
	s.AddElement(u1) // s now contains u1 and u2
	elems, allFound := s.GetByDigests([]digestmaps.DigestSymbol{d1, d2})
	assert.True(t, allFound)
	assert.ElementsMatch(t, []userItem{u1, u2}, elems)

	// Partial find
	elems, allFound = s.GetByDigests([]digestmaps.DigestSymbol{d1, 99999})
	assert.False(t, allFound)
	assert.Equal(t, []userItem{u1}, elems)

	// Empty input
	elems, allFound = s.GetByDigests(nil)
	assert.True(t, allFound)
	assert.Nil(t, elems)
}

func TestDigestSet_DefaultHasherVariants(t *testing.T) {
	// 1. Direct DigestSymbol
	hSymbol, err := digestmaps.DefaultHasher[digestmaps.DigestSymbol]()
	require.NoError(t, err)
	ds := digestmaps.DigestSymbol(42)
	assert.Equal(t, ds, hSymbol(ds))

	// 2. uint64 Digest() interface
	hUint64, err := digestmaps.DefaultHasher[itemWithUint64Digest]()
	require.NoError(t, err)
	assert.Equal(t, digestmaps.DigestSymbol(99), hUint64(itemWithUint64Digest{val: 99}))

	// 3. DigestSymbol Digest() interface
	hSymItem, err := digestmaps.DefaultHasher[itemWithSymbolDigest]()
	require.NoError(t, err)
	assert.Equal(t, digestmaps.DigestSymbol(123), hSymItem(itemWithSymbolDigest{val: 123}))

	// 4. Native string
	hStr, err := digestmaps.DefaultHasher[string]()
	require.NoError(t, err)
	hExpected := fnv.New64a()
	hExpected.Write([]byte("hello"))
	assert.Equal(t, digestmaps.DigestSymbol(hExpected.Sum64()), hStr("hello"))

	// 5. Plain struct without identity contract returns error
	hPlain, err := digestmaps.DefaultHasher[itemPlain]()
	require.Error(t, err)
	assert.Nil(t, hPlain)
	assert.ErrorIs(t, err, digestmaps.ErrUnhashableType)

	// 6. CryptographicIdentity with []byte (SHA-256 truncated to 64-bit uint64)
	hCryptoBytes, err := digestmaps.DefaultHasher[itemWithCryptoBytes]()
	require.NoError(t, err)
	payload := []byte("crypto-payload-123")
	sumB := sha256.Sum256(payload)
	expectedCryptoB := digestmaps.DigestSymbol(binary.BigEndian.Uint64(sumB[:8]))
	assert.Equal(t, expectedCryptoB, hCryptoBytes(itemWithCryptoBytes{payload: payload}))

	// 7. CryptographicIdentity with string (SHA-256 truncated to 64-bit uint64)
	hCryptoStr, err := digestmaps.DefaultHasher[itemWithCryptoString]()
	require.NoError(t, err)
	strID := "crypto-id-456"
	sumS := sha256.Sum256([]byte(strID))
	expectedCryptoS := digestmaps.DigestSymbol(binary.BigEndian.Uint64(sumS[:8]))
	assert.Equal(t, expectedCryptoS, hCryptoStr(itemWithCryptoString{id: strID}))

	// 8. Native []byte fast path (SHA-256 truncated to 64-bit uint64, zero allocations)
	hBytes, err := digestmaps.DefaultHasher[[]byte]()
	require.NoError(t, err)
	rawPayload := []byte("fast-path-raw-byte-slice-data")
	sumRaw := sha256.Sum256(rawPayload)
	expectedRaw := digestmaps.DigestSymbol(binary.BigEndian.Uint64(sumRaw[:8]))
	assert.Equal(t, expectedRaw, hBytes(rawPayload))

	// 9. Pointer to []byte (*[]byte)
	hBytesPtr, err := digestmaps.DefaultHasher[*[]byte]()
	require.NoError(t, err)
	assert.Equal(t, expectedRaw, hBytesPtr(&rawPayload))
	assert.Zero(t, hBytesPtr(nil))
}

type unhashableItem struct {
	Ch chan int
}

func TestDefaultHasher_UnhashableTypeReturnsError(t *testing.T) {
	hasher, err := digestmaps.DefaultHasher[unhashableItem]()
	require.Error(t, err)
	assert.Nil(t, hasher)
	assert.ErrorIs(t, err, digestmaps.ErrUnhashableType)

	// MustDefaultHasher panics for unhashable types
	assert.Panics(t, func() {
		digestmaps.MustDefaultHasher[unhashableItem]()
	})
}

func TestDigestSet_ByteArrayFastPathAndStoreIntegration(t *testing.T) {
	hasher := digestmaps.MustDefaultHasher[[]byte]()

	// 1. Verify determinism and empty slice behavior
	emptyDigest := hasher([]byte{})
	sumEmpty := sha256.Sum256([]byte{})
	expectedEmpty := digestmaps.DigestSymbol(binary.BigEndian.Uint64(sumEmpty[:8]))
	assert.Equal(t, expectedEmpty, emptyDigest)

	nilDigest := hasher(nil)
	assert.Equal(t, emptyDigest, nilDigest)

	// 2. Distinct inputs produce distinct digests
	blobA := []byte("chunk-alpha-001")
	blobB := []byte("chunk-bravo-002")
	digestA := hasher(blobA)
	digestB := hasher(blobB)
	assert.NotEqual(t, digestA, digestB)

	// 3. DigestSet integration with []byte
	store, err := digestmaps.NewDigestSet[[]byte, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	added := store.AddElements(blobA, blobB)
	assert.Equal(t, 2, added)
	assert.Equal(t, 2, store.Size())
	assert.Equal(t, digestA.XOR(digestB), store.Fingerprint())

	gotA, found := store.GetByDigest(digestA)
	require.True(t, found)
	assert.Equal(t, blobA, gotA)

	gotB, found := store.GetByDigest(digestB)
	require.True(t, found)
	assert.Equal(t, blobB, gotB)

	// 4. Large blob hashing (5 MB)
	largeBlob := make([]byte, 5*1024*1024)
	for i := range largeBlob {
		largeBlob[i] = byte(i % 256)
	}
	largeDigest := hasher(largeBlob)
	sumLarge := sha256.Sum256(largeBlob)
	expectedLarge := digestmaps.DigestSymbol(binary.BigEndian.Uint64(sumLarge[:8]))
	assert.Equal(t, expectedLarge, largeDigest)

	// 5. Zero heap allocation verification for []byte hashing
	sample := []byte("benchmark-allocation-check")
	allocs := testing.AllocsPerRun(1000, func() {
		_ = hasher(sample)
	})
	assert.Zero(t, allocs, "DefaultHasher[[]byte] must incur 0 heap allocations")
}

func TestDigestSet_CopyAndIsolation(t *testing.T) {
	hasher := digestmaps.MustDefaultHasher[string]()
	s, err := digestmaps.NewDigestSet[string, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	s.AddElements("a", "b")
	cp := s.Copy()

	s.AddElements("c")
	assert.Equal(t, 3, s.Size())
	assert.Equal(t, 2, cp.Size())
	_, foundC := cp.Contains("c")
	assert.False(t, foundC)
}

func TestDigestSet_JSONSerialization(t *testing.T) {
	hasher := digestmaps.MustDefaultHasher[string]()
	s, err := digestmaps.NewDigestSet[string, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	s.AddElements("item1", "item2")
	data, err := json.Marshal(s)
	require.NoError(t, err)

	s2, err := digestmaps.NewDigestSet[string, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)
	err = json.Unmarshal(data, s2)
	require.NoError(t, err)

	assert.Equal(t, s.Size(), s2.Size())
	assert.Equal(t, s.Fingerprint(), s2.Fingerprint())
}

func TestDigestSet_ConcurrentAccess(t *testing.T) {
	hasher := digestmaps.MustDefaultHasher[string]()
	s, err := digestmaps.NewDigestSet[string, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			item := fmt.Sprintf("worker-%d", id)
			s.AddElements(item)
			_ = s.Fingerprint()
			_, _ = s.Contains(item)
			_ = s.Elements()
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 50, s.Size())
}

func TestDigestSymbolConversions(t *testing.T) {
	// Nil / empty checks
	assert.Nil(t, digestmaps.AsDigestSymbols(nil))
	assert.Nil(t, digestmaps.AsDigestSymbols([]uint64{}))
	assert.Nil(t, digestmaps.AsUint64Slice(nil))
	assert.Nil(t, digestmaps.AsUint64Slice([]digestmaps.DigestSymbol{}))
	uValues := []uint64{100, 200, 300, 400}
	symbols := digestmaps.AsDigestSymbols(uValues)
	require.Len(t, symbols, 4)
	assert.Equal(t, digestmaps.DigestSymbol(100), symbols[0])
	assert.Equal(t, digestmaps.DigestSymbol(400), symbols[3])

	backToU := digestmaps.AsUint64Slice(symbols)
	assert.Equal(t, uValues, backToU)

	// Verify zero-allocation reinterpretation shares underlying array
	symbols[1] = 999
	assert.Equal(t, uint64(999), uValues[1])
}

func TestDigestSet_InsertAndDigest(t *testing.T) {
	hasher := digestmaps.MustDefaultHasher[string]()
	s, err := digestmaps.NewDigestSet[string, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	item := "test-item"
	expectedDigest := hasher(item)

	// Digest method
	assert.Equal(t, expectedDigest, s.Digest(item))

	// Insert returns digest and newlyAdded=true
	d, newlyAdded := s.Insert(item)
	assert.Equal(t, expectedDigest, d)
	assert.True(t, newlyAdded)
	assert.Equal(t, 1, s.Size())

	// Re-inserting returns digest and newlyAdded=false
	d2, newlyAdded2 := s.Insert(item)
	assert.Equal(t, expectedDigest, d2)
	assert.False(t, newlyAdded2)
	assert.Equal(t, 1, s.Size())
}

func BenchmarkDefaultHasher_ByteArray(b *testing.B) {
	hasher := digestmaps.MustDefaultHasher[[]byte]()
	sizes := []int{64, 1024, 64 * 1024, 1024 * 1024}

	for _, sz := range sizes {
		b.Run(fmt.Sprintf("size=%dB", sz), func(b *testing.B) {
			data := make([]byte, sz)
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = hasher(data)
			}
		})
	}
}
