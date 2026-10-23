package reverseindexstore_test

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sync"
	"testing"

	"github.com/joonnna/ifrit/reverseindexstore"
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
	val reverseindexstore.DigestSymbol
}

func (i itemWithSymbolDigest) Digest() reverseindexstore.DigestSymbol {
	return i.val
}

type itemPlain struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func TestDigestSet_BasicOperationsAndGetByDigest(t *testing.T) {
	hasher := reverseindexstore.DefaultHasher[userItem]()
	s, err := reverseindexstore.NewDigestSet[userItem, reverseindexstore.DigestSymbol](hasher)
	require.NoError(t, err)

	u1 := userItem{UserID: "u1", FirstName: "Alice"}
	u2 := userItem{UserID: "u2", FirstName: "Bob"}

	added := s.AddElements(u1, u2)
	assert.Equal(t, 2, added)
	assert.Equal(t, 2, s.Size())
	assert.False(t, s.Empty())

	d1 := hasher(u1)
	d2 := hasher(u2)

	assert.True(t, s.Contains(u1))
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
}

func TestDigestSet_DefaultHasherVariants(t *testing.T) {
	// 1. Direct DigestSymbol
	hSymbol := reverseindexstore.DefaultHasher[reverseindexstore.DigestSymbol]()
	ds := reverseindexstore.DigestSymbol(42)
	assert.Equal(t, ds, hSymbol(ds))

	// 2. uint64 Digest() interface
	hUint64 := reverseindexstore.DefaultHasher[itemWithUint64Digest]()
	assert.Equal(t, reverseindexstore.DigestSymbol(99), hUint64(itemWithUint64Digest{val: 99}))

	// 3. DigestSymbol Digest() interface
	hSymItem := reverseindexstore.DefaultHasher[itemWithSymbolDigest]()
	assert.Equal(t, reverseindexstore.DigestSymbol(123), hSymItem(itemWithSymbolDigest{val: 123}))

	// 4. Native string
	hStr := reverseindexstore.DefaultHasher[string]()
	hExpected := fnv.New64a()
	hExpected.Write([]byte("hello"))
	assert.Equal(t, reverseindexstore.DigestSymbol(hExpected.Sum64()), hStr("hello"))

	// 5. Plain struct JSON fallback
	hPlain := reverseindexstore.DefaultHasher[itemPlain]()
	assert.NotZero(t, hPlain(itemPlain{Name: "Carol", Age: 30}))
}

func TestDigestSet_CopyAndIsolation(t *testing.T) {
	hasher := reverseindexstore.DefaultHasher[string]()
	s, err := reverseindexstore.NewDigestSet[string, reverseindexstore.DigestSymbol](hasher)
	require.NoError(t, err)

	s.AddElements("a", "b")
	cp := s.Copy()

	s.AddElements("c")
	assert.Equal(t, 3, s.Size())
	assert.Equal(t, 2, cp.Size())
	assert.False(t, cp.Contains("c"))
}

func TestDigestSet_JSONSerialization(t *testing.T) {
	hasher := reverseindexstore.DefaultHasher[string]()
	s, err := reverseindexstore.NewDigestSet[string, reverseindexstore.DigestSymbol](hasher)
	require.NoError(t, err)

	s.AddElements("item1", "item2")
	data, err := json.Marshal(s)
	require.NoError(t, err)

	s2, err := reverseindexstore.NewDigestSet[string, reverseindexstore.DigestSymbol](hasher)
	require.NoError(t, err)
	err = json.Unmarshal(data, s2)
	require.NoError(t, err)

	assert.Equal(t, s.Size(), s2.Size())
	assert.Equal(t, s.Fingerprint(), s2.Fingerprint())
}

func TestDigestSet_ConcurrentAccess(t *testing.T) {
	hasher := reverseindexstore.DefaultHasher[string]()
	s, err := reverseindexstore.NewDigestSet[string, reverseindexstore.DigestSymbol](hasher)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			item := fmt.Sprintf("worker-%d", id)
			s.AddElements(item)
			_ = s.Fingerprint()
			_ = s.Contains(item)
			_ = s.Elements()
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 50, s.Size())
}
