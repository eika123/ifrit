package digestmaps_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func kvItemHasher(item digestmaps.Item[string, string]) digestmaps.DigestSymbol {
	h := sha256.New()
	_, _ = h.Write([]byte(item.Key))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(item.Value))
	sum := h.Sum(nil)
	return digestmaps.DigestSymbol(binary.BigEndian.Uint64(sum[:8]))
}

func TestKeyedDigestSet_NilHasher(t *testing.T) {
	_, err := digestmaps.NewKeyedDigestSet[string, string, digestmaps.DigestSymbol](nil)
	assert.ErrorIs(t, err, digestmaps.ErrNilHasher)
}

func TestKeyedDigestSet_InsertLookupAndSiblings(t *testing.T) {
	store, err := digestmaps.NewKeyedDigestSet[string, string, digestmaps.DigestSymbol](kvItemHasher)
	require.NoError(t, err)

	assert.False(t, store.ContainsKey("k1"))
	got, ok := store.GetByKey("k1")
	assert.False(t, ok)
	assert.Nil(t, got)

	// Insert first item for k1.
	item1 := digestmaps.Item[string, string]{Key: "k1", Value: "v1"}
	d1, added := store.Insert(item1)
	require.True(t, added)
	assert.True(t, store.ContainsKey("k1"))
	assert.Equal(t, 1, store.Size())

	// Duplicate insert must not duplicate sibling digest.
	d1Dup, added := store.Insert(item1)
	assert.False(t, added)
	assert.Equal(t, d1, d1Dup)
	got, ok = store.GetByKey("k1")
	require.True(t, ok)
	assert.Equal(t, []digestmaps.Item[string, string]{item1}, got)

	// Concurrent conflicting write for same key k1 produces a sibling bucket.
	item2 := digestmaps.Item[string, string]{Key: "k1", Value: "v2"}
	d2, added := store.Insert(item2)
	require.True(t, added)
	assert.NotEqual(t, d1, d2)
	assert.Equal(t, 2, store.Size())

	got, ok = store.GetByKey("k1")
	require.True(t, ok)
	assert.ElementsMatch(t, []digestmaps.Item[string, string]{item1, item2}, got)

	// InsertBatch adds new items and ignores duplicates.
	item3 := digestmaps.Item[string, string]{Key: "k2", Value: "v3"}
	addedCount := store.InsertBatch(item1, item3)
	assert.Equal(t, 1, addedCount)
	assert.Equal(t, 3, store.Size())

	gotK2, ok := store.GetByKey("k2")
	require.True(t, ok)
	assert.Equal(t, []digestmaps.Item[string, string]{item3}, gotK2)
}

func TestKeyedDigestSet_GrowOnlyCopyAndJSON(t *testing.T) {
	store, err := digestmaps.NewKeyedDigestSet[string, string, digestmaps.DigestSymbol](kvItemHasher)
	require.NoError(t, err)

	// Confirm keyedDigestSet is strictly grow-only (does not satisfy MutableReverseIndexStore).
	_, isMutable := store.(digestmaps.MutableReverseIndexStore[digestmaps.Item[string, string], digestmaps.DigestSymbol])
	assert.False(t, isMutable, "keyedDigestSet must be grow-only")

	item1 := digestmaps.Item[string, string]{Key: "k1", Value: "v1"}
	item2 := digestmaps.Item[string, string]{Key: "k1", Value: "v2"}
	item3 := digestmaps.Item[string, string]{Key: "k2", Value: "v3"}
	store.InsertBatch(item1, item2, item3)

	// Copy must preserve both primary store and secondary index independently.
	cpStore := store.Copy().(digestmaps.KeyedReverseIndexStore[string, string, digestmaps.DigestSymbol])
	assert.Equal(t, store.Fingerprint(), cpStore.Fingerprint())

	// Inserting into original must not affect copy.
	item4 := digestmaps.Item[string, string]{Key: "k1", Value: "v4"}
	store.Insert(item4)
	cpGot, ok := cpStore.GetByKey("k1")
	require.True(t, ok)
	assert.ElementsMatch(t, []digestmaps.Item[string, string]{item1, item2}, cpGot)

	// JSON round-trip rebuilds secondary index.
	raw, err := json.Marshal(cpStore)
	require.NoError(t, err)
	restored, err := digestmaps.NewKeyedDigestSet[string, string, digestmaps.DigestSymbol](kvItemHasher)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, restored))
	assert.Equal(t, cpStore.Fingerprint(), restored.Fingerprint())
	restoredK1, ok := restored.GetByKey("k1")
	require.True(t, ok)
	assert.ElementsMatch(t, []digestmaps.Item[string, string]{item1, item2}, restoredK1)
}
