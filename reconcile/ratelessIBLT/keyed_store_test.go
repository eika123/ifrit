package ratelessIBLT

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeyedHasher(item digestmaps.Item[string, string]) digestmaps.DigestSymbol {
	h := sha256.New()
	_, _ = h.Write([]byte(item.Key))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(item.Value))
	sum := h.Sum(nil)
	return digestmaps.DigestSymbol(binary.BigEndian.Uint64(sum[:8]))
}

func TestKeyedReconcilableStore_InterfaceLookupSketchAndCopy(t *testing.T) {
	store, err := NewKeyedReconcilableStore[string, string](testKeyedHasher, 64)
	require.NoError(t, err)

	// Compile-time / runtime interface checks: satisfies both reconcile.Store and KeyedReverseIndexStore.
	var _ reconcile.Store[digestmaps.Item[string, string]] = store
	var _ digestmaps.KeyedReverseIndexStore[string, string, digestmaps.DigestSymbol] = store

	item1 := digestmaps.Item[string, string]{Key: "a", Value: "v1"}
	item2 := digestmaps.Item[string, string]{Key: "a", Value: "v2"}
	store.InsertBatch(item1, item2)

	assert.True(t, store.ContainsKey("a"))
	got, ok := store.GetByKey("a")
	require.True(t, ok)
	assert.ElementsMatch(t, []digestmaps.Item[string, string]{item1, item2}, got)
	assert.NotNil(t, store.SnapshotSketch())
	assert.NotNil(t, store.Negotiator())

	// Copy preserves keyed interface and independent sketch/index state.
	cp := store.Copy().(*KeyedReconcilableStore[string, string])
	assert.Equal(t, store.Fingerprint(), cp.Fingerprint())

	store.Insert(digestmaps.Item[string, string]{Key: "b", Value: "v3"})
	assert.False(t, cp.ContainsKey("b"))
	cpGot, ok := cp.GetByKey("a")
	require.True(t, ok)
	assert.ElementsMatch(t, []digestmaps.Item[string, string]{item1, item2}, cpGot)
}
