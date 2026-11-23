package digestmaps

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStringVersionHasher(vi VersionedItem[string]) DigestSymbol {
	h := MustDefaultHasher[string]()
	return h(fmt.Sprintf("%s:%d", vi.Item, vi.Version))
}

func TestVersionVectorImmutable_EpochAndImmutability(t *testing.T) {
	keyFn := func(s string) string { return s }
	v0 := NewVersionVectorImmutable[string, string, DigestSymbol](keyFn, testStringVersionHasher)
	assert.Equal(t, uint64(0), v0.Epoch())
	assert.True(t, v0.Empty())

	v1, added := v0.AddItem(VersionedItem[string]{Item: "dht", Version: 1})
	require.True(t, added)
	assert.Equal(t, uint64(0), v0.Epoch(), "previous snapshot must remain immutable")
	assert.True(t, v0.Empty())
	assert.Equal(t, uint64(1), v1.Epoch())
	assert.True(t, v1.ContainsKey("dht"))

	// Stale or equal version is a no-op and does not bump epoch.
	v1Same, added := v1.AddItem(VersionedItem[string]{Item: "dht", Version: 1})
	assert.False(t, added)
	assert.Equal(t, uint64(1), v1Same.Epoch())

	// Adding a second key bumps epoch to 2.
	v2, added := v1.AddItem(VersionedItem[string]{Item: "pubsub", Version: 3})
	require.True(t, added)
	assert.Equal(t, uint64(2), v2.Epoch())
	assert.Equal(t, 1, v1.Size(), "v1 must remain unchanged")
	assert.Equal(t, 2, v2.Size())

	// OrderedElements returns canonical sorted order regardless of map order.
	ordered := OrderedElements[string, string, DigestSymbol](v2, keyFn)
	require.Len(t, ordered, 2)
	assert.Equal(t, "dht", ordered[0].Item)
	assert.Equal(t, "pubsub", ordered[1].Item)

	// Removing a key bumps epoch to 3 and restores v1's fingerprint.
	v3, removed := v2.Remove("pubsub")
	require.True(t, removed)
	assert.Equal(t, uint64(3), v3.Epoch())
	assert.Equal(t, v1.Fingerprint(), v3.Fingerprint())
	assert.Equal(t, 2, v2.Size(), "v2 must remain unchanged")

	// Snapshot reconstruction reproduces exact epoch and fingerprint.
	restored := NewVersionVectorImmutableSnapshot[string, string, DigestSymbol](
		v2.Epoch(),
		keyFn,
		testStringVersionHasher,
		ordered...,
	)
	assert.Equal(t, v2.Epoch(), restored.Epoch())
	assert.Equal(t, v2.Fingerprint(), restored.Fingerprint())
	assert.Equal(t, v2.Versions(), restored.Versions())
}

func TestVersionVectorMutable_EpochMonotonicity(t *testing.T) {
	keyFn := func(s string) string { return s }
	vv := NewVersionVectorMutable[string, string, DigestSymbol](keyFn, testStringVersionHasher)
	assert.Equal(t, uint64(0), vv.Epoch())

	_, added := vv.AddItem(VersionedItem[string]{Item: "a", Version: 1})
	require.True(t, added)
	assert.Equal(t, uint64(1), vv.Epoch())

	// Stale insert does not bump epoch.
	_, added = vv.AddItem(VersionedItem[string]{Item: "a", Version: 1})
	assert.False(t, added)
	assert.Equal(t, uint64(1), vv.Epoch())

	// Upgrading version bumps epoch.
	_, added = vv.AddItem(VersionedItem[string]{Item: "a", Version: 2})
	require.True(t, added)
	assert.Equal(t, uint64(2), vv.Epoch())

	// RemoveVersion with wrong version does not bump epoch.
	assert.False(t, vv.RemoveVersion("a", 1))
	assert.Equal(t, uint64(2), vv.Epoch())

	// RemoveVersion with matching version bumps epoch.
	assert.True(t, vv.RemoveVersion("a", 2))
	assert.Equal(t, uint64(3), vv.Epoch())

	// Clear on empty vector does not bump epoch.
	vv.Clear()
	assert.Equal(t, uint64(3), vv.Epoch())

	_, added = vv.AddItem(VersionedItem[string]{Item: "b", Version: 1})
	require.True(t, added)
	assert.Equal(t, uint64(4), vv.Epoch())

	vv.Clear()
	assert.Equal(t, uint64(5), vv.Epoch())
}
