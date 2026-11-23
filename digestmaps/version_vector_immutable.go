package digestmaps

import (
	"cmp"
	"maps"
	"slices"
)

type versionVectorImmutable[K comparable, T any, S Symbol[S]] struct {
	keyFunc     KeyExtractor[T, K]
	hasher      ItemHasher[T, S]
	items       map[K]*VersionedItem[T]
	fingerprint S
	epoch       uint64
}

// NewVersionVectorImmutable creates an empty persistent VersionVectorImmutable at epoch 0.
func NewVersionVectorImmutable[K comparable, T any, S Symbol[S]](
	keyFunc KeyExtractor[T, K],
	hasher ItemHasher[T, S],
) VersionVectorImmutable[K, T, S] {
	return &versionVectorImmutable[K, T, S]{
		keyFunc: keyFunc,
		hasher:  hasher,
		items:   make(map[K]*VersionedItem[T]),
	}
}

// NewVersionVectorImmutableSnapshot reconstructs an immutable version vector at an explicit
// wire epoch with the supplied entries, computing its cumulative XOR fingerprint.
// If duplicate keys appear in items, the entry with the highest Version is retained.
func NewVersionVectorImmutableSnapshot[K comparable, T any, S Symbol[S]](
	epoch uint64,
	keyFunc KeyExtractor[T, K],
	hasher ItemHasher[T, S],
	items ...VersionedItem[T],
) VersionVectorImmutable[K, T, S] {
	m := make(map[K]*VersionedItem[T], len(items))
	var fp S
	for _, it := range items {
		key := keyFunc(it.Item)
		if existing, ok := m[key]; ok {
			if it.Version <= existing.Version {
				continue
			}
			fp = fp.XOR(hasher(*existing))
		}
		cp := &VersionedItem[T]{
			Item:    it.Item,
			Version: it.Version,
		}
		m[key] = cp
		fp = fp.XOR(hasher(*cp))
	}
	return &versionVectorImmutable[K, T, S]{
		keyFunc:     keyFunc,
		hasher:      hasher,
		items:       m,
		fingerprint: fp,
		epoch:       epoch,
	}
}

func (vv *versionVectorImmutable[K, T, S]) AddItem(versionedItem VersionedItem[T]) (VersionVectorImmutable[K, T, S], bool) {
	key := vv.keyFunc(versionedItem.Item)
	versionNumber := versionedItem.Version

	curr, exists := vv.items[key]
	if exists && versionNumber <= curr.Version {
		return vv, false
	}

	newItems := make(map[K]*VersionedItem[T], len(vv.items)+1)
	maps.Copy(newItems, vv.items)

	newFP := vv.fingerprint
	if exists {
		newFP = newFP.XOR(vv.hasher(*curr))
	}
	newFP = newFP.XOR(vv.hasher(versionedItem))

	newItems[key] = &VersionedItem[T]{
		Item:    versionedItem.Item,
		Version: versionNumber,
	}

	return &versionVectorImmutable[K, T, S]{
		keyFunc:     vv.keyFunc,
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: newFP,
		epoch:       vv.epoch + 1,
	}, true
}

func (vv *versionVectorImmutable[K, T, S]) GetOne(key K) (VersionedItem[T], bool) {
	entry, exists := vv.items[key]
	if !exists {
		var zero VersionedItem[T]
		return zero, false
	}
	return *entry, true
}

func (vv *versionVectorImmutable[K, T, S]) GetMany(keys []K) []VersionedItem[T] {
	elements := make([]VersionedItem[T], 0, len(keys))
	for _, key := range keys {
		entry, exists := vv.items[key]
		if !exists {
			continue
		}
		elements = append(elements, *entry)
	}
	return elements
}

func (vv *versionVectorImmutable[K, T, S]) ContainsKey(key K) bool {
	_, found := vv.items[key]
	return found
}

func (vv *versionVectorImmutable[K, T, S]) ContainsKeyVersion(key K, version uint64) bool {
	entry, found := vv.items[key]
	if !found {
		return false
	}
	return entry.Version == version
}

func (vv *versionVectorImmutable[K, T, S]) Remove(key K) (VersionVectorImmutable[K, T, S], bool) {
	entry, found := vv.items[key]
	if !found {
		return vv, false
	}

	digest := vv.hasher(*entry)
	newItems := make(map[K]*VersionedItem[T], len(vv.items)-1)
	maps.Copy(newItems, vv.items)
	delete(newItems, key)

	return &versionVectorImmutable[K, T, S]{
		keyFunc:     vv.keyFunc,
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: vv.fingerprint.XOR(digest),
		epoch:       vv.epoch + 1,
	}, true
}

func (vv *versionVectorImmutable[K, T, S]) RemoveVersion(key K, version uint64) (VersionVectorImmutable[K, T, S], bool) {
	entry, found := vv.items[key]
	if !found || entry.Version != version {
		return vv, false
	}

	digest := vv.hasher(*entry)
	newItems := make(map[K]*VersionedItem[T], len(vv.items)-1)
	maps.Copy(newItems, vv.items)
	delete(newItems, key)

	return &versionVectorImmutable[K, T, S]{
		keyFunc:     vv.keyFunc,
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: vv.fingerprint.XOR(digest),
		epoch:       vv.epoch + 1,
	}, true
}

func (vv *versionVectorImmutable[K, T, S]) Fingerprint() S {
	return vv.fingerprint
}

func (vv *versionVectorImmutable[K, T, S]) Epoch() uint64 {
	return vv.epoch
}

func (vv *versionVectorImmutable[K, T, S]) Size() int {
	return len(vv.items)
}

func (vv *versionVectorImmutable[K, T, S]) Empty() bool {
	return len(vv.items) == 0
}

func (vv *versionVectorImmutable[K, T, S]) Elements() []VersionedItem[T] {
	elems := make([]VersionedItem[T], 0, len(vv.items))
	for _, entry := range vv.items {
		elems = append(elems, *entry)
	}
	return elems
}

func (vv *versionVectorImmutable[K, T, S]) Versions() map[K]uint64 {
	vers := make(map[K]uint64, len(vv.items))
	for k, entry := range vv.items {
		vers[k] = entry.Version
	}
	return vers
}

func (vv *versionVectorImmutable[K, T, S]) DigestsCopy() []S {
	digests := make([]S, 0, len(vv.items))
	for _, entry := range vv.items {
		digests = append(digests, vv.hasher(*entry))
	}
	return digests
}

// OrderedElements returns all entries in vv sorted canonically by their extracted key.
// Use this when marshaling or cryptographically signing a VersionVector snapshot so
// Go's randomized map iteration order does not affect the canonical byte representation.
func OrderedElements[K cmp.Ordered, T any, S Symbol[S]](
	vv VersionVector[K, T, S],
	keyFunc KeyExtractor[T, K],
) []VersionedItem[T] {
	if vv == nil {
		return nil
	}
	elems := vv.Elements()
	slices.SortFunc(elems, func(a, b VersionedItem[T]) int {
		return cmp.Compare(keyFunc(a.Item), keyFunc(b.Item))
	})
	return elems
}
