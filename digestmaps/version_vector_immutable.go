package digestmaps

import (
	"maps"
)

type versionVectorImmutable[K comparable, T any, S Symbol[S]] struct {
	keyFunc     KeyExtractor[T, K]
	hasher      ItemHasher[T, S]
	items       map[K]*VersionedItem[T]
	fingerprint S
}

// NewVersionVectorImmutable creates a persistent VersionVectorImmutable initialized with key and digest hasher functions.
func NewVersionVectorImmutable[K comparable, T any, S Symbol[S]](keyFunc KeyExtractor[T, K], hasher ItemHasher[T, S]) VersionVectorImmutable[K, T, S] {
	return &versionVectorImmutable[K, T, S]{
		keyFunc: keyFunc,
		hasher:  hasher,
		items:   make(map[K]*VersionedItem[T]),
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
		// XOR out previous version's digest
		currDigest := vv.hasher(*curr)
		newFP = newFP.XOR(currDigest)
	}

	digest := vv.hasher(versionedItem)
	newFP = newFP.XOR(digest)

	newItems[key] = &VersionedItem[T]{
		Item:    versionedItem.Item,
		Version: versionNumber,
	}

	return &versionVectorImmutable[K, T, S]{
		keyFunc:     vv.keyFunc,
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: newFP,
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
	}, true
}

func (vv *versionVectorImmutable[K, T, S]) Fingerprint() S {
	return vv.fingerprint
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
