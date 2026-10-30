package versionvector

import (
	"sync"
)

type versionVectorMutable[K comparable, T any, S Symbol[S]] struct {
	mu          sync.RWMutex
	keyFunc     KeyExtractor[T, K]
	hasher      ItemHasher[T, S]
	items       map[K]*VersionedItem[T]
	fingerprint S
}

// NewVersionVectorMutable creates a thread-safe VersionVectorMutable initialized with key and digest hasher functions.
func NewVersionVectorMutable[K comparable, T any, S Symbol[S]](keyFunc KeyExtractor[T, K], hasher ItemHasher[T, S]) VersionVectorMutable[K, T, S] {
	return &versionVectorMutable[K, T, S]{
		keyFunc: keyFunc,
		hasher:  hasher,
		items:   make(map[K]*VersionedItem[T]),
	}
}

func (vv *versionVectorMutable[K, T, S]) AddItem(versionedItem VersionedItem[T]) (*VersionedItem[T], bool) {
	key := vv.keyFunc(versionedItem.Item)
	versionNumber := versionedItem.Version

	vv.mu.Lock()
	defer vv.mu.Unlock()

	curr, exists := vv.items[key]
	if exists && versionNumber <= curr.Version {
		return nil, false
	}

	if exists {
		// XOR out the previous version's digest
		currDigest := vv.hasher(*curr)
		vv.fingerprint = vv.fingerprint.XOR(currDigest)
	}

	digest := vv.hasher(versionedItem)
	vv.fingerprint = vv.fingerprint.XOR(digest)

	itemCopy := &VersionedItem[T]{
		Item:    versionedItem.Item,
		Version: versionNumber,
	}
	vv.items[key] = itemCopy
	return itemCopy, true
}

func (vv *versionVectorMutable[K, T, S]) GetOne(key K) (VersionedItem[T], bool) {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	entry, exists := vv.items[key]
	if !exists {
		var zero VersionedItem[T]
		return zero, false
	}
	return *entry, true
}

func (vv *versionVectorMutable[K, T, S]) GetMany(keys []K) []VersionedItem[T] {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

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

func (vv *versionVectorMutable[K, T, S]) ContainsKey(key K) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	_, found := vv.items[key]
	return found
}

func (vv *versionVectorMutable[K, T, S]) ContainsKeyVersion(key K, version uint64) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	entry, found := vv.items[key]
	if !found {
		return false
	}
	return entry.Version == version
}

func (vv *versionVectorMutable[K, T, S]) Remove(key K) (VersionedItem[T], bool) {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	entry, found := vv.items[key]
	if !found {
		var zero VersionedItem[T]
		return zero, false
	}

	digest := vv.hasher(*entry)
	vv.fingerprint = vv.fingerprint.XOR(digest)
	delete(vv.items, key)
	return *entry, true
}

func (vv *versionVectorMutable[K, T, S]) RemoveVersion(key K, version uint64) bool {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	entry, found := vv.items[key]
	if !found || entry.Version != version {
		return false
	}

	digest := vv.hasher(*entry)
	vv.fingerprint = vv.fingerprint.XOR(digest)
	delete(vv.items, key)
	return true
}

func (vv *versionVectorMutable[K, T, S]) Fingerprint() S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return vv.fingerprint
}

func (vv *versionVectorMutable[K, T, S]) Size() int {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items)
}

func (vv *versionVectorMutable[K, T, S]) Empty() bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items) == 0
}

func (vv *versionVectorMutable[K, T, S]) Elements() []VersionedItem[T] {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elems := make([]VersionedItem[T], 0, len(vv.items))
	for _, entry := range vv.items {
		elems = append(elems, *entry)
	}
	return elems
}

func (vv *versionVectorMutable[K, T, S]) Versions() map[K]uint64 {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	vers := make(map[K]uint64, len(vv.items))
	for k, entry := range vv.items {
		vers[k] = entry.Version
	}
	return vers
}

func (vv *versionVectorMutable[K, T, S]) DigestsCopy() []S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	digests := make([]S, 0, len(vv.items))
	for _, entry := range vv.items {
		digests = append(digests, vv.hasher(*entry))
	}
	return digests
}

func (vv *versionVectorMutable[K, T, S]) Clear() {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	vv.items = make(map[K]*VersionedItem[T])
	var zero S
	vv.fingerprint = zero
}
