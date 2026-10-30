package versionvector

import (
	"sync"
)

type versionVectorMutable[T any, S Symbol[S]] struct {
	mu          sync.RWMutex
	keyFunc     KeyExtractor[T, S]
	hasher      ItemHasher[T, S]
	items       map[S]*VersionedItem[T]
	fingerprint S
}

// NewVersionVectorMutable creates a thread-safe VersionVectorMutable initialized with key and digest hasher functions.
func NewVersionVectorMutable[T any, S Symbol[S]](keyFunc KeyExtractor[T, S], hasher ItemHasher[T, S]) VersionVectorMutable[T, S] {
	return &versionVectorMutable[T, S]{
		keyFunc: keyFunc,
		hasher:  hasher,
		items:   make(map[S]*VersionedItem[T]),
	}
}

func (vv *versionVectorMutable[T, S]) AddItem(versionedItem VersionedItem[T]) (*VersionedItem[T], bool) {
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

func (vv *versionVectorMutable[T, S]) GetOne(key S) (VersionedItem[T], bool) {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	entry, exists := vv.items[key]
	if !exists {
		var zero VersionedItem[T]
		return zero, false
	}
	return *entry, true
}

func (vv *versionVectorMutable[T, S]) GetMany(keys []S) []VersionedItem[T] {
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

func (vv *versionVectorMutable[T, S]) ContainsKey(key S) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	_, found := vv.items[key]
	return found
}

func (vv *versionVectorMutable[T, S]) ContainsKeyVersion(key S, version uint64) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	entry, found := vv.items[key]
	if !found {
		return false
	}
	return entry.Version == version
}

func (vv *versionVectorMutable[T, S]) Remove(key S) (VersionedItem[T], bool) {
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

func (vv *versionVectorMutable[T, S]) RemoveVersion(key S, version uint64) bool {
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

func (vv *versionVectorMutable[T, S]) Fingerprint() S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return vv.fingerprint
}

func (vv *versionVectorMutable[T, S]) Size() int {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items)
}

func (vv *versionVectorMutable[T, S]) Empty() bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items) == 0
}

func (vv *versionVectorMutable[T, S]) Elements() []VersionedItem[T] {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elems := make([]VersionedItem[T], 0, len(vv.items))
	for _, entry := range vv.items {
		elems = append(elems, *entry)
	}
	return elems
}

func (vv *versionVectorMutable[T, S]) Versions() map[S]uint64 {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	vers := make(map[S]uint64, len(vv.items))
	for k, entry := range vv.items {
		vers[k] = entry.Version
	}
	return vers
}

func (vv *versionVectorMutable[T, S]) DigestsCopy() []S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	digests := make([]S, 0, len(vv.items))
	for _, entry := range vv.items {
		digests = append(digests, vv.hasher(*entry))
	}
	return digests
}

func (vv *versionVectorMutable[T, S]) Clear() {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	vv.items = make(map[S]*VersionedItem[T])
	var zero S
	vv.fingerprint = zero
}
