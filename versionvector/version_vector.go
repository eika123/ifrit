package versionvector

import (
	"sync"
)

type slotEntry[T any, S Symbol[S]] struct {
	item    T
	version uint64
	digest  S
}

type versionVector[T any, S Symbol[S]] struct {
	mu          sync.RWMutex
	keyFunc     KeyExtractor[T, S]
	hasher      ItemHasher[T, S]
	items       map[S]*slotEntry[T, S]
	fingerprint S
}

// NewVersionVector creates a thread-safe VersionVector initialized with key and digest hasher functions.
func NewVersionVector[T any, S Symbol[S]](keyFunc KeyExtractor[T, S], hasher ItemHasher[T, S]) VersionVector[T, S] {
	return &versionVector[T, S]{
		keyFunc: keyFunc,
		hasher:  hasher,
		items:   make(map[S]*slotEntry[T, S]),
	}
}

// GetByDigest retrieves an item by its identity key in O(1) time.
// Note: This method is a pluggability adapter for ReverseIndexStore-compatible reconcilers.
// The parameter 'key' is the slot identity key, NOT the item's hash/fingerprint digest.
func (vv *versionVector[T, S]) GetByDigest(key S) (T, bool) {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	entry, exists := vv.items[key]
	if !exists {
		var zero T
		return zero, false
	}
	return entry.item, true
}

// GetByDigests retrieves multiple items by their identity keys in a single operation under one read lock.
// Acts as a pluggability adapter for ReverseIndexStore-compatible reconcilers.
func (vv *versionVector[T, S]) GetByDigests(keys []S) ([]T, bool) {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elements := make([]T, 0, len(keys))
	foundAll := true
	for _, key := range keys {
		entry, exists := vv.items[key]
		if !exists {
			foundAll = false
			continue
		}
		elements = append(elements, entry.item)
	}
	return elements, foundAll
}

func (vv *versionVector[T, S]) AddItem(item T, versionNumber uint64) bool {
	key := vv.keyFunc(item)

	vv.mu.Lock()
	defer vv.mu.Unlock()

	curr, exists := vv.items[key]
	if exists && versionNumber <= curr.version {
		return false
	}

	if exists {
		// XOR out the previous version's digest
		vv.fingerprint = vv.fingerprint.XOR(curr.digest)
	}

	digest := vv.hasher(key, item, versionNumber)
	vv.fingerprint = vv.fingerprint.XOR(digest)

	vv.items[key] = &slotEntry[T, S]{
		item:    item,
		version: versionNumber,
		digest:  digest,
	}
	return true
}

func (vv *versionVector[T, S]) ContainsKey(key S) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	_, found := vv.items[key]
	return found
}

func (vv *versionVector[T, S]) Remove(key S) bool {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	entry, found := vv.items[key]
	if !found {
		return false
	}

	vv.fingerprint = vv.fingerprint.XOR(entry.digest)
	delete(vv.items, key)
	return true
}

func (vv *versionVector[T, S]) Fingerprint() S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return vv.fingerprint
}

func (vv *versionVector[T, S]) Size() int {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items)
}

func (vv *versionVector[T, S]) Empty() bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items) == 0
}

func (vv *versionVector[T, S]) Elements() []T {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elems := make([]T, 0, len(vv.items))
	for _, entry := range vv.items {
		elems = append(elems, entry.item)
	}
	return elems
}

func (vv *versionVector[T, S]) Versions() map[S]uint64 {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	vers := make(map[S]uint64, len(vv.items))
	for k, entry := range vv.items {
		vers[k] = entry.version
	}
	return vers
}

func (vv *versionVector[T, S]) DigestsCopy() []S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	digests := make([]S, 0, len(vv.items))
	for _, entry := range vv.items {
		digests = append(digests, entry.digest)
	}
	return digests
}

func (vv *versionVector[T, S]) Clear() {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	vv.items = make(map[S]*slotEntry[T, S])
	var zero S
	vv.fingerprint = zero
}
