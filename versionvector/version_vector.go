package versionvector

import (
	"maps"
	"sync"
)

type versionVector[T any, S Symbol[S]] struct {
	mu          sync.RWMutex
	hasher      ItemHasher[T, S]
	items       map[S]VersionedItem[T]
	fingerprint S
}

// NewVersionVector creates a thread-safe VersionVector initialized with an item hasher function.
func NewVersionVector[T any, S Symbol[S]](hasher ItemHasher[T, S]) VersionVector[T, S] {
	return &versionVector[T, S]{
		hasher: hasher,
		items:  make(map[S]VersionedItem[T]),
	}
}

// GetByDigest retrieves an item by its digest in O(1) time.
func (vv *versionVector[T, S]) GetByDigest(digest S) (VersionedItem[T], bool) {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	entry, exists := vv.items[digest]
	if exists {
		return entry, true
	} else {
		var zero VersionedItem[T]
		return zero, false
	}
}

// GetByDigests retrieves multiple items by their digests in a single operation under one read lock.
func (vv *versionVector[T, S]) GetByDigests(digests []S) ([]VersionedItem[T], bool) {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elements := make([]VersionedItem[T], 0, len(digests))
	foundAll := true
	for _, key := range digests {
		entry, exists := vv.items[key]
		if !exists {
			foundAll = false
			continue
		}
		elements = append(elements, entry)
	}
	return elements, foundAll
}

func (vv *versionVector[T, S]) AddItem(item VersionedItem[T]) VersionVector[T, S] {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	digest := vv.hasher(item)
	if _, exists := vv.items[digest]; exists {
		return vv
	}

	newItems := make(map[S]VersionedItem[T], len(vv.items)+1)
	maps.Copy(newItems, vv.items)
	newItems[digest] = item

	return &versionVector[T, S]{
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: vv.fingerprint.XOR(digest),
	}
}

func (vv *versionVector[T, S]) ContainsDigest(digest S) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	_, found := vv.items[digest]
	return found
}

func (vv *versionVector[T, S]) Remove(digest S) (VersionVector[T, S], bool) {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	_, found := vv.items[digest]
	if !found {
		return nil, false
	}

	newItems := make(map[S]VersionedItem[T], len(vv.items)-1)
	maps.Copy(newItems, vv.items)
	delete(newItems, digest)

	return &versionVector[T, S]{
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: vv.fingerprint.XOR(digest),
	}, true
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

func (vv *versionVector[T, S]) Elements() []VersionedItem[T] {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elems := make([]VersionedItem[T], 0, len(vv.items))
	for _, entry := range vv.items {
		elems = append(elems, entry)
	}
	return elems
}

func (vv *versionVector[T, S]) DigestsCopy() []S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	digests := make([]S, 0, len(vv.items))
	for digest := range vv.items {
		digests = append(digests, digest)
	}
	return digests
}
