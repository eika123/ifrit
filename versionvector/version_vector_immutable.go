package versionvector

import (
	"maps"
	"sync"
)

type versionVectorImmutable[T any, S Symbol[S]] struct {
	mu          sync.RWMutex
	hasher      ItemHasher[T, S]
	items       map[S]VersionedItem[T]
	fingerprint S
}

// NewVersionVector creates a thread-safe VersionVector initialized with an item hasher function.
func NewVersionVector[T any, S Symbol[S]](hasher ItemHasher[T, S]) VersionVectorImmutable[T, S] {
	return &versionVectorImmutable[T, S]{
		hasher: hasher,
		items:  make(map[S]VersionedItem[T]),
	}
}

// GetByDigest retrieves an item by its digest in O(1) time.
func (vv *versionVectorImmutable[T, S]) GetByDigest(digest S) (VersionedItem[T], bool) {
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
func (vv *versionVectorImmutable[T, S]) GetByDigests(digests []S) ([]VersionedItem[T], bool) {
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

func (vv *versionVectorImmutable[T, S]) AddItem(item VersionedItem[T]) VersionVectorImmutable[T, S] {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	digest := vv.hasher(item)
	if _, exists := vv.items[digest]; exists {
		return vv
	}

	newItems := make(map[S]VersionedItem[T], len(vv.items)+1)
	maps.Copy(newItems, vv.items)
	newItems[digest] = item

	return &versionVectorImmutable[T, S]{
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: vv.fingerprint.XOR(digest),
	}
}

func (vv *versionVectorImmutable[T, S]) ContainsDigest(digest S) bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	_, found := vv.items[digest]
	return found
}

func (vv *versionVectorImmutable[T, S]) Remove(digest S) (VersionVectorImmutable[T, S], bool) {
	vv.mu.Lock()
	defer vv.mu.Unlock()

	_, found := vv.items[digest]
	if !found {
		return nil, false
	}

	newItems := make(map[S]VersionedItem[T], len(vv.items)-1)
	maps.Copy(newItems, vv.items)
	delete(newItems, digest)

	return &versionVectorImmutable[T, S]{
		hasher:      vv.hasher,
		items:       newItems,
		fingerprint: vv.fingerprint.XOR(digest),
	}, true
}

func (vv *versionVectorImmutable[T, S]) Fingerprint() S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return vv.fingerprint
}

func (vv *versionVectorImmutable[T, S]) Size() int {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items)
}

func (vv *versionVectorImmutable[T, S]) Empty() bool {
	vv.mu.RLock()
	defer vv.mu.RUnlock()
	return len(vv.items) == 0
}

func (vv *versionVectorImmutable[T, S]) Elements() []VersionedItem[T] {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	elems := make([]VersionedItem[T], 0, len(vv.items))
	for _, entry := range vv.items {
		elems = append(elems, entry)
	}
	return elems
}

func (vv *versionVectorImmutable[T, S]) DigestsCopy() []S {
	vv.mu.RLock()
	defer vv.mu.RUnlock()

	digests := make([]S, 0, len(vv.items))
	for digest := range vv.items {
		digests = append(digests, digest)
	}
	return digests
}
