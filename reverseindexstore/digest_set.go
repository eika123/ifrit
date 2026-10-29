package reverseindexstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
)

// Hasher computes a deterministic, cross-platform digest for an element.
type Hasher[T any, S Symbol[S]] func(item T) S

// DefaultHasher returns a deterministic 64-bit FNV-1a hasher for type T.
// If item implements an interface with Digest() uint64 or ID() string, it uses that directly.
// Otherwise, it falls back to hashing the item's canonical JSON representation.
func DefaultHasher[T any]() Hasher[T, DigestSymbol] {
	return func(item T) DigestSymbol {
		// If item is already a DigestSymbol, return directly
		if ds, ok := any(item).(DigestSymbol); ok {
			return ds
		}
		// Custom Digest() uint64 interface
		if d, ok := any(item).(interface{ Digest() uint64 }); ok {
			return DigestSymbol(d.Digest())
		}
		// Custom Digest() DigestSymbol interface
		if d, ok := any(item).(interface{ Digest() DigestSymbol }); ok {
			return d.Digest()
		}
		// Custom ID() string interface
		if id, ok := any(item).(interface{ ID() string }); ok {
			h := fnv.New64a()
			_, _ = h.Write([]byte(id.ID()))
			return DigestSymbol(h.Sum64())
		}
		// Native string
		if s, ok := any(item).(string); ok {
			h := fnv.New64a()
			_, _ = h.Write([]byte(s))
			return DigestSymbol(h.Sum64())
		}
		// Fallback to deterministic JSON serialization
		b, err := json.Marshal(item)
		if err != nil {
			b = []byte(fmt.Sprintf("%v", item))
		}
		h := fnv.New64a()
		_, _ = h.Write(b)
		return DigestSymbol(h.Sum64())
	}
}

// digestSet represents a reverse-index hash set that maps deterministic digests
// to items, enabling O(1) reverse lookup (GetByDigest) for set reconciliation protocols.
type digestSet[T any, S Symbol[S]] struct {
	mu            sync.RWMutex
	itemsByDigest map[S]T
	hasher        Hasher[T, S]

	// The fingerprint is a commutative XOR sum of all item digests: an incremental hash of the set.
	// This also provides a digest of the symmetric set difference: d_AB = dA ^ dB.
	fingerprint S
}

var ErrNilHasher = errors.New("hasher cannot be nil")

// NewDigestSet creates a new empty ReverseIndexStore backed by an in-memory digest set.
// An explicit, non-nil Hasher must be provided to compute element digests.
func NewDigestSet[T any, S Symbol[S]](hasher Hasher[T, S]) (ReverseIndexStore[T, S], error) {
	if hasher == nil {
		return nil, ErrNilHasher
	}
	return &digestSet[T, S]{
		itemsByDigest: make(map[S]T),
		hasher:        hasher,
	}, nil
}

// Insert adds an element to the set.
// Returns the element's digest of type S and true if the element was newly inserted.
func (s *digestSet[T, S]) Insert(item T) (S, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hasher == nil {
		panic(ErrNilHasher)
	}
	if s.itemsByDigest == nil {
		s.itemsByDigest = make(map[S]T)
	}

	d := s.hasher(item)

	if _, exists := s.itemsByDigest[d]; exists {
		return d, false
	}

	s.itemsByDigest[d] = item
	s.fingerprint = s.fingerprint.XOR(d)
	return d, true
}

// Digest computes and returns the deterministic digest symbol for the given item.
func (s *digestSet[T, S]) Digest(item T) S {
	if s.hasher == nil {
		panic(ErrNilHasher)
	}
	return s.hasher(item)
}

// AddElement inserts an element into the set and returns true if newly added.
func (s *digestSet[T, S]) AddElement(elem T) bool {
	_, inserted := s.Insert(elem)
	return inserted
}

// InsertSlice adds multiple elements to the set.
// Returns the count of newly inserted elements.
func (s *digestSet[T, S]) InsertSlice(items []T) int {
	if len(items) == 0 {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hasher == nil {
		panic(ErrNilHasher)
	}
	if s.itemsByDigest == nil {
		s.itemsByDigest = make(map[S]T, len(items))
	}

	added := 0
	for _, item := range items {
		d := s.hasher(item)
		if _, exists := s.itemsByDigest[d]; !exists {
			s.itemsByDigest[d] = item
			s.fingerprint = s.fingerprint.XOR(d)
			added++
		}
	}

	return added
}

// AddElements inserts multiple elements into the set and returns the count of newly added elements.
func (s *digestSet[T, S]) AddElements(elems ...T) int {
	return s.InsertSlice(elems)
}

// Remove removes an element from the set.
// Returns true if the element was present and removed.
func (s *digestSet[T, S]) Remove(item T) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hasher == nil {
		panic(ErrNilHasher)
	}
	if s.itemsByDigest == nil {
		return false
	}

	d := s.hasher(item)

	if _, exists := s.itemsByDigest[d]; !exists {
		return false
	}

	delete(s.itemsByDigest, d)
	s.fingerprint = s.fingerprint.XOR(d)
	return true
}

// RemoveByDigest removes an element by its digest.
// Returns true if the element was present and removed.
func (s *digestSet[T, S]) RemoveByDigest(digest S) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.itemsByDigest[digest]; !exists {
		return false
	}

	delete(s.itemsByDigest, digest)
	s.fingerprint = s.fingerprint.XOR(digest)
	return true
}

// Contains retrieves the stored element matching item's digest.
// Returns the stored element and true if found, or zero value and false otherwise.
func (s *digestSet[T, S]) Contains(item T) (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.hasher == nil {
		panic(ErrNilHasher)
	}
	if s.itemsByDigest == nil {
		var zero T
		return zero, false
	}

	d := s.hasher(item)
	stored, exists := s.itemsByDigest[d]
	return stored, exists
}

// ContainsDigest returns true if an item with the given digest exists in the set.
func (s *digestSet[T, S]) ContainsDigest(digest S) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.itemsByDigest[digest]
	return exists
}

// GetByDigest returns the item associated with the digest in O(1) time.
func (s *digestSet[T, S]) GetByDigest(digest S) (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, exists := s.itemsByDigest[digest]
	return item, exists
}

// GetByDigests retrieves multiple elements by their digests in a single operation under one read lock.
// Returns a slice containing all found elements and true if all requested digests were found,
// or false if one or more digests were missing.
func (s *digestSet[T, S]) GetByDigests(digests []S) ([]T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(digests) == 0 {
		return nil, true
	}

	elems := make([]T, 0, len(digests))
	allFound := true
	for _, d := range digests {
		if item, exists := s.itemsByDigest[d]; exists {
			elems = append(elems, item)
		} else {
			allFound = false
		}
	}
	return elems, allFound
}

// Size returns the total count of items in the set.
func (s *digestSet[T, S]) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.itemsByDigest)
}

// Empty returns true if the set contains no items.
func (s *digestSet[T, S]) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.itemsByDigest) == 0
}

// Fingerprint returns the XOR sum of all digests in the set.
func (s *digestSet[T, S]) Fingerprint() S {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.fingerprint
}

// DigestsCopy returns a slice containing the digests of all elements in the set.
func (s *digestSet[T, S]) DigestsCopy() []S {
	s.mu.RLock()
	defer s.mu.RUnlock()

	digests := make([]S, 0, len(s.itemsByDigest))
	for d := range s.itemsByDigest {
		digests = append(digests, d)
	}
	return digests
}

// Slice returns all elements currently in the set as a slice.
func (s *digestSet[T, S]) Slice() []T {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]T, 0, len(s.itemsByDigest))
	for _, item := range s.itemsByDigest {
		items = append(items, item)
	}
	return items
}

// Elements returns all elements currently in the set as a slice.
func (s *digestSet[T, S]) Elements() []T {
	return s.Slice()
}

// Copy creates an independent, deep clone of the digestSet.
func (s *digestSet[T, S]) Copy() ReverseIndexStore[T, S] {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := &digestSet[T, S]{
		itemsByDigest: make(map[S]T, len(s.itemsByDigest)),
		hasher:        s.hasher,
		fingerprint:   s.fingerprint,
	}

	for d, item := range s.itemsByDigest {
		cp.itemsByDigest[d] = item
	}

	return cp
}

// Close satisfies ReverseIndexStore (and io.Closer). For in-memory digestSet,
// this is a no-op returning nil.
func (s *digestSet[T, S]) Close() error {
	return nil
}

// MarshalJSON serializes the set as a JSON array of elements.
func (s *digestSet[T, S]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Slice())
}

// UnmarshalJSON populates the set from a JSON array of elements.
func (s *digestSet[T, S]) UnmarshalJSON(data []byte) error {
	var items []T
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hasher == nil {
		return ErrNilHasher
	}

	if s.itemsByDigest == nil {
		s.itemsByDigest = make(map[S]T, len(items))
	}

	for _, item := range items {
		d := s.hasher(item)
		if _, exists := s.itemsByDigest[d]; !exists {
			s.itemsByDigest[d] = item
			s.fingerprint = s.fingerprint.XOR(d)
		}
	}

	return nil
}
