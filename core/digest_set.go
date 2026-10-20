package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
)

// Hasher computes a deterministic, cross-platform 64-bit digest for an element.
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

// DigestSet represents a reverse-index hash set that maps deterministic 64-bit digests
// to items, enabling O(1) reverse lookup (GetByDigest) for set reconciliation protocols.
type digestSet[T any, S Symbol[S]] struct {
	mu            sync.RWMutex
	itemsByDigest map[S]T
	hasher        Hasher[T, S]

	// The fingerprint is a commutative XOR sum of all item digests, so an incremental hash of the set.
	// This also provides a digest of the symmetric set difference, as in the example below.

	// Example: NodeA has set A={h1,h2,h3, h4} and nodeB has set B={h3, h4, h5, h6}.
	// The digest A sends node B is dA = h1 ^ h2 ^ h3 ^ h4.
	// B's digest is dB = h3 ^ h4 ^ h5 ^ h6, and it can calulate d_AB = dA ^ dB = h1 ^ h2 ^ h5 ^ h6,
	// which is the fingerprint of the symmetric difference!
	// Piggybacking this back to A, both nodes will know when the entire symmetric difference has been
	// fully exchanged.
	//
	// Exactly how to decide what digests to exchange is left to the set reconciliation protocols to solve.
	fingerprint S
}

var ErrNilHasher = errors.New("hasher cannot be nil")

// newDigestSet creates an in-memory digestSet pointer for internal package use.
// An explicit, non-nil Hasher must be provided to compute element digests.
// Returns ErrNilHasher if hasher is nil. Callers MUST check and handle this error;
// attempting to ignore the error or invoke mutation/lookup methods on an uninitialized
// or nil-hasher set will result in a panic (ErrNilHasher).
func newDigestSet[T any, S Symbol[S]](hasher Hasher[T, S]) (*digestSet[T, S], error) {
	if hasher == nil {
		return nil, ErrNilHasher
	}
	return &digestSet[T, S]{
		itemsByDigest: make(map[S]T),
		hasher:        hasher,
	}, nil
}

// NewDigestSet creates a new empty ReverseIndexStore backed by an in-memory digest set.
// An explicit, non-nil Hasher must be provided to compute element digests.
// Returns ErrNilHasher if hasher is nil. Callers MUST check and handle this error;
// attempting to ignore the error or invoke mutation/lookup methods on an uninitialized
// or nil-hasher set will result in a panic (ErrNilHasher).
func NewDigestSet[T any, S Symbol[S]](hasher Hasher[T, S]) (ReverseIndexStore[T, S], error) {
	return newDigestSet(hasher)
}

// Insert adds an element to the set.
// Returns the element's digest of type S and true if the element was new and inserted.
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

// AddElement inserts an element into the set and returns true if newly added.
// Satisfies ReverseIndexStore[T].
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
// Satisfies ReverseIndexStore[T].
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

// RemoveByDigest removes an element by its 64-bit digest.
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

// Contains returns true if the element is present in the set.
func (s *digestSet[T, S]) Contains(item T) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.hasher == nil {
		panic(ErrNilHasher)
	}
	if s.itemsByDigest == nil {
		return false
	}

	d := s.hasher(item)
	_, exists := s.itemsByDigest[d]
	return exists
}

// ContainsDigest returns true if an item with the given 64-bit digest exists in the set.
func (s *digestSet[T, S]) ContainsDigest(digest S) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.itemsByDigest[digest]
	return exists
}

// GetByDigest returns the item associated with the 64-bit digest in O(1) time.
// This is the core operation used during set reconciliation to retrieve requested missing items.
func (s *digestSet[T, S]) GetByDigest(digest S) (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, exists := s.itemsByDigest[digest]
	return item, exists
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

// Fingerprint returns the 64-bit XOR sum of all digests in the set.
// Two nodes have identical sets if and only if their fingerprints match (with high probability).
func (s *digestSet[T, S]) Fingerprint() S {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.fingerprint
}

// Digests returns a slice containing the 64-bit digests of all elements in the set.
func (s *digestSet[T, S]) Digests() []S {
	s.mu.RLock()
	defer s.mu.RUnlock()

	digests := make([]S, 0, len(s.itemsByDigest))
	for d := range s.itemsByDigest {
		digests = append(digests, d)
	}
	return digests
}

// Slice returns all elements currently in the set as a slice.
// The items are deep copied, so mutations on the returned slice will not
// affect the original set.
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
// Satisfies ReverseIndexStore[T].
func (s *digestSet[T, S]) Elements() []T {
	return s.Slice()
}

// Copy creates an independent, deep clone of the DigestSet.
// Mutations on the returned copy will not affect the original set.
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

// Close satisfies ReverseIndexStore (and io.Closer). For in-memory DigestSet,
// this is a no-op returning nil.
func (s *digestSet[T, S]) Close() error {
	return nil
}

// MarshalJSON serializes the set as a JSON array of elements.
func (s *digestSet[T, S]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Slice())
}

// UnmarshalJSON populates the set from a JSON array of elements.
// The receiver must already be initialized with a non-nil hasher; returns ErrNilHasher otherwise.
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
