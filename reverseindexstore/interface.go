package reverseindexstore

import (
	"encoding/binary"
	"io"

	"github.com/dchest/siphash"
	"github.com/yangl1996/riblt"
)

// Symbol defines the operations required for a digest symbol in set reconciliation.
type Symbol[S any] interface {
	comparable
	riblt.Symbol[S] // XOR(other S) S and Hash() uint64
}

// DigestSymbol represents a concrete 64-bit digest symbol satisfying Symbol[DigestSymbol].
type DigestSymbol uint64

// XOR implements riblt.Symbol[DigestSymbol].
func (d DigestSymbol) XOR(other DigestSymbol) DigestSymbol {
	return d ^ other
}

// Hash implements riblt.Symbol[DigestSymbol] (must be non-homomorphic to XOR).
func (d DigestSymbol) Hash() uint64 {
	buf := [8]byte{}
	binary.LittleEndian.PutUint64(buf[:], uint64(d))
	return siphash.Hash(50683, 19283, buf[:])
}

// ReverseIndexStore defines the standard contract that all data stores must comply with
// in order to participate in set reconciliation. It provides set operations,
// deterministic 64-bit fingerprinting, and O(1) reverse lookup by digest.
type ReverseIndexStore[T any, S Symbol[S]] interface {
	io.Closer

	// AddElement adds an element to the store. Returns true if the element was newly added.
	AddElement(elem T) bool

	// AddElements adds multiple elements to the store. Returns the count of newly added elements.
	AddElements(elems ...T) int

	// Remove removes an element from the store. Returns true if present and removed.
	Remove(elem T) bool

	// RemoveByDigest removes an element by its digest. Returns true if present and removed.
	RemoveByDigest(digest S) bool

	// Contains returns true if the element exists in the store.
	Contains(elem T) bool

	// ContainsDigest returns true if an element with the given digest exists in the store.
	ContainsDigest(digest S) bool

	// GetByDigest retrieves an element by its digest in O(1) time.
	GetByDigest(digest S) (elem T, found bool)

	// Digests returns a slice of all digests currently in the store.
	Digests() []S

	// Fingerprint returns the commutative XOR sum of all element digests in the store.
	Fingerprint() S

	// Size returns the total number of elements in the store.
	Size() int

	// Empty returns true if the store contains no elements.
	Empty() bool

	// Elements returns all elements currently in the store as a slice.
	Elements() []T

	// Copy returns an independent, deep copy of the set at this point in time.
	Copy() ReverseIndexStore[T, S]
}
