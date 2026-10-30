package reverseindexstore

import (
	"encoding/binary"
	"io"
	"unsafe"

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

// CryptographicIdentity represents elements that supply a canonical byte or string
// representation intended for cryptographic hashing (e.g., SHA-256) rather than FNV-1a.
type CryptographicIdentity interface {
	CryptographicIdentity() []byte
}

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

// AsDigestSymbols casts a []uint64 slice to []DigestSymbol with zero allocations.
// Safe because DigestSymbol is defined with underlying type uint64 (identical size, alignment, and GC layout).
func AsDigestSymbols(in []uint64) []DigestSymbol {
	if len(in) == 0 {
		return nil
	}
	return unsafe.Slice((*DigestSymbol)(unsafe.Pointer(unsafe.SliceData(in))), len(in))
}

// AsUint64Slice casts a []DigestSymbol slice to []uint64 with zero allocations.
func AsUint64Slice(in []DigestSymbol) []uint64 {
	if len(in) == 0 {
		return nil
	}
	return unsafe.Slice((*uint64)(unsafe.Pointer(unsafe.SliceData(in))), len(in))
}

// ReverseIndexStore defines the standard contract that all data stores must comply with
// in order to participate in set reconciliation. It provides set operations,
// deterministic 64-bit fingerprinting, and O(1) reverse lookup by digest.
type ReverseIndexStore[T any, S Symbol[S]] interface {
	io.Closer

	// Insert adds an element to the store and returns its digest symbol and whether it was newly inserted.
	Insert(elem T) (digest S, newlyAdded bool)

	// Digest returns the deterministic digest symbol for an element according to the store's configured hasher.
	Digest(elem T) S

	// AddElement adds an element to the store. Returns true if the element was newly added.
	AddElement(elem T) bool

	// AddElements adds multiple elements to the store. Returns the count of newly added elements.
	AddElements(elems ...T) int

	// Remove removes an element from the store. Returns true if present and removed.
	Remove(elem T) bool

	// RemoveByDigest removes an element by its digest. Returns true if present and removed.
	RemoveByDigest(digest S) bool

	// Contains retrieves the stored element matching elem's digest.
	// Returns the stored element and true if found, or zero value and false otherwise.
	// Returning (T, bool) enables callers to verify full field equality and guard against hash collisions.
	Contains(elem T) (stored T, found bool)

	// ContainsDigest returns true if an element with the given digest exists in the store.
	ContainsDigest(digest S) bool

	// GetByDigest retrieves an element by its digest in O(1) time.
	GetByDigest(digest S) (elem T, found bool)

	// GetByDigests retrieves multiple elements by their digests in a single operation.
	// Returns a slice containing all found elements and true if all requested digests were present in the store,
	// or false if one or more digests were missing.
	GetByDigests(digests []S) (elems []T, found bool)

	// DigestsCopy returns a newly allocated slice containing a snapshot of all digests currently in the store.
	DigestsCopy() []S

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
