package digestmaps

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

// VersionedItem wraps an arbitrary value T with a monotonically ordered uint64 version.
type VersionedItem[T any] struct {
	Item    T
	Version uint64
}

// ItemHasher computes the combined digest symbol of the item and its version.
type ItemHasher[T any, S Symbol[S]] func(item VersionedItem[T]) S

// VersionVectorImmutable defines the generic interface for an immutable version vector
// with incremental 64-bit commutative XOR fingerprinting.
// Key type K is decoupled from Symbol type S, allowing arbitrary comparable identity keys (e.g. string, struct).
// Any mutation returns a completely new VersionVectorImmutable instance.
type VersionVectorImmutable[K comparable, T any, S Symbol[S]] interface {
	// AddItem applies an item with a given version number.
	// Returns a new VersionVectorImmutable and true if the item was added or upgraded (new version > current version).
	// Returns the unmodified instance and false if an existing entry has an equal or newer version.
	AddItem(item VersionedItem[T]) (VersionVectorImmutable[K, T, S], bool)

	GetOne(key K) (item VersionedItem[T], found bool)

	GetMany(keys []K) (items []VersionedItem[T])

	// ContainsKey reports whether an entry for key exists.
	ContainsKey(key K) bool

	// ContainsKeyVersion reports whether an entry for key exists with the specified version.
	ContainsKeyVersion(key K, version uint64) bool

	// Remove evicts an item by key, subtracting its digest from the fingerprint.
	// Returns a new VersionVectorImmutable and true if present; otherwise returns unmodified instance and false.
	Remove(key K) (VersionVectorImmutable[K, T, S], bool)

	RemoveVersion(key K, version uint64) (VersionVectorImmutable[K, T, S], bool)

	// Fingerprint returns the current cumulative XOR fingerprint in O(1).
	Fingerprint() S

	// Size returns the count of active identity slots.
	Size() int

	// Empty reports whether the version vector contains no items.
	Empty() bool

	// Elements returns all current items as a slice.
	Elements() []VersionedItem[T]

	// Versions returns a map of all keys and their latest version numbers.
	Versions() map[K]uint64

	// DigestsCopy returns a slice of all digests currently contributing to the fingerprint.
	DigestsCopy() []S
}

// KeyExtractor extracts the identity key from an item (excluding the version number).
type KeyExtractor[T any, K comparable] func(item T) K

// VersionVectorMutable defines the generic interface for an identity-keyed version vector
// with monotonically increasing versions and incremental 64-bit commutative XOR fingerprinting.
// Key type K is decoupled from Symbol type S, allowing arbitrary comparable identity keys (e.g. string, struct).
// Importantly, when running e.g GetOne, GetMany, Elements or Remove, one must check
// the version of the item returned as the hash does not include the version.
type VersionVectorMutable[K comparable, T any, S Symbol[S]] interface {
	// AddItem applies an item with a given version number.
	// Returns true if the item was added or upgraded (new version > current version).
	// Returns false if an existing entry has an equal or newer version.
	AddItem(item VersionedItem[T]) (*VersionedItem[T], bool)

	GetOne(key K) (item VersionedItem[T], found bool)

	GetMany(keys []K) (items []VersionedItem[T])

	// ContainsKey reports whether an entry for key exists.
	ContainsKey(key K) bool

	// ContainsKeyVersion reports whether an entry for key exists with the specified version.
	ContainsKeyVersion(key K, version uint64) bool

	// Remove evicts an item by key, subtracting its digest from the fingerprint.
	// Returns true if an item was present and removed.
	Remove(key K) (VersionedItem[T], bool)

	RemoveVersion(key K, version uint64) bool

	// Fingerprint returns the current cumulative XOR fingerprint in O(1).
	Fingerprint() S

	// Size returns the count of active identity slots.
	Size() int

	// Empty reports whether the version vector contains no items.
	Empty() bool

	// Elements returns all current items as a slice.
	Elements() []VersionedItem[T]

	// Versions returns a map of all keys and their latest version numbers.
	Versions() map[K]uint64

	// DigestsCopy returns a slice of all digests currently contributing to the fingerprint.
	DigestsCopy() []S

	// Clear removes all entries and resets the fingerprint to zero.
	Clear()
}
