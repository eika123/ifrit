package versionvector

import (
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

// Symbol is aliased from reverseindexstore.Symbol.
type Symbol[S any] = revIdxStore.Symbol[S]

// DigestSymbol is aliased from reverseindexstore.DigestSymbol.
type DigestSymbol = revIdxStore.DigestSymbol
type VersionedItem[T any] struct {
	Item    T
	Version uint64
}

// ItemHasher computes the combined digest symbol of the item and its version.
type ItemHasher[T any, S Symbol[S]] func(item VersionedItem[T]) S

// VersionVector defines the generic interface for an immutable version vector
// with incremental 64-bit commutative XOR fingerprinting.
// Any mutation returns a completely new VersionVector instance.
type VersionVectorImmutable[T any, S Symbol[S]] interface {
	// AddItem returns a new VersionVector containing the added or updated versioned item.
	AddItem(item VersionedItem[T]) VersionVectorImmutable[T, S]

	// GetByDigest retrieves an item by its digest in O(1) time.
	GetByDigest(digest S) (item VersionedItem[T], found bool)

	// GetByDigests retrieves multiple items by their digests in a single operation.
	// Returns a slice of all found items and true if every requested digest was found,
	// or false if one or more digests were missing.
	GetByDigests(digests []S) (items []VersionedItem[T], found bool)

	// ContainsDigest reports whether an item with the given digest exists.
	ContainsDigest(digest S) bool

	// Remove evicts an item by its digest, returning a new VersionVector and true if present.
	Remove(digest S) (VersionVectorImmutable[T, S], bool)

	// Fingerprint returns the current cumulative XOR fingerprint in O(1).
	Fingerprint() S

	// Size returns the count of active items.
	Size() int

	// Empty reports whether the version vector contains no items.
	Empty() bool

	// Elements returns all current items as a slice.
	Elements() []VersionedItem[T]

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
