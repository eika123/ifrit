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
type VersionVector[T any, S Symbol[S]] interface {
	// AddItem returns a new VersionVector containing the added or updated versioned item.
	AddItem(item VersionedItem[T]) VersionVector[T, S]

	// GetByDigest retrieves an item by its digest in O(1) time.
	GetByDigest(digest S) (item VersionedItem[T], found bool)

	// GetByDigests retrieves multiple items by their digests in a single operation.
	// Returns a slice of all found items and true if every requested digest was found,
	// or false if one or more digests were missing.
	GetByDigests(digests []S) (items []VersionedItem[T], found bool)

	// ContainsDigest reports whether an item with the given digest exists.
	ContainsDigest(digest S) bool

	// Remove evicts an item by its digest, returning a new VersionVector and true if present.
	Remove(digest S) (VersionVector[T, S], bool)

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
