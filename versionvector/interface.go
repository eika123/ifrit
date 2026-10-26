package versionvector

import (
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

// Symbol is aliased from reverseindexstore.Symbol.
type Symbol[S any] = revIdxStore.Symbol[S]

// DigestSymbol is aliased from reverseindexstore.DigestSymbol.
type DigestSymbol = revIdxStore.DigestSymbol

// KeyExtractor extracts the identity key from an item (excluding the version number).
type KeyExtractor[T any, S comparable] func(item T) S

// ItemHasher computes the combined digest symbol of the key, item, and version number.
type ItemHasher[T any, S Symbol[S]] func(key S, item T, version uint64) S

// VersionVector defines the generic interface for an identity-keyed monotonic version vector
// with incremental 64-bit commutative XOR fingerprinting.
type VersionVector[T any, S Symbol[S]] interface {
	// AddItem applies an item with a given version number.
	// Returns true if the item was added or upgraded (new version > current version).
	// Returns false if an existing entry has an equal or newer version.
	AddItem(item T, versionNumber uint64) bool

	// Get retrieves the current item and version for a given key.
	Get(key S) (item T, version uint64, found bool)

	// GetByDigest retrieves an item by its digest in O(1) time.
	GetByDigest(digest S) (item T, found bool)

	// GetByDigests retrieves multiple items by their digests in a single operation.
	// Returns a slice of all found items and true if every requested digest was found,
	// or false if one or more digests were missing.
	GetByDigests(digests []S) (items []T, found bool)

	// ContainsKey reports whether an entry for key exists.
	ContainsKey(key S) bool

	// Remove evicts an item by key, subtracting its digest from the fingerprint.
	// Returns true if an item was present and removed.
	Remove(key S) bool

	// Fingerprint returns the current cumulative XOR fingerprint in O(1).
	Fingerprint() S

	// Size returns the count of active identity slots.
	Size() int

	// Empty reports whether the version vector contains no items.
	Empty() bool

	// Elements returns all current items as a slice.
	Elements() []T

	// Versions returns a map of all keys and their latest version numbers.
	Versions() map[S]uint64

	// DigestsCopy returns a slice of all digests currently contributing to the fingerprint.
	DigestsCopy() []S

	// Clear removes all entries and resets the fingerprint to zero.
	Clear()
}
