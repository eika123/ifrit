package core

// ReverseIndexStore defines the standard contract that all data stores must comply to
// in order to participate in set reconciliation. It provides set operations,
// deterministic 64-bit fingerprinting, and O(1) reverse lookup by digest.
type ReverseIndexStore[T any] interface {
	// AddElement adds an element to the store. Returns true if the element was newly added.
	AddElement(elem T) bool

	// AddElements adds multiple elements to the store. Returns the count of newly added elements.
	AddElements(elems ...T) int

	// Contains returns true if the element exists in the store.
	Contains(elem T) bool

	// ContainsDigest returns true if an element with the given 64-bit digest exists in the store.
	ContainsDigest(digest uint64) bool

	// GetByDigest retrieves an element by its 64-bit digest in O(1) time.
	// Essential for set reconciliation when a peer requests missing elements by digest.
	GetByDigest(digest uint64) (elem T, found bool)

	// Digests returns a slice of all 64-bit digests currently in the store.
	Digests() []uint64

	// Fingerprint returns the 64-bit commutative XOR sum of all element digests in the store.
	// Used for O(1) symmetric difference detection: d_AB = d_A ^ d_B.
	Fingerprint() uint64

	// Size returns the total number of elements in the store.
	Size() int

	// Empty returns true if the store contains no elements.
	Empty() bool

	// Elements returns all elements currently in the store as a slice.
	// The slice shoudl be a deep copy
	Elements() []T

	// Copy returns an independent, deep copy of the set at this point in time.
	Copy() ReverseIndexStore[T]

	// Close finalizes the store, flushing any pending data or releasing resources.
	// In-memory stores may safely stub this as a no-op returning nil.
	Close() error
}
