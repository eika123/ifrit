package core

import (
	"sync"

	"github.com/yangl1996/riblt"
)

type Symbol[S any] interface {
	comparable
	riblt.Symbol[S] // XOR(other S) S and Hash() uint64
}

// ReverseIndexStore defines the standard contract that all data stores must comply to
// in order to participate in set reconciliation. It provides set operations,
// deterministic 64-bit fingerprinting, and O(1) reverse lookup by digest.
type ReverseIndexStore[T any, S Symbol[S]] interface {
	// AddElement adds an element to the store. Returns true if the element was newly added.
	AddElement(elem T) bool

	// AddElements adds multiple elements to the store. Returns the count of newly added elements.
	AddElements(elems ...T) int

	// Contains returns true if the element exists in the store.
	Contains(elem T) bool

	// ContainsDigest returns true if an element with the given 64-bit digest exists in the store.
	ContainsDigest(digest S) bool

	// GetByDigest retrieves an element by its 64-bit digest in O(1) time.
	// Essential for set reconciliation when a peer requests missing elements by digest.
	GetByDigest(digest S) (elem T, found bool)

	// Digests returns a slice of all 64-bit digests currently in the store.
	Digests() []S

	// Fingerprint returns the 64-bit commutative XOR sum of all element digests in the store.
	// Used for O(1) symmetric difference detection: d_AB = d_A ^ d_B.
	Fingerprint() S

	// Size returns the total number of elements in the store.
	Size() int

	// Empty returns true if the store contains no elements.
	Empty() bool

	// Elements returns all elements currently in the store as a slice.
	// The slice shoudl be a deep copy
	Elements() []T

	// Copy returns an independent, deep copy of the set at this point in time.
	Copy() ReverseIndexStore[T, S]

	// Close finalizes the store, flushing any pending data or releasing resources.
	// In-memory stores may safely stub this as a no-op returning nil.
	Close() error
}

type ReconcilerSession[T, S any] interface {
	ProcessIncomingMessage(msg []byte) error
	GenerateNextMessage() ([]byte, error)

	Done() bool
	RemoteDigests() []S // Elements the peer has that we need to fetch
	LocalDigests() []S  // Elements we have that the peer is missing
}

// SessionFactory creates a new reconciliation session backed by a store snapshot/view
type SessionFactory[T any, S Symbol[S]] interface {
	NewSession(store ReverseIndexStore[T, S]) ReconcilerSession[T, S]
}

type reconcilerGossipSet[T any, S Symbol[S]] struct {
	ReverseIndexStore[T, S]

	sessionFactory SessionFactory[T, S]
	node           *Node
	inboundChan    chan []byte
	exitChan       chan struct{}
	closeOnce      sync.Once
}

// The store can be any implementation of ReverseIndexStore that doens't have funny side effects like
// the one in gossip_set, but the one in digest_set.go should work just fine.
//
// The session factory decides what strategy to use for reconciliation.
func NewReconcilerGossipSet[T any, S Symbol[S]](node *Node, store ReverseIndexStore[T, S], sessionFactory SessionFactory[T, S]) *reconcilerGossipSet[T, S] {
	return &reconcilerGossipSet[T, S]{
		ReverseIndexStore: store,
		sessionFactory:    sessionFactory,
		node:              node,
		inboundChan:       make(chan []byte),
		exitChan:          make(chan struct{}),
	}
}
