package core

import (
	"errors"
	"sync"

	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

// ErrNilStore indicates that a nil store was provided where an active store is required.
var ErrNilStore = errors.New("store cannot be nil")

// Symbol is aliased from revIdxStore.Symbol.
type Symbol[S any] = revIdxStore.Symbol[S]

// ReverseIndexStore is aliased from revIdxStore.ReverseIndexStore.
type ReverseIndexStore[T any, S Symbol[S]] = revIdxStore.ReverseIndexStore[T, S]

// ReconcilerSession represents an active set reconciliation session between two peers.
type ReconcilerSession[T, S any] interface {
	ProcessIncomingMessage(msg []byte) error
	ProcessIncomingDigests(incoming []S)
	GenerateNextMessage() ([]byte, error)

	Done() bool
	RemoteDigests() []S // Elements the peer has that we need to fetch
	LocalDigests() []S  // Elements we have that the peer is missing
	LocalElements() []T // Elements we have that the peer is missing (resolved from local store)
	DiffDigests() []S   // Union of RemoteDigests() and LocalDigests() (the symmetric difference)
}

// SessionFactory creates a new reconciliation session backed by a store snapshot/view.
type SessionFactory[T any, S Symbol[S]] interface {
	NewSession(store ReverseIndexStore[T, S]) (ReconcilerSession[T, S], error)
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

// DiffDigests returns the union of local and remote digests (the symmetric difference).
func DiffDigests[S any](local, remote []S) []S {
	diff := make([]S, 0, len(local)+len(remote))
	diff = append(diff, local...)
	diff = append(diff, remote...)
	return diff
}

// SessionLocalElements resolves elements from the store corresponding to localDiff digests.
func SessionLocalElements[T any, S Symbol[S]](store ReverseIndexStore[T, S], localDiff []S) []T {
	if store == nil || len(localDiff) == 0 {
		return nil
	}
	elems, _ := store.GetByDigests(localDiff)
	return elems
}

// ReconcileStore executes a protocol-agnostic reconciliation round against the given store using
// a session produced by factory. If factory is nil, it defaults to NaiveSessionFactory.
func ReconcileStore[T any, S Symbol[S]](
	factory SessionFactory[T, S],
	store ReverseIndexStore[T, S],
	incomingDigests []S,
) (localElements []T, remoteDigests []S, err error) {
	if store == nil {
		return nil, nil, ErrNilStore
	}
	if factory == nil {
		factory = NewNaiveSessionFactory[T, S]()
	}
	session, err := factory.NewSession(store)
	if err != nil {
		return nil, nil, err
	}
	session.ProcessIncomingDigests(incomingDigests)
	return session.LocalElements(), session.RemoteDigests(), nil
}

// DataReconciler provides a type-erased reconciliation interface for arbitrary application data stores.
type DataReconciler interface {
	Digests() []revIdxStore.DigestSymbol
	Fingerprint() revIdxStore.DigestSymbol
	Reconcile(incomingDigests []revIdxStore.DigestSymbol) (remoteMissing []revIdxStore.DigestSymbol, err error)
}

type typedDataReconciler[T any] struct {
	store   ReverseIndexStore[T, revIdxStore.DigestSymbol]
	factory SessionFactory[T, revIdxStore.DigestSymbol]
}

func (r *typedDataReconciler[T]) Digests() []revIdxStore.DigestSymbol {
	if r.store == nil {
		return nil
	}
	return r.store.DigestsCopy()
}

func (r *typedDataReconciler[T]) Fingerprint() revIdxStore.DigestSymbol {
	if r.store == nil {
		return 0
	}
	return r.store.Fingerprint()
}

func (r *typedDataReconciler[T]) Reconcile(incomingDigests []revIdxStore.DigestSymbol) ([]revIdxStore.DigestSymbol, error) {
	_, remoteDigests, err := ReconcileStore(r.factory, r.store, incomingDigests)
	return remoteDigests, err
}

// NewTypedDataReconciler wraps an application's typed store and session factory into a DataReconciler.
func NewTypedDataReconciler[T any](
	store ReverseIndexStore[T, revIdxStore.DigestSymbol],
	factory SessionFactory[T, revIdxStore.DigestSymbol],
) DataReconciler {
	if factory == nil {
		factory = NewNaiveSessionFactory[T, revIdxStore.DigestSymbol]()
	}
	return &typedDataReconciler[T]{
		store:   store,
		factory: factory,
	}
}
