package core

import (
	"sync"

	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

// Symbol is aliased from revIdxStore.Symbol.
type Symbol[S any] = revIdxStore.Symbol[S]

// ReverseIndexStore is aliased from revIdxStore.ReverseIndexStore.
type ReverseIndexStore[T any, S Symbol[S]] = revIdxStore.ReverseIndexStore[T, S]

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
