package core

import (
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

// DataReconciler provides a type-erased reconciliation interface for arbitrary application data stores.
type DataReconciler interface {
	Digests() []revIdxStore.DigestSymbol
	Fingerprint() revIdxStore.DigestSymbol
	Reconcile(incomingDigests []revIdxStore.DigestSymbol) (localMissingOnCaller, remoteMissingLocally []revIdxStore.DigestSymbol, err error)
}

type typedDataReconciler[T any] struct {
	store       ReverseIndexStore[T, revIdxStore.DigestSymbol]
	constructor SessionConstructor[T, revIdxStore.DigestSymbol]
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

func (r *typedDataReconciler[T]) Reconcile(incomingDigests []revIdxStore.DigestSymbol) ([]revIdxStore.DigestSymbol, []revIdxStore.DigestSymbol, error) {
	if r.store == nil {
		return nil, nil, ErrNilStore
	}
	session, err := r.constructor(r.store)
	if err != nil {
		return nil, nil, err
	}
	session.ProcessIncomingDigests(incomingDigests)
	return session.LocalDigests(), session.RemoteDigests(), nil
}

// NewTypedDataReconciler wraps an application's typed store into a DataReconciler.
// If constructor is omitted or nil, it defaults to the configured default session constructor.
func NewTypedDataReconciler[T any](
	store ReverseIndexStore[T, revIdxStore.DigestSymbol],
	constructor ...SessionConstructor[T, revIdxStore.DigestSymbol],
) DataReconciler {
	var c SessionConstructor[T, revIdxStore.DigestSymbol]
	if len(constructor) > 0 && constructor[0] != nil {
		c = constructor[0]
	} else {
		c = DefaultSessionConstructor[T]()
	}
	return &typedDataReconciler[T]{
		store:       store,
		constructor: c,
	}
}
