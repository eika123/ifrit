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

func (r *typedDataReconciler[T]) Reconcile(incomingDigests []revIdxStore.DigestSymbol) ([]revIdxStore.DigestSymbol, []revIdxStore.DigestSymbol, error) {
	if r.store == nil {
		return nil, nil, ErrNilStore
	}
	factory := r.factory
	if factory == nil {
		factory = NewNaiveSessionFactory[T, revIdxStore.DigestSymbol]()
	}
	session, err := factory.NewSession(r.store)
	if err != nil {
		return nil, nil, err
	}
	session.ProcessIncomingDigests(incomingDigests)
	return session.LocalDigests(), session.RemoteDigests(), nil
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
