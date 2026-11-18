package naive

import (
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
)

// ReconcilableStore implements reconcile.Store[T] over a plain ReverseIndexStore
// without IBLT sketch overhead, serving as a baseline benchmark backend.
type ReconcilableStore[T any] struct {
	digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]
}

// NewReconcilableStore creates a new in-memory naive reconcile.Store[T].
func NewReconcilableStore[T any](hasher digestmaps.Hasher[T, digestmaps.DigestSymbol]) (*ReconcilableStore[T], error) {
	base, err := digestmaps.NewDigestSet(hasher)
	if err != nil {
		return nil, err
	}
	return WrapStore(base), nil
}

// WrapStore wraps an existing ReverseIndexStore in a naive ReconcilableStore.
func WrapStore[T any](base digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]) *ReconcilableStore[T] {
	return &ReconcilableStore[T]{ReverseIndexStore: base}
}

// Base returns the underlying ReverseIndexStore wrapped by this ReconcilableStore.
func (s *ReconcilableStore[T]) Base() digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol] {
	return s.ReverseIndexStore
}

// NewReconciler constructs a naive StoreReconciler bound to this store.
func (s *ReconcilableStore[T]) NewReconciler(cfg reconcile.Config[T]) reconcile.StoreReconciler {
	return NewReconciler(s.ReverseIndexStore, cfg)
}
