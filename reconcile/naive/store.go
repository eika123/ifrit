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

// Negotiator returns the default naive Phase 1 Negotiator.
func (s *ReconcilableStore[T]) Negotiator() reconcile.Negotiator {
	return NewNegotiator()
}

// Copy returns an independent clone wrapped in a naive ReconcilableStore.
func (s *ReconcilableStore[T]) Copy() digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol] {
	return &ReconcilableStore[T]{ReverseIndexStore: s.ReverseIndexStore.Copy()}
}

// Remove delegates to the underlying store if it implements MutableReverseIndexStore.
func (s *ReconcilableStore[T]) Remove(elem T) bool {
	if m, ok := s.ReverseIndexStore.(digestmaps.MutableReverseIndexStore[T, digestmaps.DigestSymbol]); ok {
		return m.Remove(elem)
	}
	return false
}

// RemoveByDigest delegates to the underlying store if it implements MutableReverseIndexStore.
func (s *ReconcilableStore[T]) RemoveByDigest(digest digestmaps.DigestSymbol) bool {
	if m, ok := s.ReverseIndexStore.(digestmaps.MutableReverseIndexStore[T, digestmaps.DigestSymbol]); ok {
		return m.RemoveByDigest(digest)
	}
	return false
}
