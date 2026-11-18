package ratelessIBLT

import (
	"slices"
	"sync"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/yangl1996/riblt"
)

const (
	DefaultSketchSize      = 4096
	DefaultSymbolBatchSize = 48 // ~1.35 KB protobuf payload; fits in one 1500-byte Ethernet MTU frame
)

type Symbol[S any] digestmaps.Symbol[S]

// Store wraps ReverseIndexStore and incrementally maintains a fixed-size
// riblt.Sketch for O(M) snapshot reconciliation with rateless fallback.
type Store[T any, S Symbol[S]] struct {
	digestmaps.ReverseIndexStore[T, S]
	mu     sync.RWMutex
	sketch riblt.Sketch[S]
}

func NewRatelessIBLTStore[T any, S Symbol[S]](base digestmaps.ReverseIndexStore[T, S], sketchSize int) *Store[T, S] {
	var sketch riblt.Sketch[S]
	if sketchSize > 0 {
		sketch = make(riblt.Sketch[S], sketchSize)
		if base != nil {
			for _, d := range base.DigestsCopy() {
				sketch.AddSymbol(d)
			}
		}
	}
	return &Store[T, S]{
		ReverseIndexStore: base,
		sketch:            sketch,
	}
}

// Base returns the underlying ReverseIndexStore wrapped by this Store.
func (s *Store[T, S]) Base() digestmaps.ReverseIndexStore[T, S] {
	return s.ReverseIndexStore
}

func (s *Store[T, S]) Insert(elem T) (S, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	digest, added := s.ReverseIndexStore.Insert(elem)
	if added && len(s.sketch) > 0 {
		s.sketch.AddSymbol(digest)
	}
	return digest, added
}

func (s *Store[T, S]) InsertBatch(elems ...T) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	addedCount := 0
	for _, elem := range elems {
		digest, added := s.ReverseIndexStore.Insert(elem)
		if added {
			if len(s.sketch) > 0 {
				s.sketch.AddSymbol(digest)
			}
			addedCount++
		}
	}
	return addedCount
}

func (s *Store[T, S]) SnapshotSketch() riblt.Sketch[S] {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.sketch) == 0 {
		return nil
	}
	return slices.Clone(s.sketch)
}

func (s *Store[T, S]) MakeEncoder() riblt.Encoder[S] {
	enc := riblt.Encoder[S]{}
	for _, d := range s.DigestsCopy() {
		enc.AddSymbol(d)
	}
	return enc
}

func (s *Store[T, S]) MakeDecoder() riblt.Decoder[S] {
	dec := riblt.Decoder[S]{}
	for _, d := range s.DigestsCopy() {
		dec.AddSymbol(d)
	}
	return dec
}

// ReconcilableStore implements reconcile.Store[T] over a ratelessIBLT-backed Store.
// Callers interact with standard Insert/Contains/Fingerprint methods while incremental
// sketch updates and snapshotting remain encapsulated inside ratelessIBLT.
type ReconcilableStore[T any] struct {
	*Store[T, digestmaps.DigestSymbol]
}

// NewReconcilableStore creates a new in-memory ratelessIBLT-backed reconcile.Store[T].
// sketchSize is optional and defaults to DefaultSketchSize when omitted or <= 0.
func NewReconcilableStore[T any](hasher digestmaps.Hasher[T, digestmaps.DigestSymbol], sketchSize ...int) (*ReconcilableStore[T], error) {
	base, err := digestmaps.NewDigestSet(hasher)
	if err != nil {
		return nil, err
	}
	return WrapStore(base, sketchSize...), nil
}

// WrapStore wraps an existing ReverseIndexStore in a ReconcilableStore.
// sketchSize is optional and defaults to DefaultSketchSize when omitted or <= 0.
func WrapStore[T any](base digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol], sketchSize ...int) *ReconcilableStore[T] {
	size := DefaultSketchSize
	if len(sketchSize) > 0 && sketchSize[0] > 0 {
		size = sketchSize[0]
	}
	return &ReconcilableStore[T]{
		Store: NewRatelessIBLTStore(base, size),
	}
}

// NewReconciler constructs a StoreReconciler bound to this store.
func (s *ReconcilableStore[T]) NewReconciler(cfg reconcile.Config[T]) reconcile.StoreReconciler {
	return NewReconciler(s.Store, cfg)
}
