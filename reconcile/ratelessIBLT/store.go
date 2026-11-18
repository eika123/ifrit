package ratelessIBLT

import (
	"slices"
	"sync"

	"github.com/joonnna/ifrit/digestmaps"
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
	}
	return &Store[T, S]{
		ReverseIndexStore: base,
		sketch:            sketch,
	}
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
