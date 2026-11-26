package digestmaps

import (
	"encoding/json"
	"slices"
	"sync"
)

type keyedDigestSet[K comparable, T any, S Symbol[S]] struct {
	ReverseIndexStore[Item[K, T], S]

	// secondaryIndex maps each key K to all distinct item digests stored under K
	// (Dynamo-style sibling buckets for concurrent conflicting writes).
	secondaryIndex map[K][]S

	mu sync.RWMutex
}

// NewKeyedDigestSet creates a new grow-only KeyedReverseIndexStore backed by an in-memory
// digest set with a secondary key-to-digests index.
// An explicit, non-nil Hasher over Item[K, T] must be provided.
func NewKeyedDigestSet[K comparable, T any, S Symbol[S]](hasher Hasher[Item[K, T], S]) (KeyedReverseIndexStore[K, T, S], error) {
	base, err := NewDigestSet(hasher)
	if err != nil {
		return nil, err
	}
	return &keyedDigestSet[K, T, S]{
		ReverseIndexStore: base,
		secondaryIndex:    make(map[K][]S),
	}, nil
}

// GetByKey retrieves all items currently stored under key.
// Returns the matching items and true if at least one item exists for key, or nil and false otherwise.
func (kds *keyedDigestSet[K, T, S]) GetByKey(key K) ([]Item[K, T], bool) {
	kds.mu.RLock()
	defer kds.mu.RUnlock()

	digests, exists := kds.secondaryIndex[key]
	if !exists || len(digests) == 0 {
		return nil, false
	}
	elems, _ := kds.ReverseIndexStore.GetByDigests(digests)
	if len(elems) == 0 {
		return nil, false
	}
	return elems, true
}

// ContainsKey reports whether at least one item with key exists in the store.
func (kds *keyedDigestSet[K, T, S]) ContainsKey(key K) bool {
	kds.mu.RLock()
	defer kds.mu.RUnlock()

	digests, exists := kds.secondaryIndex[key]
	return exists && len(digests) > 0
}

func (kds *keyedDigestSet[K, T, S]) insertItemLocked(item Item[K, T]) (digest S, newlyAdded bool) {
	digest, newlyAdded = kds.ReverseIndexStore.Insert(item)
	if newlyAdded {
		if kds.secondaryIndex == nil {
			kds.secondaryIndex = make(map[K][]S)
		}
		kds.secondaryIndex[item.Key] = append(kds.secondaryIndex[item.Key], digest)
	}
	return digest, newlyAdded
}

// Insert adds item to the store and indexes its digest under item.Key.
func (kds *keyedDigestSet[K, T, S]) Insert(item Item[K, T]) (digest S, newlyAdded bool) {
	kds.mu.Lock()
	defer kds.mu.Unlock()
	return kds.insertItemLocked(item)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// InsertBatch adds multiple items to the store and returns the count of newly added items.
func (kds *keyedDigestSet[K, T, S]) InsertBatch(elems ...Item[K, T]) int {
	if len(elems) == 0 {
		return 0
	}

	kds.mu.Lock()
	defer kds.mu.Unlock()

	sumNew := 0
	for _, e := range elems {
		_, newlyAdded := kds.insertItemLocked(e)
		sumNew += boolToInt(newlyAdded)
	}
	return sumNew
}

// Copy returns an independent, deep clone of the keyedDigestSet, including its secondary index.
func (kds *keyedDigestSet[K, T, S]) Copy() ReverseIndexStore[Item[K, T], S] {
	kds.mu.RLock()
	defer kds.mu.RUnlock()

	indexCopy := make(map[K][]S, len(kds.secondaryIndex))
	for k, digests := range kds.secondaryIndex {
		indexCopy[k] = slices.Clone(digests)
	}
	return &keyedDigestSet[K, T, S]{
		ReverseIndexStore: kds.ReverseIndexStore.Copy(),
		secondaryIndex:    indexCopy,
	}
}

// MarshalJSON serializes the set as a JSON array of elements.
func (kds *keyedDigestSet[K, T, S]) MarshalJSON() ([]byte, error) {
	return json.Marshal(kds.Elements())
}

// UnmarshalJSON populates both the primary digest set and the secondary key index from a JSON array of items.
func (kds *keyedDigestSet[K, T, S]) UnmarshalJSON(data []byte) error {
	var items []Item[K, T]
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}

	kds.mu.Lock()
	defer kds.mu.Unlock()

	if kds.ReverseIndexStore == nil {
		return ErrNilHasher
	}
	for _, item := range items {
		kds.insertItemLocked(item)
	}
	return nil
}
