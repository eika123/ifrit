package core

import (
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-set/v2"
	log "github.com/inconshreveable/log15"
)

// GossipSet represents a distributed, convergent set synchronized across Ifrit nodes.
// State mutations are performed strictly through AddElement / AddElements, while state
// inspection is safely exposed through Copy() or Elements(), preventing application
// code from arbitrarily mutating Ifrit's internal gossip state.
type GossipSet[T comparable] interface {
	// AddElement inserts a single element into the set and publishes the update to Ifrit gossip.
	// Returns true if the element was newly added.
	AddElement(elem T) bool

	// AddElements inserts multiple elements into the set and publishes the update to Ifrit gossip.
	// Returns the count of newly added elements.
	AddElements(elems ...T) int

	// Copy returns an independent, deep copy of the set at this point in time.
	// Mutations made to the returned set do not affect Ifrit's internal gossip state.
	Copy() *set.Set[T]

	// Contains returns true if the set contains the given element.
	Contains(elem T) bool

	// Size returns the total number of unique elements in the set.
	Size() int

	// Empty returns true if the set contains no elements.
	Empty() bool

	// RawBytes returns the latest serialized JSON representation of the gossip set.
	RawBytes() []byte

	// OnUpdate registers a callback invoked when new elements are merged from remote peers.
	OnUpdate(callback func(newElements []T, total int))

	// Close terminates the internal background merge worker and cleans up resources.
	Close()
}

type gossipSet[T comparable] struct {
	node        *Node
	inboundChan chan []byte
	exitChan    chan struct{}
	closeOnce   sync.Once

	mu         sync.RWMutex
	currentSet *set.Set[T]
	onUpdate   func(newElements []T, total int)

	latestBytes atomic.Pointer[[]byte]
}

// NewGossipSet creates and initializes a new GossipSet bound to the specified Ifrit Node.
// It automatically registers gossip and response handlers on the node, launches the background
// merge worker, and initializes the gossip payload.
// If initial sets are provided, the first non-nil set is copied as the starting state.
func NewGossipSet[T comparable](node *Node, initial ...*set.Set[T]) GossipSet[T] {
	var s *set.Set[T]
	if len(initial) > 0 && initial[0] != nil {
		s = initial[0].Copy()
	} else {
		s = set.New[T](16)
	}

	gs := &gossipSet[T]{
		node:        node,
		inboundChan: make(chan []byte, 256),
		exitChan:    make(chan struct{}),
		currentSet:  s,
	}

	initialBytes, err := s.MarshalJSON()
	if err == nil {
		gs.latestBytes.Store(&initialBytes)
		if node != nil {
			node.setExternalGossipContent(initialBytes)
		}
	}

	if node != nil {
		node.SetGossipHandler(gs.handleGossip)
		node.SetResponseHandler(gs.handleResponse)
	}

	go gs.mergeWorkerLoop()

	return gs
}

func (s *gossipSet[T]) AddElement(elem T) bool {
	return s.AddElements(elem) > 0
}

func (s *gossipSet[T]) AddElements(elems ...T) int {
	if len(elems) == 0 {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	added := 0
	for _, elem := range elems {
		if s.currentSet.Insert(elem) {
			added++
		}
	}

	if added == 0 {
		return added
	}

	raw, err := s.currentSet.MarshalJSON()
	if err == nil {
		s.latestBytes.Store(&raw)
		if s.node != nil {
			s.node.setExternalGossipContent(raw)
		}
	} else {
		log.Error("Failed to marshal gossip set after AddElements", "err", err)
	}

	return added
}

func (s *gossipSet[T]) Copy() *set.Set[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.currentSet.Copy()
}

func (s *gossipSet[T]) Contains(elem T) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.currentSet.Contains(elem)
}

func (s *gossipSet[T]) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.currentSet.Size()
}

func (s *gossipSet[T]) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.currentSet.Empty()
}

func (s *gossipSet[T]) RawBytes() []byte {
	if ptr := s.latestBytes.Load(); ptr != nil {
		return *ptr
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := s.currentSet.MarshalJSON()
	return b
}

func (s *gossipSet[T]) OnUpdate(callback func(newElements []T, total int)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.onUpdate = callback
}

func (s *gossipSet[T]) Close() {
	s.closeOnce.Do(func() {
		close(s.exitChan)
	})
}

func (s *gossipSet[T]) handleGossip(data []byte) ([]byte, error) {
	s.enqueue(data)

	if ptr := s.latestBytes.Load(); ptr != nil {
		return *ptr, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentSet.MarshalJSON()
}

func (s *gossipSet[T]) handleResponse(data []byte) {
	s.enqueue(data)
}

func (s *gossipSet[T]) enqueue(data []byte) {
	if len(data) == 0 {
		return
	}

	select {
	case <-s.exitChan:
		return
	default:
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case s.inboundChan <- cp:
	default:
		log.Warn("Inbound gossip buffer full; dropping packet to prevent head-of-line blocking")
	}
}

func (s *gossipSet[T]) mergeWorkerLoop() {
	for {
		select {
		case <-s.exitChan:
			return
		case data := <-s.inboundChan:
			s.processInbound(data)
		}
	}
}

func (gset *gossipSet[T]) processInbound(data []byte) {
	incoming := set.New[T](0)
	if err := json.Unmarshal(data, incoming); err != nil {
		log.Warn("Discarded malformed gossip payload", "err", err)
		return
	}
	if incoming.Size() == 0 {
		return
	}

	gset.mu.Lock()
	defer gset.mu.Unlock()

	oldSize := gset.currentSet.Size()
	if merged, ok := gset.currentSet.Union(incoming).(*set.Set[T]); ok {
		gset.currentSet = merged
	}
	newSize := gset.currentSet.Size()

	// Only re-marshal and update wire if state actually changed
	if newSize > oldSize {
		if gset.onUpdate != nil {
			gset.onUpdate(gset.currentSet.Slice(), newSize)
		}

		b, err := gset.currentSet.MarshalJSON()
		if err != nil {
			log.Error("Failed to marshal gossip set", "err", err)
			return
		}
		gset.latestBytes.Store(&b)

		if gset.node != nil {
			gset.node.setExternalGossipContent(b)
		}
	}
}
