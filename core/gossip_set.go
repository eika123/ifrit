package core

import (
	"encoding/json"
	"sync"

	log "github.com/inconshreveable/log15"
)

type naiveGossipSet[T comparable] struct {
	ReverseIndexStore[T]

	node        *Node
	inboundChan chan []byte
	exitChan    chan struct{}
	closeOnce   sync.Once
}

var _ ReverseIndexStore[string] = (*naiveGossipSet[string])(nil)

// NewNaiveGossipSet creates and initializes a push-based ReverseIndexStore bound to the specified Ifrit Node.
// It automatically registers gossip and response handlers on the node, launches the background
// merge worker, and initializes the gossip payload.
func NewNaiveGossipSet[T comparable](node *Node, initial ReverseIndexStore[T]) ReverseIndexStore[T] {
	if initial == nil {
		initial = NewDigestSet[T]()
	}
	s := initial.Copy()

	gs := &naiveGossipSet[T]{
		ReverseIndexStore: s,
		node:              node,
		inboundChan:       make(chan []byte, 256),
		exitChan:          make(chan struct{}),
	}

	if node != nil {
		initialBytes, err := json.Marshal(s.Elements())
		if err == nil {
			node.setExternalGossipContent(initialBytes)
		}
		node.SetGossipHandler(gs.handleGossip)
		node.SetResponseHandler(gs.handleResponse)
	}

	go gs.mergeWorkerLoop()

	return gs
}

func (s *naiveGossipSet[T]) AddElement(elem T) bool {
	return s.AddElements(elem) > 0
}

func (s *naiveGossipSet[T]) AddElements(elems ...T) int {
	if len(elems) == 0 {
		return 0
	}

	added := s.ReverseIndexStore.AddElements(elems...)
	if added > 0 {
		log.Debug("GossipSet updated", "added", added, "total", s.ReverseIndexStore.Size())
		if s.node != nil {
			raw, err := json.Marshal(s.Elements())
			if err == nil {
				s.node.setExternalGossipContent(raw)
			} else {
				log.Error("Failed to marshal gossip set after AddElements", "err", err)
			}
		}
	}

	return added
}

func (s *naiveGossipSet[T]) Close() error {
	s.closeOnce.Do(func() {
		close(s.exitChan)
	})
	return s.ReverseIndexStore.Close()
}

func (s *naiveGossipSet[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Elements())
}

func (s *naiveGossipSet[T]) handleGossip(data []byte) ([]byte, error) {
	s.enqueue(data)
	return json.Marshal(s.Elements())
}

func (s *naiveGossipSet[T]) handleResponse(data []byte) {
	s.enqueue(data)
}

func (s *naiveGossipSet[T]) enqueue(data []byte) {
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

func (s *naiveGossipSet[T]) mergeWorkerLoop() {
	for {
		select {
		case <-s.exitChan:
			return
		case data := <-s.inboundChan:
			s.processInbound(data)
		}
	}
}

func (gset *naiveGossipSet[T]) processInbound(data []byte) {
	var incoming []T
	if err := json.Unmarshal(data, &incoming); err != nil {
		log.Warn("Discarded malformed gossip payload", "err", err)
		return
	}
	if len(incoming) == 0 {
		return
	}

	// updated set will be externalized in the AddElements method.
	gset.AddElements(incoming...)
}
