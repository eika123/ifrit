package core

import (
	"encoding/json"
	"sync"

	log "github.com/inconshreveable/log15"
)

type naiveGossipSet[T comparable, S Symbol[S]] struct {
	ReverseIndexStore[T, S]

	node        *Node
	inboundChan chan []byte
	exitChan    chan struct{}
	closeOnce   sync.Once
}

var _ ReverseIndexStore[string, DigestSymbol] = (*naiveGossipSet[string, DigestSymbol])(nil)

// NewNaiveGossipSet creates and initializes a push-based ReverseIndexStore bound to the specified Ifrit Node.
// It automatically registers gossip and response handlers on the node, launches the background
// merge worker, and initializes the gossip payload.
func NewNaiveGossipSet[T comparable](node *Node, initial ReverseIndexStore[T, DigestSymbol]) ReverseIndexStore[T, DigestSymbol] {
	if initial == nil {
		var err error
		initial, err = NewDigestSet[T, DigestSymbol](DefaultHasher[T]())
		if err != nil {
			panic(err)
		}
	}
	s := initial.Copy()

	gs := &naiveGossipSet[T, DigestSymbol]{
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

func (s *naiveGossipSet[T, S]) AddElement(elem T) bool {
	return s.AddElements(elem) > 0
}

func (s *naiveGossipSet[T, S]) AddElements(elems ...T) int {
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

func (s *naiveGossipSet[T, S]) Close() error {
	s.closeOnce.Do(func() {
		close(s.exitChan)
	})
	return s.ReverseIndexStore.Close()
}

func (s *naiveGossipSet[T, S]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Elements())
}

func (s *naiveGossipSet[T, S]) handleGossip(data []byte) ([]byte, error) {
	s.enqueue(data)
	return json.Marshal(s.Elements())
}

func (s *naiveGossipSet[T, S]) handleResponse(data []byte) {
	s.enqueue(data)
}

func (s *naiveGossipSet[T, S]) enqueue(data []byte) {
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

func (s *naiveGossipSet[T, S]) mergeWorkerLoop() {
	for {
		select {
		case <-s.exitChan:
			return
		case data := <-s.inboundChan:
			s.processInbound(data)
		}
	}
}

func (gset *naiveGossipSet[T, S]) processInbound(data []byte) {
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
