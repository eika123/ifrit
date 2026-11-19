package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/eika123/ifrit/digestmaps"
)

// Set is the read-only digest set view exposed to a Phase 1 Negotiator.
// Protocol-specific fast paths (such as ratelessIBLT.SketchStore) may be
// discovered via optional interface type assertions on Set.
type Set interface {
	Fingerprint() digestmaps.DigestSymbol
	DigestsCopy() []digestmaps.DigestSymbol
}

// NegotiationStream carries opaque Phase 1 negotiation payloads over the active Reconcile stream.
// CloseSend signals end-of-Phase-1 from this side without closing the underlying gRPC
// stream; the remote Recv observes io.EOF once all prior Phase 1 frames have been read.
type NegotiationStream interface {
	Send(payload []byte) error
	Recv() ([]byte, error)
	CloseSend() error
}

// Diff is the symmetric set difference computed by Phase 1 negotiation.
type Diff struct {
	Requested    []digestmaps.DigestSymbol // A \ B: responder wants from initiator
	Available    []digestmaps.DigestSymbol // B \ A: initiator wants from responder
	RemoteFP     []byte                    // Responder's pre-transfer fingerprint
	UsedFallback bool                      // True if protocol fell back (e.g. RIBLT sketch overflow)
}

// Negotiator implements a pluggable Phase 1 set-reconciliation algorithm
// (e.g., "naive/1", "riblt/1", "pinsketch/1", "mtz/1").
type Negotiator interface {
	Name() string
	Initiate(ctx context.Context, stream NegotiationStream, set Set) (Diff, error)
	Respond(ctx context.Context, stream NegotiationStream, set Set) (Diff, error)
}

// Registry maps wire protocol names to Negotiator implementations.
// Registries are constructed explicitly without package-global init() state.
type Registry struct {
	mu          sync.RWMutex
	negotiators map[string]Negotiator
}

// NewRegistry creates a Registry pre-populated with negotiators.
func NewRegistry(negotiators ...Negotiator) (*Registry, error) {
	r := &Registry{
		negotiators: make(map[string]Negotiator, len(negotiators)),
	}
	for _, n := range negotiators {
		if err := r.Register(n); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register binds n.Name() to n, failing on nil, empty name, or duplicate registration.
func (r *Registry) Register(n Negotiator) error {
	if n == nil {
		return errors.New("reconcile: cannot register nil negotiator")
	}
	name := n.Name()
	if name == "" {
		return errors.New("reconcile: negotiator name must not be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.negotiators[name]; exists {
		return fmt.Errorf("reconcile: negotiator %q already registered", name)
	}
	r.negotiators[name] = n
	return nil
}

// Get looks up a Negotiator by wire protocol name.
func (r *Registry) Get(name string) (Negotiator, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProtocol, name)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.negotiators[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProtocol, name)
	}
	return n, nil
}
