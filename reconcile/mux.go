package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sync"

	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// StreamGuard optionally wraps inbound Reconcile streams (e.g. for crossed-wires
// tie-breaking and per-peer concurrency gating). It is acquired once for the entire
// Phase 1 + Phase 2 lifecycle of a stream.
type StreamGuard func(ctx context.Context, next func() error) error

// Mux multiplexes incoming ReconcileService.Reconcile streams across stores
// by the "store-id" gRPC metadata header.
type Mux struct {
	reconpb.UnimplementedReconcileServiceServer
	mu       sync.RWMutex
	handlers map[string]StreamHandler
	guard    StreamGuard
}

// NewMux constructs a typed store-routing Mux with an optional StreamGuard.
func NewMux(guard ...StreamGuard) *Mux {
	var g StreamGuard
	if len(guard) > 0 {
		g = guard[0]
	}
	return &Mux{
		handlers: make(map[string]StreamHandler),
		guard:    g,
	}
}

// RegisterStore binds storeID to handler, returning an error on empty storeID,
// nil handler, or duplicate storeID.
func (m *Mux) RegisterStore(storeID string, handler StreamHandler) error {
	if storeID == "" {
		return errors.New("reconcile: store-id must not be empty")
	}
	if handler == nil {
		return errors.New("reconcile: stream handler must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.handlers[storeID]; exists {
		return fmt.Errorf("%w: %q", ErrStoreAlreadyRegistered, storeID)
	}
	m.handlers[storeID] = handler
	return nil
}

// ReplaceStore binds storeID to handler, replacing any existing binding for storeID.
func (m *Mux) ReplaceStore(storeID string, handler StreamHandler) error {
	if storeID == "" {
		return errors.New("reconcile: store-id must not be empty")
	}
	if handler == nil {
		return errors.New("reconcile: stream handler must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[storeID] = handler
	return nil
}

// Register attaches this Mux to any grpc.ServiceRegistrar (such as *grpc.Server or *comm.Comm).
func (m *Mux) Register(s grpc.ServiceRegistrar) {
	reconpb.RegisterReconcileServiceServer(s, m)
}

// Reconcile routes an incoming stream to the StreamHandler matching "store-id".
func (m *Mux) Reconcile(stream reconpb.ReconcileService_ReconcileServer) error {
	h, err := m.resolve(stream.Context())
	if err != nil {
		return err
	}
	if m.guard != nil {
		return m.guard(stream.Context(), func() error {
			return h.HandleReconcile(stream)
		})
	}
	return h.HandleReconcile(stream)
}

func (m *Mux) resolve(ctx context.Context) (StreamHandler, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	md, hasMD := metadata.FromIncomingContext(ctx)
	var vals []string
	if hasMD {
		vals = md.Get(StoreIDMetadataKey)
	}

	if len(vals) == 0 {
		if len(m.handlers) == 1 {
			for _, h := range m.handlers {
				return h, nil
			}
		}
		return nil, status.Error(codes.InvalidArgument, "missing store-id metadata")
	}
	if len(vals) > 1 || vals[0] == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid store-id metadata")
	}

	h, ok := m.handlers[vals[0]]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown store-id %q", vals[0])
	}
	return h, nil
}
