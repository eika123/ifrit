package services

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/reconcile"
	"google.golang.org/grpc"
)

// TransportHost is the minimal mTLS gRPC transport surface required by opt-in
// services in services/. Both *ifrit.Client and *core.Node implement TransportHost.
type TransportHost interface {
	RegisterGRPCService(desc *grpc.ServiceDesc, impl any) error
	EnsureGRPCService(desc *grpc.ServiceDesc, factory func() (any, error)) (any, error)
	ConnProvider() reconcile.ConnProvider
	PeerAuthenticator() reconcile.PeerAuthenticator
	ValidatePeerCtx(ctx context.Context) (*x509.Certificate, error)
}

// Host extends TransportHost with Fireflies ServiceDirectory discovery,
// super-overlay membership, service accusations, and store reconciliation mounting.
// Both *ifrit.Client and *core.Node implement Host.
type Host interface {
	TransportHost
	RegisterService(serviceID string, version uint64, healthCheck func() bool) (*discovery.RingSuperOverlay, error)
	UnregisterService(serviceID string) error
	ServiceMembers(serviceID string) []discovery.PeerInfo
	ServiceNeighbours(serviceID string) []discovery.PeerInfo
	AccuseServicePeer(serviceID, peerID string, ringNum uint32) error
	RegisterServiceStoreReconciler(serviceID, storeName string, rec reconcile.StoreReconciler, fpFn func() []byte) error
}

type serviceConfig struct {
	version     uint64
	healthCheck func() bool
}

// ServiceOption configures how a service announces itself in Fireflies ServiceDirectory.
type ServiceOption func(*serviceConfig)

// WithServiceVersion sets the initial service version published in this node's ServiceNote.
func WithServiceVersion(version uint64) ServiceOption {
	return func(cfg *serviceConfig) {
		if version > 0 {
			cfg.version = version
		}
	}
}

// WithHealthCheck registers a local health callback invoked before rebutting a ServiceAccusation
// targeting this service. Returning false unregisters the service instead of rebutting.
func WithHealthCheck(fn func() bool) ServiceOption {
	return func(cfg *serviceConfig) {
		cfg.healthCheck = fn
	}
}

// Endpoint is a scoped handle for a third-party service running atop an Ifrit Host,
// providing super-overlay discovery, service-level accusations, and named store
// reconciler attachment.
type Endpoint struct {
	host      Host
	serviceID string
}

// NewEndpoint announces serviceID on host, initializing its deterministic RingSuperOverlay
// over S_svc and publishing a signed ServiceNote across the cluster.
func NewEndpoint(host Host, serviceID string, opts ...ServiceOption) (*Endpoint, error) {
	if host == nil {
		return nil, errors.New("services: host cannot be nil")
	}
	cfg := serviceConfig{version: 1}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if _, err := host.RegisterService(serviceID, cfg.version, cfg.healthCheck); err != nil {
		return nil, err
	}
	return &Endpoint{
		host:      host,
		serviceID: serviceID,
	}, nil
}

// ID returns the validated service identifier for this endpoint.
func (e *Endpoint) ID() string {
	return e.serviceID
}

// Host returns the underlying Host this endpoint is bound to.
func (e *Endpoint) Host() Host {
	return e.host
}

// Members returns all live, non-evicted peers currently hosting this service (sorted by ID).
func (e *Endpoint) Members() []discovery.PeerInfo {
	return e.host.ServiceMembers(e.serviceID)
}

// MemberAddrs returns the RPC addresses of all live, non-evicted peers hosting this service.
func (e *Endpoint) MemberAddrs() []string {
	members := e.Members()
	addrs := make([]string, 0, len(members))
	for _, p := range members {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// Neighbours returns the deterministic k-ring neighbors from this service's RingSuperOverlay.
func (e *Endpoint) Neighbours() []discovery.PeerInfo {
	return e.host.ServiceNeighbours(e.serviceID)
}

// NeighbourAddrs returns the RPC addresses of this service's deterministic k-ring neighbors.
func (e *Endpoint) NeighbourAddrs() []string {
	neighbours := e.Neighbours()
	addrs := make([]string, 0, len(neighbours))
	for _, p := range neighbours {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// AccusePeer signs and publishes a ServiceAccusation against peerID on ringNum of this
// service's RingSuperOverlay when peerID's service instance crashes or behaves malignantly.
func (e *Endpoint) AccusePeer(peerID string, ringNum uint32) error {
	return e.host.AccuseServicePeer(e.serviceID, peerID, ringNum)
}

// RegisterStoreReconciler mounts a custom reconcile.StoreReconciler for this service under
// "service/<serviceID>/<storeName>" and enables automatic background anti-entropy across Neighbours().
func (e *Endpoint) RegisterStoreReconciler(storeName string, rec reconcile.StoreReconciler, fpFn func() []byte) error {
	return e.host.RegisterServiceStoreReconciler(e.serviceID, storeName, rec, fpFn)
}

// Close detaches this service's store reconcilers and super-overlay, and publishes
// an updated ServiceNote epoch without this service.
func (e *Endpoint) Close() error {
	return e.host.UnregisterService(e.serviceID)
}

// Open announces serviceID on host (creating an *Endpoint) and binds a service
// implementation via attach. If attach fails, the Fireflies ServiceDirectory
// announcement is rolled back via ep.Close().
func Open[T any](
	host Host,
	serviceID string,
	attach func(Host, *Endpoint) (T, error),
	opts ...ServiceOption,
) (T, error) {
	var zero T
	if host == nil {
		return zero, errors.New("services: host cannot be nil")
	}
	if attach == nil {
		return zero, errors.New("services: attach function cannot be nil")
	}
	ep, err := NewEndpoint(host, serviceID, opts...)
	if err != nil {
		return zero, err
	}
	svc, err := attach(host, ep)
	if err != nil {
		_ = ep.Close()
		return zero, err
	}
	return svc, nil
}
