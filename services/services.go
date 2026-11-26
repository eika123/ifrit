package services

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/eika123/ifrit"
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

// Host extends TransportHost with Fireflies ServiceDirectory announcement.
// *ifrit.Client implements Host.
type Host interface {
	TransportHost
	Service(serviceID string, opts ...ifrit.ServiceOption) (*ifrit.ServiceEndpoint, error)
}

// Open announces serviceID on host (creating a *ifrit.ServiceEndpoint) and
// binds a service implementation via attach. If attach fails, the Fireflies
// ServiceEndpoint announcement is rolled back via ep.Close().
func Open[T any](
	host Host,
	serviceID string,
	attach func(Host, *ifrit.ServiceEndpoint) (T, error),
	opts ...ifrit.ServiceOption,
) (T, error) {
	var zero T
	if host == nil {
		return zero, errors.New("services: host cannot be nil")
	}
	if attach == nil {
		return zero, errors.New("services: attach function cannot be nil")
	}
	ep, err := host.Service(serviceID, opts...)
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
