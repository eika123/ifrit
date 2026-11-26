package dht

import (
	"errors"

	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/eika123/ifrit/services"
)

type config struct {
	serviceOpts []services.ServiceOption
	storeOpts   []services.StoreOption[Item]
}

// Option configures a replicated DHT Service opened via Open or Attach.
type Option func(*config)

// WithServiceOptions forwards Fireflies service options (e.g. version, health check)
// to services.Open.
func WithServiceOptions(opts ...services.ServiceOption) Option {
	return func(c *config) {
		c.serviceOpts = append(c.serviceOpts, opts...)
	}
}

// WithStoreOptions forwards store reconciliation options (e.g. codec, detector, timeout)
// to services.AttachStore.
func WithStoreOptions(opts ...services.StoreOption[Item]) Option {
	return func(c *config) {
		c.storeOpts = append(c.storeOpts, opts...)
	}
}

// Open announces serviceID in Fireflies ServiceDirectory, constructs the DHT's
// replicated store, and attaches it under "service/<serviceID>/items".
func Open(host services.Host, serviceID string, opts ...Option) (*Service, error) {
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return services.Open(host, serviceID,
		func(_ services.Host, baseEp *services.Endpoint) (*Service, error) {
			return Attach(baseEp, opts...)
		}, cfg.serviceOpts...)
}

// Attach constructs the DHT's replicated store and attaches it to an existing
// *services.Endpoint under "service/<serviceID>/items".
func Attach(ep *services.Endpoint, opts ...Option) (*Service, error) {
	if ep == nil {
		return nil, errors.New("dht: endpoint cannot be nil")
	}
	var cfg config
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	store, err := ratelessIBLT.NewKeyedReconcilableStore[string, []byte](hashItem)
	if err != nil {
		return nil, err
	}
	if err := services.AttachStore(ep, "items", store, cfg.storeOpts...); err != nil {
		return nil, err
	}

	return &Service{
		Endpoint: ep,
		items:    store,
	}, nil
}
