package messaging

import (
	"context"
	"errors"

	"github.com/eika123/ifrit"
	"github.com/eika123/ifrit/services"
)

type endpointConfig struct {
	msgHandler    MsgHandler
	streamHandler StreamHandler
	serviceOpts   []ifrit.ServiceOption
	transportOpts []Option
}

// EndpointOption configures a scoped messaging Endpoint created via Open or Attach.
type EndpointOption func(*endpointConfig)

// WithMsgHandler binds an inbound unary message handler for this endpoint.
func WithMsgHandler(fn MsgHandler) EndpointOption {
	return func(c *endpointConfig) {
		c.msgHandler = fn
	}
}

// WithStreamHandler binds an inbound bidirectional stream handler for this endpoint.
func WithStreamHandler(fn StreamHandler) EndpointOption {
	return func(c *endpointConfig) {
		c.streamHandler = fn
	}
}

// WithServiceOptions forwards Fireflies service options (e.g. version, health check)
// to client.Service when creating an Endpoint via Open.
func WithServiceOptions(opts ...ifrit.ServiceOption) EndpointOption {
	return func(c *endpointConfig) {
		c.serviceOpts = append(c.serviceOpts, opts...)
	}
}

// WithTransportOptions forwards messaging transport options (e.g. WithMaxConcurrent,
// WithTimeout, WithAuthenticator) if Messaging has not yet been mounted on client.
func WithTransportOptions(opts ...Option) EndpointOption {
	return func(c *endpointConfig) {
		c.transportOpts = append(c.transportOpts, opts...)
	}
}

// Endpoint combines a Fireflies ServiceEndpoint (discovery, super-overlay,
// service accusations) with scoped messaging over client's shared Messaging
// transport, eliminating repeated serviceID arguments and coordinating Close().
type Endpoint struct {
	*ifrit.ServiceEndpoint
	svc *Service
}

// Open ensures Messaging is mounted on host, announces serviceID in Fireflies
// ServiceDirectory, binds any configured handlers, and returns a scoped *Endpoint.
// Safe to call for multiple independent or layered services on the same host.
func Open(host services.Host, serviceID string, opts ...EndpointOption) (*Endpoint, error) {
	var cfg endpointConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return services.Open(host, serviceID, func(h services.Host, baseEp *ifrit.ServiceEndpoint) (*Endpoint, error) {
		return Attach(h, baseEp, opts...)
	}, cfg.serviceOpts...)
}

// Attach ensures Messaging is mounted on host and layers scoped messaging onto
// an existing *ifrit.ServiceEndpoint (e.g. one that already carries a replicated store).
func Attach(host services.TransportHost, ep *ifrit.ServiceEndpoint, opts ...EndpointOption) (*Endpoint, error) {
	if host == nil {
		return nil, errors.New("messaging: host cannot be nil")
	}
	if ep == nil {
		return nil, errors.New("messaging: service endpoint cannot be nil")
	}
	var cfg endpointConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	svc, err := Register(host, cfg.transportOpts...)
	if err != nil {
		return nil, err
	}
	return bindEndpoint(svc, ep, cfg)
}

func bindEndpoint(svc *Service, baseEp *ifrit.ServiceEndpoint, cfg endpointConfig) (*Endpoint, error) {
	ep := &Endpoint{
		ServiceEndpoint: baseEp,
		svc:             svc,
	}
	if cfg.msgHandler != nil {
		if err := ep.Handle(cfg.msgHandler); err != nil {
			return nil, err
		}
	}
	if cfg.streamHandler != nil {
		if err := ep.HandleStream(cfg.streamHandler); err != nil {
			return nil, err
		}
	}
	return ep, nil
}

// Handle registers (or clears, if handler == nil) the unary message handler for this endpoint.
func (e *Endpoint) Handle(handler MsgHandler) error {
	return e.svc.Handle(e.ID(), handler)
}

// HandleStream registers (or clears, if handler == nil) the bidirectional stream handler for this endpoint.
func (e *Endpoint) HandleStream(handler StreamHandler) error {
	return e.svc.HandleStream(e.ID(), handler)
}

// Send dispatches a synchronous unary message to addr routed to this endpoint's service ID.
func (e *Endpoint) Send(ctx context.Context, addr string, data []byte) ([]byte, error) {
	return e.svc.Send(ctx, e.ID(), addr, data)
}

// SendAsync dispatches a unary message to addr asynchronously and delivers the result on the returned channel.
func (e *Endpoint) SendAsync(addr string, data []byte) chan *Message {
	return e.svc.SendAsync(e.ID(), addr, data)
}

// OpenStream opens a bidirectional byte stream to addr routed to this endpoint's service ID.
func (e *Endpoint) OpenStream(ctx context.Context, addr string) (chan<- []byte, <-chan []byte) {
	return e.svc.OpenStream(ctx, e.ID(), addr)
}

// Close clears this endpoint's unary and stream handlers on the messaging service
// and unregisters the service from Fireflies ServiceDirectory.
func (e *Endpoint) Close() error {
	_ = e.svc.Handle(e.ID(), nil)
	_ = e.svc.HandleStream(e.ID(), nil)
	return e.ServiceEndpoint.Close()
}
