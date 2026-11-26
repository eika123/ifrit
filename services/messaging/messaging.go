package messaging

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/services"
	messagingpb "github.com/eika123/ifrit/services/messaging/proto"
	log "github.com/inconshreveable/log15"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// ServiceIDMetadataKey is the gRPC metadata key routing Messaging Send and Stream RPCs to a handler.
	ServiceIDMetadataKey = "service-id"
	defaultTimeout       = 10 * time.Second
)

// MsgHandler handles an inbound unary message for a registered serviceID.
type MsgHandler func([]byte) ([]byte, error)

// StreamHandler handles an inbound bidirectional byte stream for a registered serviceID.
// The handler must close reply when finished.
type StreamHandler func(input, reply chan []byte)

// Message holds the result of an asynchronous SendAsync call.
type Message struct {
	Data  []byte
	Error error
}

type config struct {
	maxConcurrent int
	timeout       time.Duration
	auth          func(context.Context) error
}

// Option configures a Messaging Service registered via Register.
type Option func(*config)

// WithMaxConcurrent caps concurrent outbound unary Send calls using a semaphore.
// Values <= 0 disable the concurrency cap.
func WithMaxConcurrent(n int) Option {
	return func(c *config) {
		c.maxConcurrent = n
	}
}

// WithTimeout sets the default per-RPC timeout for Send calls when the caller's
// context has no deadline. Defaults to 10s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithAuthenticator overrides inbound peer authentication for Send and Stream RPCs.
// By default, host.ValidatePeerCtx is used (validates mTLS cert without requiring
// Fireflies live-view membership). Pass client.PeerAuthenticator() to also enforce
// live-view membership.
func WithAuthenticator(fn func(context.Context) error) Option {
	return func(c *config) {
		if fn != nil {
			c.auth = fn
		}
	}
}

// Service implements an opt-in point-to-point messaging and bidirectional streaming
// service multiplexed by "service-id" gRPC metadata over an Ifrit Host's mTLS server.
type Service struct {
	connProvider reconcile.ConnProvider
	auth         func(context.Context) error
	timeout      time.Duration
	sem          chan struct{}

	baseCtx    context.Context
	baseCancel context.CancelFunc

	mu             sync.RWMutex
	msgHandlers    map[string]MsgHandler
	streamHandlers map[string]StreamHandler
}

type rpcServer struct {
	messagingpb.UnimplementedMessagingServer
	svc *Service
}

// Register ensures a Messaging Service is mounted on host's shared mTLS gRPC server
// and returns it. Safe to call multiple times on the same host (subsequent calls
// return the existing shared *Service); the first call must happen before host.Start().
func Register(host services.TransportHost, opts ...Option) (*Service, error) {
	if host == nil {
		return nil, errors.New("messaging: host cannot be nil")
	}

	impl, err := host.EnsureGRPCService(&messagingpb.Messaging_ServiceDesc, func() (any, error) {
		cfg := config{
			timeout: defaultTimeout,
			auth: func(ctx context.Context) error {
				_, err := host.ValidatePeerCtx(ctx)
				return err
			},
		}
		for _, opt := range opts {
			if opt != nil {
				opt(&cfg)
			}
		}

		var sem chan struct{}
		if cfg.maxConcurrent > 0 {
			sem = make(chan struct{}, cfg.maxConcurrent)
		}

		baseCtx, baseCancel := context.WithCancel(context.Background())
		svc := &Service{
			connProvider:   host.ConnProvider(),
			auth:           cfg.auth,
			timeout:        cfg.timeout,
			sem:            sem,
			baseCtx:        baseCtx,
			baseCancel:     baseCancel,
			msgHandlers:    make(map[string]MsgHandler),
			streamHandlers: make(map[string]StreamHandler),
		}
		return &rpcServer{svc: svc}, nil
	})
	if err != nil {
		return nil, err
	}
	srv, ok := impl.(*rpcServer)
	if !ok || srv == nil || srv.svc == nil {
		return nil, errors.New("messaging: unexpected gRPC service implementation registered")
	}
	return srv.svc, nil
}

// Close cancels the base context used for outbound async sends and streams.
func (s *Service) Close() {
	if s.baseCancel != nil {
		s.baseCancel()
	}
}

// Handle registers (or clears, if handler == nil) the unary message handler for serviceID.
// Safe to call dynamically at runtime after host.Start().
func (s *Service) Handle(serviceID string, handler MsgHandler) error {
	if err := discovery.ValidateServiceID(serviceID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if handler == nil {
		delete(s.msgHandlers, serviceID)
		return nil
	}
	s.msgHandlers[serviceID] = handler
	return nil
}

// HandleStream registers (or clears, if handler == nil) the bidirectional stream handler for serviceID.
// Safe to call dynamically at runtime after host.Start().
func (s *Service) HandleStream(serviceID string, handler StreamHandler) error {
	if err := discovery.ValidateServiceID(serviceID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if handler == nil {
		delete(s.streamHandlers, serviceID)
		return nil
	}
	s.streamHandlers[serviceID] = handler
	return nil
}

// Send dispatches a synchronous unary message routed to serviceID on addr.
func (s *Service) Send(ctx context.Context, serviceID, addr string, data []byte) ([]byte, error) {
	if ctx == nil {
		ctx = s.baseCtx
	}
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { <-s.sem }()
	}

	cc, err := s.connProvider(ctx, addr)
	if err != nil {
		return nil, err
	}
	if cc == nil {
		return nil, errors.New("messaging: conn provider returned nil connection")
	}

	callCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		callCtx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	if serviceID != "" {
		callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs(ServiceIDMetadataKey, serviceID))
	}

	resp, err := messagingpb.NewMessagingClient(cc).Send(callCtx, &messagingpb.Msg{Content: data})
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		return resp.GetContent(), errors.New(resp.GetError())
	}
	return resp.GetContent(), nil
}

// SendAsync dispatches a unary message in a goroutine and delivers the result on the returned channel.
func (s *Service) SendAsync(serviceID, addr string, data []byte) chan *Message {
	ch := make(chan *Message, 1)
	go func() {
		defer close(ch)
		respData, err := s.Send(s.baseCtx, serviceID, addr, data)
		if err != nil && respData == nil {
			ch <- &Message{Error: err}
			return
		}
		ch <- &Message{Data: respData, Error: err}
	}()
	return ch
}

// OpenStream opens a bidirectional byte stream routed to serviceID on addr.
// Close inputCh when done sending; replyCh is closed automatically when the stream terminates.
func (s *Service) OpenStream(ctx context.Context, serviceID, addr string) (inputCh chan<- []byte, replyCh <-chan []byte) {
	in := make(chan []byte)
	out := make(chan []byte)
	go s.runOutboundStream(ctx, serviceID, addr, in, out)
	return in, out
}

func (s *Service) runOutboundStream(ctx context.Context, serviceID, addr string, input, reply chan []byte) {
	defer close(reply)

	if ctx == nil {
		ctx = s.baseCtx
	}
	cc, err := s.connProvider(ctx, addr)
	if err != nil {
		log.Error("messaging: dial failed", "addr", addr, "err", err)
		return
	}
	if cc == nil {
		log.Error("messaging: conn provider returned nil connection", "addr", addr)
		return
	}

	callCtx := ctx
	if serviceID != "" {
		callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs(ServiceIDMetadataKey, serviceID))
	}

	srv, err := messagingpb.NewMessagingClient(cc).Stream(callCtx)
	if err != nil {
		log.Error("messaging: stream open failed", "addr", addr, "err", err)
		return
	}

	streamCtx := srv.Context()
	done := make(chan struct{})
	var once sync.Once
	safeCloseDone := func() {
		once.Do(func() {
			close(done)
		})
	}

	go func() {
		for content := range input {
			if err := srv.Send(&messagingpb.Msg{Content: content}); err != nil {
				log.Error(err.Error())
				break
			}
		}
		if err := srv.CloseSend(); err != nil {
			log.Error(err.Error())
		}
	}()

	go func() {
		for {
			resp, err := srv.Recv()
			if err == io.EOF {
				safeCloseDone()
				return
			}
			if err != nil {
				log.Error(err.Error())
				safeCloseDone()
				return
			}
			reply <- resp.GetContent()
		}
	}()

	go func() {
		<-streamCtx.Done()
		safeCloseDone()
	}()

	<-done
}

// Send implements messagingpb.MessagingServer.
func (r *rpcServer) Send(ctx context.Context, args *messagingpb.Msg) (*messagingpb.MsgResponse, error) {
	s := r.svc
	if err := s.auth(ctx); err != nil {
		return nil, err
	}

	serviceID, err := serviceIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	handler := s.msgHandlers[serviceID]
	s.mu.RUnlock()
	if handler == nil {
		return nil, status.Errorf(codes.NotFound, "no message handler registered for service %q", serviceID)
	}

	replyContent, err := handler(args.GetContent())
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	return &messagingpb.MsgResponse{Content: replyContent, Error: errMsg}, nil
}

// Stream implements messagingpb.MessagingServer.
func (r *rpcServer) Stream(srv messagingpb.Messaging_StreamServer) error {
	s := r.svc
	ctx := srv.Context()
	if err := s.auth(ctx); err != nil {
		return err
	}

	serviceID, err := serviceIDFromContext(ctx)
	if err != nil {
		return err
	}

	s.mu.RLock()
	handler := s.streamHandlers[serviceID]
	s.mu.RUnlock()
	if handler == nil {
		return status.Errorf(codes.NotFound, "no stream handler registered for service %q", serviceID)
	}

	input := make(chan []byte)
	reply := make(chan []byte)

	replyDone := make(chan struct{})
	go func() {
		defer close(replyDone)
		for resp := range reply {
			if err := srv.Send(&messagingpb.MsgResponse{Content: resp}); err != nil {
				log.Error(err.Error())
			}
		}
	}()

	go handler(input, reply)

	var recvErr error
	for {
		select {
		case <-ctx.Done():
			recvErr = ctx.Err()
			goto done
		default:
		}

		req, err := srv.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			recvErr = err
			break
		}

		select {
		case <-ctx.Done():
			recvErr = ctx.Err()
			goto done
		case input <- req.GetContent():
		}
	}

done:
	close(input)
	<-replyDone

	if recvErr != nil && recvErr != io.EOF {
		return recvErr
	}
	return nil
}

func serviceIDFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.InvalidArgument, "missing service-id metadata")
	}
	vals := md.Get(ServiceIDMetadataKey)
	if len(vals) != 1 || vals[0] == "" {
		return "", status.Error(codes.InvalidArgument, "missing or invalid service-id metadata")
	}
	if err := discovery.ValidateServiceID(vals[0]); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "invalid service-id %q: %v", vals[0], err)
	}
	return vals[0], nil
}
