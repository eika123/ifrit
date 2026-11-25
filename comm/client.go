package comm

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

var (
	errReachable = errors.New("Remote entity not reachable")
	errNilConfig = errors.New("Provided tls config was nil")
)

type gRPCClient struct {
	allConnections  map[string]*grpc.ClientConn
	connectionMutex sync.RWMutex

	dialOptions []grpc.DialOption
}

func newClient(
	config *tls.Config,
	useCompression bool,
	unaryInterceptors []grpc.UnaryClientInterceptor,
	streamInterceptors []grpc.StreamClientInterceptor,
) (*gRPCClient, error) {
	var dialOptions []grpc.DialOption

	if config == nil {
		return nil, errNilConfig
	}

	if len(unaryInterceptors) > 0 {
		dialOptions = append(dialOptions, grpc.WithChainUnaryInterceptor(unaryInterceptors...))
	}
	if len(streamInterceptors) > 0 {
		dialOptions = append(dialOptions, grpc.WithChainStreamInterceptor(streamInterceptors...))
	}

	creds := credentials.NewTLS(config)
	dialOptions = append(dialOptions, grpc.WithTransportCredentials(creds))
	dialOptions = append(dialOptions, grpc.WithBackoffMaxDelay(time.Minute*1))
	dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                time.Minute * 1,
		Timeout:             30 * time.Second,
		PermitWithoutStream: true,
	}))

	if useCompression {
		dialOptions = append(dialOptions,
			grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	}

	return &gRPCClient{
		allConnections: make(map[string]*grpc.ClientConn),
		dialOptions:    dialOptions,
	}, nil
}

// ClientConn returns a pooled, mTLS-authenticated gRPC ClientConnInterface for addr.
// Callers must not close the returned connection; lifecycle is managed by Comm.
func (c *gRPCClient) ClientConn(addr string) (grpc.ClientConnInterface, error) {
	return c.connection(addr)
}

func (c *gRPCClient) CloseConn(addr string) {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()

	if cc, ok := c.allConnections[addr]; ok {
		cc.Close()
		delete(c.allConnections, addr)
	}
}

// CloseAll closes and removes all pooled gRPC client connections.
func (c *gRPCClient) CloseAll() {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()

	for addr, cc := range c.allConnections {
		if cc != nil {
			_ = cc.Close()
		}
		delete(c.allConnections, addr)
	}
}

func (c *gRPCClient) dial(addr string) (*grpc.ClientConn, error) {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()

	if cc, ok := c.allConnections[addr]; ok {
		return cc, nil
	}

	cc, err := grpc.Dial(addr, c.dialOptions...)
	if err != nil {
		return nil, err
	}
	c.allConnections[addr] = cc
	return cc, nil
}

func (c *gRPCClient) connection(addr string) (*grpc.ClientConn, error) {
	if cc := c.getConnection(addr); cc != nil {
		return cc, nil
	}
	return c.dial(addr)
}

func (c *gRPCClient) getConnection(addr string) *grpc.ClientConn {
	c.connectionMutex.RLock()
	defer c.connectionMutex.RUnlock()

	return c.allConnections[addr]
}
