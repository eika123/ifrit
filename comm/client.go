package comm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"time"

	pb "github.com/eika123/ifrit/protobuf"
	log "github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

const defaultRPCTimeout = 10 * time.Second

var (
	errReachable = errors.New("Remote entity not reachable")
	errNilConfig = errors.New("Provided tls config was nil")
)

type gRPCClient struct {
	allConnections  map[string]*conn
	connectionMutex sync.RWMutex

	dialOptions []grpc.DialOption
}

type conn struct {
	pb.GossipClient
	cc *grpc.ClientConn
}

func newClient(
	config *tls.Config,
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

	if compress := viper.GetBool("use_compression"); compress {
		dialOptions = append(dialOptions,
			grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	}

	return &gRPCClient{
		allConnections: make(map[string]*conn),
		dialOptions:    dialOptions,
	}, nil
}

func (c *gRPCClient) Gossip(addr string, args *pb.State) (*pb.StateResponse, error) {
	conn, err := c.connection(addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	// rpc call on remote connection peer.
	reply, err := conn.Spread(ctx, args)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (c *gRPCClient) Send(addr string, args *pb.Msg) (*pb.MsgResponse, error) {
	conn, err := c.connection(addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRPCTimeout)
	defer cancel()

	return conn.Messenger(ctx, args)
}

// ClientConn returns a pooled, mTLS-authenticated gRPC ClientConnInterface for addr.
// Callers must not close the returned connection; lifecycle is managed by Comm.
func (c *gRPCClient) ClientConn(addr string) (grpc.ClientConnInterface, error) {
	conn, err := c.connection(addr)
	if err != nil {
		return nil, err
	}
	return conn.cc, nil
}

func (c *gRPCClient) StreamMessenger(addr string, input, reply chan []byte) error {
	conn, err := c.connection(addr)
	if err != nil {
		return err
	}

	srv, err := conn.Stream(context.Background())
	if err != nil {
		return err
	}

	ctx := srv.Context()
	done := make(chan bool)
	defer close(reply)

	// Concurrency guard: Multiple goroutines (Recv EOF, Recv error, or ctx.Done) can
	// encounter exit conditions concurrently. sync.Once ensures done is closed exactly once,
	// preventing "close of closed channel" panics while avoiding deadlocks on <-done.
	var once sync.Once
	safeCloseDone := func() {
		once.Do(func() {
			close(done)
		})
	}

	// Sending messages from input stream to the server.
	// Runs until the producer closes the channel
	go func() {
		for content := range input {
			msg := &pb.Msg{
				Content: content,
			}

			if err := srv.Send(msg); err != nil {
				log.Error(err.Error())
				break
			}
		}

		if err := srv.CloseSend(); err != nil {
			log.Error(err.Error())
		}
	}()

	// Receiving replies from the server
	go func() {
		for {
			req, err := srv.Recv()
			if err == io.EOF {
				safeCloseDone()
				return
			}

			if err != nil {
				log.Error(err.Error())
				safeCloseDone()
				return
			}

			reply <- req.GetContent()
		}
	}()

	go func() {
		<-ctx.Done()
		if err := ctx.Err(); err != nil {
			log.Error(err.Error())
		}
		safeCloseDone()
	}()

	<-done

	return nil
}

func (c *gRPCClient) CloseConn(addr string) {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()

	if conn, ok := c.allConnections[addr]; ok {
		conn.cc.Close()
		delete(c.allConnections, addr)
	}
}

// CloseAll closes and removes all pooled gRPC client connections.
func (c *gRPCClient) CloseAll() {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()

	for addr, conn := range c.allConnections {
		if conn != nil && conn.cc != nil {
			_ = conn.cc.Close()
		}
		delete(c.allConnections, addr)
	}
}

func (c *gRPCClient) dial(addr string) (*conn, error) {
	c.connectionMutex.Lock()
	defer c.connectionMutex.Unlock()

	if conn, ok := c.allConnections[addr]; ok {
		return conn, nil
	}

	cc, err := grpc.Dial(addr, c.dialOptions...)
	if err != nil {
		return nil, err
	} else {
		connection := &conn{
			GossipClient: pb.NewGossipClient(cc),
			cc:           cc,
		}
		c.allConnections[addr] = connection

		return connection, nil
	}
}

func (c *gRPCClient) connection(addr string) (*conn, error) {
	if conn := c.getConnection(addr); conn != nil {
		return conn, nil
	} else {
		return c.dial(addr)
	}
}

func (c *gRPCClient) getConnection(addr string) *conn {
	c.connectionMutex.RLock()
	defer c.connectionMutex.RUnlock()

	return c.allConnections[addr]
}
