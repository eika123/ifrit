package core

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	pb "github.com/eika123/ifrit/protobuf"
	log "github.com/inconshreveable/log15"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// ServiceIDMetadataKey is the gRPC metadata key routing Messaging Send and Stream RPCs to a service.
	ServiceIDMetadataKey    = "service-id"
	defaultMessagingTimeout = 10 * time.Second
)

type messagingRPCServer struct {
	pb.UnimplementedMessagingServer
	node *Node
}

func (s *messagingRPCServer) Send(ctx context.Context, args *pb.Msg) (*pb.MsgResponse, error) {
	return s.node.handleSend(ctx, args)
}

func (s *messagingRPCServer) Stream(srv pb.Messaging_StreamServer) error {
	return s.node.handleStream(srv)
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

func (n *Node) handleSend(ctx context.Context, args *pb.Msg) (*pb.MsgResponse, error) {
	var errMsg string
	var replyContent []byte

	_, err := n.validateCtx(ctx)
	if err != nil {
		return nil, err
	}

	serviceID, err := serviceIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	handler := n.getServiceMsgHandler(serviceID)
	if handler == nil {
		return nil, status.Errorf(codes.NotFound, "no message handler registered for service %q", serviceID)
	}

	replyContent, err = handler(args.GetContent())
	if err != nil {
		errMsg = err.Error()
	}
	return &pb.MsgResponse{Content: replyContent, Error: errMsg}, nil
}

func (n *Node) handleStream(srv pb.Messaging_StreamServer) error {
	ctx := srv.Context()
	if _, err := n.validateCtx(ctx); err != nil {
		return err
	}

	serviceID, err := serviceIDFromContext(ctx)
	if err != nil {
		return err
	}

	handler := n.getServiceStreamHandler(serviceID)
	if handler == nil {
		return status.Errorf(codes.NotFound, "no stream handler registered for service %q", serviceID)
	}

	// Channels used for bi-directional communication
	input := make(chan []byte)
	reply := make(chan []byte)

	// Concurrency guard: Ensure replyStream finishes transmitting all generated responses
	// before Stream() returns. Returning early on io.EOF cancels the gRPC stream context
	// on the server, prematurely severing the connection and dropping in-flight responses.
	replyDone := make(chan struct{})
	go func() {
		defer close(replyDone)
		n.replyStream(reply, srv)
	}()

	go n.runStreamHandler(handler, input, reply)

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
	// Signal to stream handler that client has closed its send side (no more inputs).
	close(input)

	// Wait for handler to finish processing remaining messages and replyStream to flush
	// all replies across the gRPC transport before completing the RPC.
	<-replyDone

	if recvErr != nil && recvErr != io.EOF {
		return recvErr
	}
	return nil
}

func (n *Node) replyStream(reply chan []byte, srv pb.Messaging_StreamServer) {
	for resp := range reply {
		responseMsg := &pb.MsgResponse{
			Content: resp,
		}

		if err := srv.Send(responseMsg); err != nil {
			log.Error(err.Error())
		}
	}
}

func (n *Node) runStreamHandler(handler streamMsg, input, reply chan []byte) {
	handler(input, reply)
}

func (n *Node) sendServiceMsg(serviceID, dest string, ch chan *Message, msg *pb.Msg) {
	defer close(ch)

	cc, err := n.comm.ClientConn(dest)
	if err != nil {
		log.Error(err.Error())
		ch <- nil
		return
	}
	if cc == nil {
		log.Error("comm returned nil client connection")
		ch <- nil
		return
	}

	baseCtx := n.syncCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, defaultMessagingTimeout)
	defer cancel()
	if serviceID != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(ServiceIDMetadataKey, serviceID))
	}

	reply, err := pb.NewMessagingClient(cc).Send(ctx, msg)
	if err != nil {
		log.Error(err.Error())
		ch <- nil
		return
	}

	if reply.GetError() == "" {
		err = nil
	} else {
		err = errors.New(reply.GetError())
	}

	ch <- &Message{Data: reply.GetContent(), Error: err}
}

func (n *Node) openServiceStream(serviceID, dest string, input, reply chan []byte) {
	defer close(reply)

	cc, err := n.comm.ClientConn(dest)
	if err != nil {
		log.Error(err.Error())
		return
	}
	if cc == nil {
		log.Error("comm returned nil client connection")
		return
	}

	callCtx := n.syncCtx
	if callCtx == nil {
		callCtx = context.Background()
	}
	if serviceID != "" {
		callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs(ServiceIDMetadataKey, serviceID))
	}

	srv, err := pb.NewMessagingClient(cc).Stream(callCtx)
	if err != nil {
		log.Error(err.Error())
		return
	}

	ctx := srv.Context()
	done := make(chan bool)

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
	// Runs until the producer closes the channel.
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

	// Receiving replies from the server.
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
}
