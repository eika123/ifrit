package messaging_test

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/eika123/ifrit"
	"github.com/eika123/ifrit/core"
	"github.com/eika123/ifrit/crypto/cauth"
	"github.com/eika123/ifrit/services/messaging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func startTestCA(t *testing.T) string {
	t.Helper()
	caDir := t.TempDir()
	ca, err := cauth.NewCa(caDir)
	require.NoError(t, err)
	require.NoError(t, ca.NewGroup(3, 5))
	require.NoError(t, ca.SavePrivateKey())
	require.NoError(t, ca.SaveCertificate())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	go ca.Start("127.0.0.1", strconv.Itoa(port))
	t.Cleanup(ca.Shutdown)

	caAddr := fmt.Sprintf("127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		conn, dialErr := net.DialTimeout("tcp", caAddr, 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 3*time.Second, 25*time.Millisecond)
	return caAddr
}

func newTestClient(t *testing.T, caAddr string) *ifrit.Client {
	t.Helper()
	c, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: "127.0.0.1",
		CertPath: t.TempDir(),
		CAAddr:   caAddr,
	})
	require.NoError(t, err)
	t.Cleanup(c.Stop)
	return c
}

func TestMessaging_OptInIsolationAndDynamicRuntimeHandlers(t *testing.T) {
	caAddr := startTestCA(t)

	clientA := newTestClient(t, caAddr)
	clientB := newTestClient(t, caAddr)
	clientNoMsg := newTestClient(t, caAddr)

	msgA, err := messaging.Register(clientA, messaging.WithMaxConcurrent(4))
	require.NoError(t, err)
	defer msgA.Close()

	msgB, err := messaging.Register(clientB)
	require.NoError(t, err)
	defer msgB.Close()

	// Announce a store-less "chat" service on both A and B.
	_, err = clientA.Service("chat")
	require.NoError(t, err)
	_, err = clientB.Service("chat")
	require.NoError(t, err)

	// Start all three clients BEFORE registering handlers on msgB to verify
	// handlers can be attached dynamically at runtime once Messaging is mounted.
	go clientA.Start()
	go clientB.Start()
	go clientNoMsg.Start()

	// Wait for all gRPC listeners to be serving, then verify registering messaging
	// after Start() fails cleanly with core.ErrAlreadyStarted.
	for _, addr := range []string{clientA.Addr(), clientB.Addr(), clientNoMsg.Addr()} {
		require.Eventually(t, func() bool {
			conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if dialErr != nil {
				return false
			}
			_ = conn.Close()
			return true
		}, 3*time.Second, 15*time.Millisecond)
	}
	_, regErr := messaging.Register(clientNoMsg)
	assert.ErrorIs(t, regErr, core.ErrAlreadyStarted)

	// Dynamically bind "chat" and "dht" handlers on B at runtime.
	require.NoError(t, msgB.Handle("chat", func(b []byte) ([]byte, error) {
		return append([]byte("chat:"), b...), nil
	}))
	require.NoError(t, msgB.Handle("dht", func(b []byte) ([]byte, error) {
		return append([]byte("dht:"), b...), nil
	}))
	require.NoError(t, msgB.HandleStream("chat", func(in, out chan []byte) {
		defer close(out)
		for m := range in {
			out <- append([]byte("chat-stream:"), m...)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Unary Send routes independently by service-id.
	gotChat, err := msgA.Send(ctx, "chat", clientB.Addr(), []byte("hi"))
	require.NoError(t, err)
	assert.Equal(t, "chat:hi", string(gotChat))

	gotDHT, err := msgA.Send(ctx, "dht", clientB.Addr(), []byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, "dht:ping", string(gotDHT))

	// 2. Async SendAsync works.
	asyncResp := <-msgA.SendAsync("chat", clientB.Addr(), []byte("async"))
	require.NotNil(t, asyncResp)
	require.NoError(t, asyncResp.Error)
	assert.Equal(t, "chat:async", string(asyncResp.Data))

	// 3. Bidirectional OpenStream works.
	inCh, outCh := msgA.OpenStream(ctx, "chat", clientB.Addr())
	inCh <- []byte("hello")
	close(inCh)
	assert.Equal(t, "chat-stream:hello", string(<-outCh))

	// 4. Unregistered service-id on a Messaging-enabled node returns codes.NotFound.
	_, err = msgA.Send(ctx, "unknown-svc", clientB.Addr(), []byte("x"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// 5. Node that never opted into messaging.Register returns codes.Unimplemented.
	_, err = msgA.Send(ctx, "chat", clientNoMsg.Addr(), []byte("x"))
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestMessaging_OpenAttachMultiServiceAndClose(t *testing.T) {
	caAddr := startTestCA(t)

	clientA := newTestClient(t, caAddr)
	clientB := newTestClient(t, caAddr)
	clientNoMsg := newTestClient(t, caAddr)

	// Open two independent services ("chat" and "dht") on the same clients via
	// one-line messaging.Open; both must share the single Messaging gRPC mount.
	chatA, err := messaging.Open(clientA, "chat", messaging.WithTransportOptions(messaging.WithMaxConcurrent(4)))
	require.NoError(t, err)
	dhtA, err := messaging.Open(clientA, "dht")
	require.NoError(t, err)

	chatB, err := messaging.Open(clientB, "chat",
		messaging.WithMsgHandler(func(b []byte) ([]byte, error) {
			return append([]byte("chat:"), b...), nil
		}),
		messaging.WithStreamHandler(func(in, out chan []byte) {
			defer close(out)
			for m := range in {
				out <- append([]byte("chat-stream:"), m...)
			}
		}),
	)
	require.NoError(t, err)

	// Bottom-up layering: create a base ServiceEndpoint first, then Attach messaging.
	baseDHTB, err := clientB.Service("dht")
	require.NoError(t, err)
	dhtB, err := messaging.Attach(clientB, baseDHTB, messaging.WithMsgHandler(func(b []byte) ([]byte, error) {
		return append([]byte("dht:"), b...), nil
	}))
	require.NoError(t, err)

	go clientA.Start()
	go clientB.Start()
	go clientNoMsg.Start()

	for _, addr := range []string{clientA.Addr(), clientB.Addr(), clientNoMsg.Addr()} {
		require.Eventually(t, func() bool {
			conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if dialErr != nil {
				return false
			}
			_ = conn.Close()
			return true
		}, 3*time.Second, 15*time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Scoped Send / OpenStream work without repeating service IDs.
	gotChat, err := chatA.Send(ctx, clientB.Addr(), []byte("hi"))
	require.NoError(t, err)
	assert.Equal(t, "chat:hi", string(gotChat))

	gotDHT, err := dhtA.Send(ctx, clientB.Addr(), []byte("get"))
	require.NoError(t, err)
	assert.Equal(t, "dht:get", string(gotDHT))

	inCh, outCh := chatA.OpenStream(ctx, clientB.Addr())
	inCh <- []byte("hello")
	close(inCh)
	assert.Equal(t, "chat-stream:hello", string(<-outCh))

	// Opening a new messaging endpoint AFTER Start() succeeds when Messaging was
	// already mounted on clientB before Start().
	lateB, err := messaging.Open(clientB, "late-svc", messaging.WithMsgHandler(func(b []byte) ([]byte, error) {
		return append([]byte("late:"), b...), nil
	}))
	require.NoError(t, err)
	lateA, err := messaging.Open(clientA, "late-svc")
	require.NoError(t, err)
	gotLate, err := lateA.Send(ctx, clientB.Addr(), []byte("ok"))
	require.NoError(t, err)
	assert.Equal(t, "late:ok", string(gotLate))

	// Opening messaging AFTER Start() on a client that never mounted Messaging fails cleanly.
	_, err = messaging.Open(clientNoMsg, "too-late")
	assert.ErrorIs(t, err, core.ErrAlreadyStarted)

	// Closing chatB clears its messaging handlers (codes.NotFound) without affecting dhtB or lateB.
	require.NoError(t, chatB.Close())
	_, err = chatA.Send(ctx, clientB.Addr(), []byte("after-close"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	gotDHTAfter, err := dhtA.Send(ctx, clientB.Addr(), []byte("still-up"))
	require.NoError(t, err)
	assert.Equal(t, "dht:still-up", string(gotDHTAfter))
	_ = dhtB.Close()
	_ = lateB.Close()
}
