package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/joonnna/ifrit"
	"github.com/joonnna/ifrit/cauth"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestStreamingExample(t *testing.T) {
	// 1. Create a dedicated temporary directory for test CA state
	caDir, err := os.MkdirTemp("", "ifrit-ca-stream-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(caDir)

	ca, err := cauth.NewCa(caDir)
	require.NoError(t, err)

	err = ca.NewGroup(3, 5)
	require.NoError(t, err)

	// Save initial CA state
	require.NoError(t, ca.SavePrivateKey())
	require.NoError(t, ca.SaveCertificate())

	// Find an available local port for the CA
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	caPort := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	go ca.Start("127.0.0.1", strconv.Itoa(caPort))
	defer ca.Shutdown()

	// Wait for CA HTTP listener to become ready
	caReady := false
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", caPort), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			caReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.True(t, caReady, "test CA failed to start")

	// Point ifrit clients to the ephemeral test CA
	viper.Set("ca_addr", fmt.Sprintf("127.0.0.1:%d", caPort))

	// Also ensure client crypto directories are isolated
	clientDir, err := os.MkdirTemp("", "ifrit-client-crypto-*")
	require.NoError(t, err)
	defer os.RemoveAll(clientDir)

	masterDir, err := os.MkdirTemp("", "ifrit-master-crypto-*")
	require.NoError(t, err)
	defer os.RemoveAll(masterDir)

	// Concurrency guard: Coordinate teardown so the background client.Start() and
	// master.Start() goroutines cleanly finish and exit after Stop() unblocks them,
	// preventing goroutine leakage and data races between test runs.
	var wg sync.WaitGroup
	wg.Add(2)
	// Create test app with isolated crypto paths
	clientApp, err := newTestApp(clientDir, masterDir, &wg)
	require.NoError(t, err)
	defer func() {
		clientApp.master.Stop()
		clientApp.client.Stop()
		wg.Wait()
	}()

	// Execute bidirectional streaming exchange
	err = clientApp.Stream()
	require.NoError(t, err, "streaming exchange between master and client should succeed")
}

func newTestApp(clientCryptoPath, masterCryptoPath string, wg *sync.WaitGroup) (*App, error) {
	client, err := ifrit.NewClient(&ifrit.Config{
		New:            true,
		Hostname:       "localhost",
		CryptoUnitPath: clientCryptoPath,
	})
	if err != nil {
		return nil, err
	}
	client.RegisterStreamHandler(streamHandler)
	// Pass client by value as argument to avoid closure capture races on local variables.
	go func(c *ifrit.Client) {
		defer wg.Done()
		c.Start()
	}(client)

	master, err := ifrit.NewClient(&ifrit.Config{
		New:            true,
		Hostname:       "localhost",
		CryptoUnitPath: masterCryptoPath,
	})
	if err != nil {
		client.Stop()
		return nil, err
	}
	// Pass master by value as argument to avoid closure capture races on local variables.
	go func(m *ifrit.Client) {
		defer wg.Done()
		m.Start()
	}(master)

	return &App{
		master: master,
		client: client,
	}, nil
}
