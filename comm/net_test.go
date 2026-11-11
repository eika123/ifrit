package comm_test

import (
	"net"
	"testing"

	"github.com/joonnna/ifrit/comm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetListener(t *testing.T) {
	l, addr, err := comm.GetListener("127.0.0.1", 0)
	require.NoError(t, err)
	require.NotNil(t, l)
	defer l.Close()

	assert.Contains(t, addr, "127.0.0.1:")
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.NotEmpty(t, port)
}

func TestListenUdp(t *testing.T) {
	conn, addr, err := comm.ListenUdp("127.0.0.1", 0)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	assert.Contains(t, addr, "127.0.0.1:")
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.NotEmpty(t, port)
}

func TestListenOnPort(t *testing.T) {
	l, err := comm.ListenOnPort(0)
	require.NoError(t, err)
	require.NotNil(t, l)
	defer l.Close()
}

func TestGetLocalIP(t *testing.T) {
	ip := comm.GetLocalIP()
	// In some sandboxed or disconnected container environments this may be empty,
	// but if present it must parse as a valid IP and not be loopback.
	if ip != "" {
		parsed := net.ParseIP(ip)
		require.NotNil(t, parsed)
		assert.False(t, parsed.IsLoopback())
		assert.NotNil(t, parsed.To4())
	}
}
