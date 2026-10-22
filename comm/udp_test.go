package comm

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummySigner struct{}

func (d *dummySigner) Sign(data []byte) ([]byte, []byte, error) {
	return []byte("dummy-r"), []byte("dummy-s"), nil
}

func TestUDPServer_PongCarriesFingerprint(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	server, err := NewUdpServer(&dummySigner{}, conn, time.Second*2)
	require.NoError(t, err)

	const expectedFP uint64 = 0xDEADBEEFCAFE1234
	server.SetFingerprint(expectedFP)

	go server.Start()
	defer server.Stop()

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	ping := &pb.Ping{Nonce: nonce}
	pong, err := server.Ping(conn.LocalAddr().String(), ping)
	require.NoError(t, err)

	assert.Equal(t, nonce, pong.GetNonce())
	assert.Equal(t, []byte("dummy-r"), pong.GetSignature().GetR())
	assert.Equal(t, []byte("dummy-s"), pong.GetSignature().GetS())
	assert.Equal(t, expectedFP, pong.GetFingerprint())
}
