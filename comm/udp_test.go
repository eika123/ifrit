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

type recordingSigner struct {
	lastSigned []byte
}

func (d *recordingSigner) Sign(data []byte) ([]byte, []byte, error) {
	d.lastSigned = append([]byte(nil), data...)
	return []byte("dummy-r"), []byte("dummy-s"), nil
}

func TestUDPServer_PongCarriesFingerprint(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	signer := &recordingSigner{}
	server, err := NewUdpServer(signer, conn, time.Second*2)
	require.NoError(t, err)

	expectedFP := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34}
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
	assert.Equal(t, PongContent(nonce, expectedFP), signer.lastSigned, "signature must cover PongContent(nonce, fingerprint)")
}
