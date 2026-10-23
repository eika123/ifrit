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

	expectedFPData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34}
	expectedFPAcc := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	expectedFPView := []byte{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	server.SetFingerprintData(expectedFPData)
	server.SetFingerprintAccusations(expectedFPAcc)
	server.SetFingerprintView(expectedFPView)

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
	assert.Equal(t, expectedFPData, pong.GetFingerprintData())
	assert.Equal(t, expectedFPAcc, pong.GetFingerprintAccusations())
	assert.Equal(t, expectedFPView, pong.GetFingerprintView())
	assert.Equal(t, PongContent(nonce, expectedFPData, expectedFPAcc, expectedFPView), signer.lastSigned, "signature must cover PongContent(nonce, fpData, fpAcc, fpView)")
}
