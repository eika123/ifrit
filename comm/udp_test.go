package comm

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/eika123/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingSigner struct {
	mu         sync.Mutex
	lastSigned []byte
}

func (d *recordingSigner) Sign(data []byte) ([]byte, []byte, error) {
	d.mu.Lock()
	d.lastSigned = append([]byte(nil), data...)
	d.mu.Unlock()
	return []byte("dummy-r"), []byte("dummy-s"), nil
}

func (d *recordingSigner) last() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.lastSigned...)
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
	server.SetFingerprints(Fingerprints{
		Data:        expectedFPData,
		Accusations: expectedFPAcc,
		View:        expectedFPView,
	})

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
	assert.Equal(t, PongContent(nonce, expectedFPData, expectedFPAcc, expectedFPView), signer.last(), "signature must cover PongContent(nonce, fpData, fpAcc, fpView)")

	// Verify dynamic provider updates are reflected on subsequent pings without races.
	var fpMu sync.RWMutex
	dynamicFP := Fingerprints{
		Data:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Accusations: []byte{8, 7, 6, 5, 4, 3, 2, 1},
		View:        []byte{9, 9, 9, 9, 9, 9, 9, 9},
	}
	server.SetFingerprintsProvider(func() Fingerprints {
		fpMu.RLock()
		defer fpMu.RUnlock()
		return dynamicFP
	})
	pong2, err := server.Ping(conn.LocalAddr().String(), ping)
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, pong2.GetFingerprintData())

	fpMu.Lock()
	dynamicFP.Data = []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	fpMu.Unlock()
	pong3, err := server.Ping(conn.LocalAddr().String(), ping)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}, pong3.GetFingerprintData())
}

func TestPongContent_FieldBoundaryShifting(t *testing.T) {
	nonce := []byte("test-nonce-12345678901234567890")
	val := []byte("boundary-test")

	// Shift bytes between fpData and fpAcc:
	// Case 1: fpData has val, fpAcc is nil
	c1 := PongContent(nonce, val, nil, nil)
	// Case 2: fpData is nil, fpAcc has val
	c2 := PongContent(nonce, nil, val, nil)
	// Case 3: fpData and fpAcc are nil, fpView has val
	c3 := PongContent(nonce, nil, nil, val)

	assert.NotEqual(t, c1, c2, "framed PongContent must prevent field-boundary shifting between fpData and fpAcc")
	assert.NotEqual(t, c1, c3, "framed PongContent must prevent field-boundary shifting between fpData and fpView")
	assert.NotEqual(t, c2, c3, "framed PongContent must prevent field-boundary shifting between fpAcc and fpView")
}
