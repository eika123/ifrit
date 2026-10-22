package core

import (
	"errors"
	"testing"
	"time"

	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPingService struct {
	customPong func(p *pb.Ping) (*pb.Pong, error)
}

func (s *mockPingService) Pause(time.Duration) {}
func (s *mockPingService) Start()              {}
func (s *mockPingService) Stop()               {}

func (s *mockPingService) Ping(addr string, p *pb.Ping) (*pb.Pong, error) {
	if s.customPong != nil {
		return s.customPong(p)
	}
	return nil, errors.New("connection timeout")
}

func createTestPeer() (*discovery.Peer, *cryptoStub, error) {
	priv, err := genKeys()
	if err != nil {
		return nil, nil, err
	}
	cert := genCert(priv, 1)
	cs := &cryptoStub{priv: priv}
	v, err := discovery.NewView(1, cert, nil, cs)
	if err != nil {
		return nil, nil, err
	}
	return v.Self(), cs, nil
}

func setupFDTest(t *testing.T) (*failureDetector, *mockPingService, *cryptoStub, *discovery.Peer) {
	destPeer, cs, err := createTestPeer()
	require.NoError(t, err)

	ps := &mockPingService{}
	fd := newFd(ps, cs, 3)

	return fd, ps, cs, destPeer
}

func TestFailureDetector_ProbeSuccess(t *testing.T) {
	fd, ps, cs, destPeer := setupFDTest(t)

	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(p.GetNonce())
		if err != nil {
			return nil, err
		}
		return &pb.Pong{
			Nonce: p.GetNonce(),
			Signature: &pb.Signature{
				R: r,
				S: s,
			},
			Fingerprint: 0x12345678,
		}, nil
	}

	destPeer.IncrementPingCount()
	assert.Equal(t, uint32(1), destPeer.NumPing())

	err := fd.probe(destPeer)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), destPeer.NumPing(), "successful pong should reset ping count")
}

func TestFailureDetector_ProbeTransportFailuresAndThreshold(t *testing.T) {
	fd, ps, _, destPeer := setupFDTest(t)

	networkErr := errors.New("network unreachable")
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		return nil, networkErr
	}

	// 1st failure: returns underlying error, ping count becomes 1
	err := fd.probe(destPeer)
	assert.Equal(t, networkErr, err)
	assert.Equal(t, uint32(1), destPeer.NumPing())

	// 2nd failure: returns underlying error, ping count becomes 2
	err = fd.probe(destPeer)
	assert.Equal(t, networkErr, err)
	assert.Equal(t, uint32(2), destPeer.NumPing())

	// 3rd failure: reaches maxFailedPings (3), returns errDead
	err = fd.probe(destPeer)
	assert.Equal(t, errDead, err)
	assert.Equal(t, uint32(3), destPeer.NumPing())
}

func TestFailureDetector_ProbeRecoveryResetsCount(t *testing.T) {
	fd, ps, cs, destPeer := setupFDTest(t)

	// Simulate one failed probe
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		return nil, errors.New("temporary packet drop")
	}
	err := fd.probe(destPeer)
	require.Error(t, err)
	assert.Equal(t, uint32(1), destPeer.NumPing())

	// Followed by a successful probe
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(p.GetNonce())
		require.NoError(t, err)
		return &pb.Pong{
			Nonce: p.GetNonce(),
			Signature: &pb.Signature{
				R: r,
				S: s,
			},
		}, nil
	}
	err = fd.probe(destPeer)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), destPeer.NumPing(), "recovery must reset consecutive failed pings")
}

func TestFailureDetector_ProbeInvalidSignature(t *testing.T) {
	fd, ps, _, destPeer := setupFDTest(t)

	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		return &pb.Pong{
			Nonce: p.GetNonce(),
			Signature: &pb.Signature{
				R: []byte("corrupted-r"),
				S: []byte("corrupted-s"),
			},
		}, nil
	}

	err := fd.probe(destPeer)
	assert.Equal(t, errInvalidPongSignature, err)
	assert.Equal(t, uint32(1), destPeer.NumPing())
}

func TestFailureDetector_ProbeMismatchedNonce(t *testing.T) {
	fd, ps, cs, destPeer := setupFDTest(t)

	wrongNonce := []byte("different-nonce-bytes-1234567890")
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(wrongNonce)
		require.NoError(t, err)
		return &pb.Pong{
			Nonce: wrongNonce,
			Signature: &pb.Signature{
				R: r,
				S: s,
			},
		}, nil
	}

	err := fd.probe(destPeer)
	assert.Equal(t, errInvalidPongSignature, err)
	assert.Equal(t, uint32(1), destPeer.NumPing())
}

func TestFailureDetector_ProbeNilSignature(t *testing.T) {
	fd, ps, _, destPeer := setupFDTest(t)

	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		return &pb.Pong{
			Nonce:     p.GetNonce(),
			Signature: nil,
		}, nil
	}

	err := fd.probe(destPeer)
	assert.Equal(t, errInvalidPongSignature, err)
	assert.Equal(t, uint32(1), destPeer.NumPing())
}

func TestFailureDetector_ProbeInvalidSignatureThreshold(t *testing.T) {
	fd, ps, _, destPeer := setupFDTest(t)

	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		return &pb.Pong{
			Nonce:     p.GetNonce(),
			Signature: nil,
		}, nil
	}

	for i := 0; i < 2; i++ {
		err := fd.probe(destPeer)
		assert.Equal(t, errInvalidPongSignature, err)
	}

	// 3rd consecutive invalid pong reaches maxFailedPings (3)
	err := fd.probe(destPeer)
	assert.Equal(t, errDead, err)
	assert.Equal(t, uint32(3), destPeer.NumPing())
}
