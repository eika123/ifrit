package core

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/joonnna/ifrit/core/discovery"
	"github.com/joonnna/ifrit/digestmaps"
	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingPingServer struct {
	pingStub
	fpDataProvider func() []byte
	fpAccProvider  func() []byte
	fpViewProvider func() []byte
}

func (r *recordingPingServer) SetFingerprintDataProvider(f func() []byte) {
	r.fpDataProvider = f
}

func (r *recordingPingServer) SetFingerprintAccusationsProvider(f func() []byte) {
	r.fpAccProvider = f
}

func (r *recordingPingServer) SetFingerprintViewProvider(f func() []byte) {
	r.fpViewProvider = f
}

func appendProtocolFramed(dst []byte, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, field...)
}

func (r *recordingPingServer) PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte) []byte {
	totalLen := 4*4 + len(nonce) + len(fpData) + len(fpAcc) + len(fpView)
	content := make([]byte, 0, totalLen)
	content = appendProtocolFramed(content, nonce)
	content = appendProtocolFramed(content, fpData)
	content = appendProtocolFramed(content, fpAcc)
	content = appendProtocolFramed(content, fpView)
	return content
}

func TestNode_PiggybacksAccusationFingerprintOnPingServer(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)

	cert := genCert(priv, 1)
	ps := &recordingPingServer{}
	cs := &cryptoStub{priv: priv}

	n, err := NewNode(&commStub{}, ps, &cmStub{cert: cert}, cs)
	require.NoError(t, err)

	require.NotNil(t, ps.fpDataProvider, "data fingerprint provider should be registered")
	require.NotNil(t, ps.fpAccProvider, "accusation fingerprint provider should be registered")
	require.NotNil(t, ps.fpViewProvider, "view fingerprint provider should be registered")

	// View fingerprint reflects initial view
	initialViewFP := ps.fpViewProvider()
	require.Len(t, initialViewFP, 8)
	assert.Equal(t, uint64(n.ViewFingerprint()), binary.BigEndian.Uint64(initialViewFP))

	// Initial empty accusation set -> accusation fingerprint 0
	initialAccFP := ps.fpAccProvider()
	require.Len(t, initialAccFP, 8)
	assert.Equal(t, uint64(0), binary.BigEndian.Uint64(initialAccFP))

	// Add an accusation to the view
	err = n.view.AddAccusation("accusedNode", "accuserNode", 1, 1, []byte("r"), []byte("s"))
	require.NoError(t, err)

	// Accusation fingerprint in provider must now reflect the new accusation
	updatedAccFP := ps.fpAccProvider()
	require.Len(t, updatedAccFP, 8)
	assert.NotEqual(t, initialAccFP, updatedAccFP)
	assert.Equal(t, uint64(n.AccusationFingerprint()), binary.BigEndian.Uint64(updatedAccFP))
}

func TestNode_PiggybacksDataFingerprintOnPingServer(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)

	cert := genCert(priv, 1)

	ps := &recordingPingServer{}
	cs := &cryptoStub{priv: priv}

	n, err := NewNode(&commStub{}, ps, &cmStub{cert: cert}, cs)
	require.NoError(t, err)
	defer n.Stop()

	require.NotNil(t, ps.fpDataProvider, "data fingerprint provider should be registered")

	// Initially, no data reconciler registered -> data fingerprint provider returns nil
	initialDataFP := ps.fpDataProvider()
	assert.Nil(t, initialDataFP, "data fingerprint should be nil when no data reconciler is registered")

	// Register a typed data store with items
	hasher := digestmaps.MustDefaultHasher[string]()
	store, err := digestmaps.NewDigestSet[string, digestmaps.DigestSymbol](hasher)
	require.NoError(t, err)

	store.AddElement("item-alpha")
	store.AddElement("item-beta")

	RegisterDataStore(n, store)

	// Data fingerprint in ping server provider must now reflect the store's fingerprint
	updatedDataFP := ps.fpDataProvider()
	require.Len(t, updatedDataFP, 8)
	expectedFP := store.Fingerprint()
	assert.Equal(t, uint64(expectedFP), binary.BigEndian.Uint64(updatedDataFP))
}

func TestNode_AdversarySuppressesRebuttal(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingComm{}
	cs := &cryptoStub{priv: priv}

	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, cs)
	require.NoError(t, err)

	// Add a live neighbor
	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "neighbor-1-addr"
	n.view.AddLive(p)

	// Honest node: rebuttal sends Gossip message
	n.rebuttal()
	comm.mu.Lock()
	assert.NotEmpty(t, comm.gossipedAddrs, "honest node should send rebuttal to neighbor")
	comm.gossipedAddrs = nil
	comm.mu.Unlock()

	// Adversary: SuppressRebuttalBps = 10000 (100% suppression)
	n.SetAdversarialPolicy(&AdversarialPolicy{
		SuppressRebuttalBps: 10000,
	})
	n.rebuttal()
	comm.mu.Lock()
	assert.Empty(t, comm.gossipedAddrs, "adversary with 100% suppression should not send rebuttal")
	comm.mu.Unlock()

	// Adversary: OnRebuttal hook returning nil suppresses
	n.SetAdversarialPolicy(&AdversarialPolicy{
		OnRebuttal: func(target *discovery.Peer, msg *pb.State) *pb.State {
			return nil
		},
	})
	n.rebuttal()
	comm.mu.Lock()
	assert.Empty(t, comm.gossipedAddrs, "OnRebuttal hook returning nil should suppress rebuttal")
	comm.mu.Unlock()
}

func TestNode_AdversarySuppressesAccusation(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	cs := &cryptoStub{priv: priv}
	ps := &mockPingService{
		customPong: func(p *pb.Ping) (*pb.Pong, error) {
			return nil, errors.New("timeout")
		},
	}

	n, err := NewNode(&commStub{}, ps, &cmStub{cert: cert}, cs)
	require.NoError(t, err)

	// Add a successor peer with an active note
	p, peerCs, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "dead-neighbor-addr"
	parsedCert, err := x509.ParseCertificate(p.Certificate())
	require.NoError(t, err)
	err = n.view.AddFull(p.Id, parsedCert)
	require.NoError(t, err)
	n.view.AddLive(p)

	// Register peer's active note
	note := discovery.NewNote(p.Id, 1, 0xFFFFFFFF, peerCs.priv)
	require.NoError(t, n.evalNote(note))

	// Verify predecessor/successor ring relationship
	succ, _ := n.view.MyRingNeighbours(1)
	if succ == nil || succ.Id != p.Id {
		t.Skip("peer is not ring 1 successor in this 2-node topology; monitorTarget will select him")
	}

	// Adversary with 100% accusation suppression
	n.SetAdversarialPolicy(&AdversarialPolicy{
		SuppressAccusationBps: 10000,
	})

	// Fail 3 probes to exceed maxFailedPings threshold
	for i := 0; i < 3; i++ {
		n.monitor()
	}

	// Accusation must NOT have been created due to adversarial suppression
	accs := n.view.Accusations()
	assert.Empty(t, accs, "adversary with 100% suppression must not emit accusation")
}

func TestNode_AdversaryMutatesOutboundGossip(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingComm{}
	cs := &cryptoStub{priv: priv}

	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, cs)
	require.NoError(t, err)

	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "neighbor-gossip-addr"
	// Set divergent fingerprint so gossip triggers
	p.SetFingerprintData([]byte("different-data"))
	n.view.AddLive(p)

	poisonedBytes := []byte("poisoned-fingerprint-data")
	n.SetAdversarialPolicy(&AdversarialPolicy{
		OnGossipOut: func(target *discovery.Peer, msg *pb.State) {
			msg.FingerprintData = poisonedBytes
		},
	})

	n.gossip()

	comm.mu.Lock()
	defer comm.mu.Unlock()
	require.NotEmpty(t, comm.sentStates, "gossip should have sent a State message")
	assert.Equal(t, poisonedBytes, comm.sentStates[0].FingerprintData, "outbound State should carry poisoned fingerprint")
}

type recordingComm struct {
	commStub
	mu            sync.Mutex
	gossipedAddrs []string
	sentStates    []*pb.State
	response      *pb.StateResponse
	err           error
}

func (c *recordingComm) Gossip(addr string, msg *pb.State) (*pb.StateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gossipedAddrs = append(c.gossipedAddrs, addr)
	c.sentStates = append(c.sentStates, msg)
	if c.err != nil {
		return nil, c.err
	}
	if c.response != nil {
		return c.response, nil
	}
	return &pb.StateResponse{}, nil
}

func TestNode_GossipStateDivergenceCheck(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingComm{}
	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	p1, _, err := createTestPeer()
	require.NoError(t, err)
	p1.Addr = "peer1-addr"
	p1.SetFingerprintData(n.FingerprintData())
	p1.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p1.SetFingerprintView(n.ViewFingerprintBytes())

	p2, _, err := createTestPeer()
	require.NoError(t, err)
	p2.Addr = "peer2-addr"
	p2.SetFingerprintData(n.FingerprintData())
	p2.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p2.SetFingerprintView(n.ViewFingerprintBytes())

	n.view.AddLive(p1)
	n.view.AddLive(p2)

	// Initially, peers have matching empty fingerprints -> IsDivergent returns false
	n.gossip()

	comm.mu.Lock()
	assert.Empty(t, comm.gossipedAddrs, "In-sync peers should not be gossiped to")
	comm.mu.Unlock()

	// Make p1 divergent in Data
	p1.SetFingerprintData([]byte("different-data"))
	n.gossip()

	comm.mu.Lock()
	assert.Equal(t, []string{"peer1-addr"}, comm.gossipedAddrs, "Only divergent peer p1 should be gossiped to")
	comm.gossipedAddrs = nil
	comm.mu.Unlock()

	// Bring p1 back into sync with local node
	p1.SetFingerprintData(n.FingerprintData())

	// Make p2 divergent in Accusations
	p2.SetFingerprintAccusations([]byte("different-acc"))
	n.gossip()

	comm.mu.Lock()
	assert.Equal(t, []string{"peer2-addr"}, comm.gossipedAddrs, "Only divergent peer p2 should be gossiped to")
	comm.gossipedAddrs = nil
	comm.mu.Unlock()

	// Bring p2 back into sync with local node
	p2.SetFingerprintAccusations(n.AccusationFingerprintBytes())

	// Make p2 divergent in View
	p2.SetFingerprintView([]byte("different-view"))
	n.gossip()

	comm.mu.Lock()
	assert.Equal(t, []string{"peer2-addr"}, comm.gossipedAddrs, "Only divergent peer p2 should be gossiped to")
	comm.mu.Unlock()
}

func TestNode_GossipConvergenceClearsDivergence(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingComm{}
	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	localFp := []byte("converged-data-fp")
	n.SetFingerprintData(localFp)

	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "peer-addr"
	p.SetFingerprintData([]byte("initial-diff"))
	p.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p.SetFingerprintView(n.ViewFingerprintBytes())
	n.view.AddLive(p)

	// Server returns updated fingerprints matching local node
	comm.response = &pb.StateResponse{
		FingerprintData:         localFp,
		FingerprintAccusations:  n.AccusationFingerprintBytes(),
		FingerprintView:         n.ViewFingerprintBytes(),
		FingerprintCertificates: n.CertFingerprintBytes(),
	}

	n.gossip()

	comm.mu.Lock()
	assert.Equal(t, []string{"peer-addr"}, comm.gossipedAddrs)
	comm.gossipedAddrs = nil
	comm.mu.Unlock()

	// Fingerprint on peer should now be updated to local
	assert.False(t, n.IsDivergent(p), "Peer should no longer be divergent after reply fingerprints are stored")

	// Next gossip tick should NOT send any messages
	n.gossip()
	comm.mu.Lock()
	assert.Empty(t, comm.gossipedAddrs, "Converged peer should not receive further gossip messages")
	comm.mu.Unlock()
}

func TestNode_GossipPeerReconcileSessionFlow(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingComm{}
	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "peer-divergent-addr"
	// Ensure peer is divergent
	p.SetFingerprintData([]byte("diff-data"))
	n.view.AddLive(p)

	// Case 1: RPC returns divergent deltas -> session transitions to SessionTransferring
	comm.response = &pb.StateResponse{
		AvailableCertificateDigests: []uint64{0x12345},
		RequestedDataDigests:        []uint64{0x99999},
	}
	n.gossip()

	sess := n.SessionManager().Get(p.Id)
	require.NotNil(t, sess)
	assert.Equal(t, SessionTransferring, sess.State())
	assert.True(t, sess.HasDeltas())
	assert.Equal(t, []uint64{0x12345}, sess.Deltas().AvailableCertificates)
	assert.Equal(t, []uint64{0x99999}, sess.Deltas().RequestedData)
	assert.Equal(t, []uint64{0x12345}, sess.Deltas().IngressCertificates(true))
	assert.Equal(t, []uint64{0x99999}, sess.Deltas().EgressData(true))

	// Case 2: Concurrency guard - while session is in SessionTransferring, next Gossip tick skips peer
	comm.mu.Lock()
	comm.gossipedAddrs = nil
	comm.mu.Unlock()
	n.gossip()
	comm.mu.Lock()
	assert.Empty(t, comm.gossipedAddrs, "Peer must be skipped while session is busy transferring")
	comm.mu.Unlock()

	// Finish or reset session to test next case
	sess.ResetToIdle()

	// Case 3: RPC returns empty deltas -> session transitions to SessionIdle, fingerprints updated
	newFpData := []byte("converged-data-fp")
	comm.response = &pb.StateResponse{
		FingerprintData: newFpData,
	}
	n.gossip()
	assert.Equal(t, SessionIdle, sess.State())
	assert.False(t, sess.HasDeltas())
	assert.Equal(t, newFpData, p.FingerprintData())

	// Case 4: RPC error -> session resets to SessionIdle
	p.SetFingerprintData([]byte("diverged-again"))
	comm.err = errors.New("network dial failure")
	n.gossip()
	assert.Equal(t, SessionIdle, sess.State())
}

// -----------------------------------------------------------------------------
// Failure detector unit tests
// -----------------------------------------------------------------------------

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

func appendFramed(dst []byte, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, field...)
}

func (s *mockPingService) PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte) []byte {
	totalLen := 4*4 + len(nonce) + len(fpData) + len(fpAcc) + len(fpView)
	content := make([]byte, 0, totalLen)
	content = appendFramed(content, nonce)
	content = appendFramed(content, fpData)
	content = appendFramed(content, fpAcc)
	content = appendFramed(content, fpView)
	return content
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

	expectedFPData := []byte{0x12, 0x34, 0x56, 0x78}
	expectedFPAcc := []byte{0x9A, 0xBC, 0xDE, 0xF0}
	expectedFPView := []byte{0x11, 0x22, 0x33, 0x44}
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(ps.PongContent(p.GetNonce(), expectedFPData, expectedFPAcc, expectedFPView))
		if err != nil {
			return nil, err
		}
		return &pb.Pong{
			Nonce: p.GetNonce(),
			Signature: &pb.Signature{
				R: r,
				S: s,
			},
			FingerprintData:        expectedFPData,
			FingerprintAccusations: expectedFPAcc,
			FingerprintView:        expectedFPView,
		}, nil
	}

	destPeer.IncrementPingCount()
	assert.Equal(t, uint32(1), destPeer.NumPing())

	err := fd.probe(destPeer)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), destPeer.NumPing(), "successful pong should reset ping count")
	assert.Equal(t, expectedFPData, destPeer.FingerprintData(), "peer should store piggybacked data fingerprint")
	assert.Equal(t, expectedFPAcc, destPeer.FingerprintAccusations(), "peer should store piggybacked accusation fingerprint")
	assert.Equal(t, expectedFPView, destPeer.FingerprintView(), "peer should store piggybacked view fingerprint")
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
		r, s, err := cs.Sign(ps.PongContent(p.GetNonce(), nil, nil, nil))
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

func TestFailureDetector_ProbeTamperedFingerprint(t *testing.T) {
	fd, ps, cs, destPeer := setupFDTest(t)

	originalDataFP := []byte("sha256-hash-original-fp-32bytes")
	originalAccFP := []byte("sha256-hash-original-acc-32byte")
	tamperedAccFP := []byte("sha256-hash-tampered-acc-32byte")

	// Legitimate responder signed original fingerprints with the nonce
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(ps.PongContent(p.GetNonce(), originalDataFP, originalAccFP, nil))
		require.NoError(t, err)
		return &pb.Pong{
			Nonce: p.GetNonce(),
			Signature: &pb.Signature{
				R: r,
				S: s,
			},
			// MITM attacker alters accusation fingerprint in transit
			FingerprintData:        originalDataFP,
			FingerprintAccusations: tamperedAccFP,
		}, nil
	}

	err := fd.probe(destPeer)
	assert.Equal(t, errInvalidPongSignature, err, "tampered fingerprint must fail signature verification")
	assert.Equal(t, uint32(1), destPeer.NumPing())
}

func TestFailureDetector_ProbeMismatchedNonce(t *testing.T) {
	fd, ps, cs, destPeer := setupFDTest(t)

	wrongNonce := []byte("different-nonce-bytes-1234567890")
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(ps.PongContent(wrongNonce, nil, nil, nil))
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
