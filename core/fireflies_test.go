package core

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/digestmaps"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/eika123/ifrit/reconcile"
	reconpb "github.com/eika123/ifrit/reconcile/proto"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recordingPingServer struct {
	pingStub
	fpProvider func() comm.Fingerprints
}

func (r *recordingPingServer) SetFingerprintsProvider(f func() comm.Fingerprints) {
	r.fpProvider = f
}

func appendProtocolFramed(dst []byte, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, field...)
}

func (r *recordingPingServer) PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte, fpServices []byte) []byte {
	return comm.PongContent(nonce, fpData, fpAcc, fpView, fpServices)
}

func TestNode_PiggybacksAccusationFingerprintOnPingServer(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)

	cert := genCert(priv, 1)
	ps := &recordingPingServer{}
	cs := &cryptoStub{priv: priv}

	n, err := NewNode(&commStub{}, ps, &cmStub{cert: cert}, cs)
	require.NoError(t, err)

	require.NotNil(t, ps.fpProvider, "fingerprint provider should be registered")

	// View fingerprint reflects initial view
	initialFPS := ps.fpProvider()
	require.Len(t, initialFPS.View, 8)
	assert.Equal(t, uint64(n.ViewFingerprint()), binary.BigEndian.Uint64(initialFPS.View))

	// Initial empty accusation set -> accusation fingerprint 0
	require.Len(t, initialFPS.Accusations, 8)
	assert.Equal(t, uint64(0), binary.BigEndian.Uint64(initialFPS.Accusations))

	// Add an accusation to the view
	err = n.view.AddAccusation("accusedNode", "accuserNode", 1, 1, []byte("r"), []byte("s"))
	require.NoError(t, err)

	// Accusation fingerprint in provider must now reflect the new accusation
	updatedAccFP := ps.fpProvider().Accusations
	require.Len(t, updatedAccFP, 8)
	assert.NotEqual(t, initialFPS.Accusations, updatedAccFP)
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

	require.NotNil(t, ps.fpProvider, "fingerprint provider should be registered")

	// Initially, no data reconciler registered -> canonical 8-byte zero fingerprint
	initialDataFP := ps.fpProvider().Data
	assert.Equal(t, make([]byte, 8), initialDataFP, "data fingerprint should be canonical 8-byte zero when no data reconciler is registered")

	// Register a typed reconcilable data store with items
	hasher := digestmaps.MustDefaultHasher[string]()
	store, err := ratelessIBLT.NewReconcilableStore[string](hasher)
	require.NoError(t, err)

	store.Insert("item-alpha")
	store.Insert("item-beta")

	RegisterDataStore(n, store)

	// Data fingerprint in ping server provider must now reflect the store's fingerprint
	updatedDataFP := ps.fpProvider().Data
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

type stubStoreReconciler struct {
	mu    sync.Mutex
	addrs []string
	fn    func(ctx context.Context, addr string) (reconcile.Summary, error)
}

func (s *stubStoreReconciler) ReconcileWithPeer(ctx context.Context, addr string) (reconcile.Summary, error) {
	s.mu.Lock()
	s.addrs = append(s.addrs, addr)
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, addr)
	}
	return reconcile.Summary{}, nil
}

func (s *stubStoreReconciler) HandleReconcile(reconpb.ReconcileService_ReconcileServer) error {
	return nil
}

func (s *stubStoreReconciler) takeAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.addrs...)
	s.addrs = nil
	return out
}

func installStubReconcilers(n *Node, cert, note, acc, data reconcile.StoreReconciler) {
	n.certReconciler = cert
	n.noteReconciler = note
	n.accReconciler = acc
	n.dataReconcilerMutex.Lock()
	n.dataStoreReconciler = data
	n.dataReconcilerMutex.Unlock()
}

func TestNode_AdversaryMutatesOutboundGossip(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingComm{}
	cs := &cryptoStub{priv: priv}

	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, cs)
	require.NoError(t, err)
	defer n.Stop()

	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "neighbor-gossip-addr"
	// Set divergent fingerprint so gossip triggers
	p.SetFingerprintData([]byte("different-data"))
	n.view.AddLive(p)

	// Force PermissionDenied on first ReconcileWithPeer so gossip() falls back to thin Spread admission.
	var attempts sync.Mutex
	calls := 0
	installStubReconcilers(n,
		&stubStoreReconciler{
			fn: func(context.Context, string) (reconcile.Summary, error) {
				attempts.Lock()
				calls++
				c := calls
				attempts.Unlock()
				if c == 1 {
					return reconcile.Summary{}, status.Error(codes.PermissionDenied, "unrecognized caller")
				}
				return reconcile.Summary{}, nil
			},
		},
		&stubStoreReconciler{},
		&stubStoreReconciler{},
		&stubStoreReconciler{},
	)

	n.SetAdversarialPolicy(&AdversarialPolicy{
		OnGossipOut: func(target *discovery.Peer, msg *pb.State) {
			msg.IsRebuttal = true
		},
	})

	n.gossip()

	comm.mu.Lock()
	defer comm.mu.Unlock()
	require.NotEmpty(t, comm.sentStates, "gossip fallback must send a thin Spread State message")
	assert.True(t, comm.sentStates[0].GetIsRebuttal(), "outbound State should carry OnGossipOut mutation")
}

func TestNode_CanonicalFingerprintDataQuiescence(t *testing.T) {
	caCert, caPriv := genTestCA(t)
	nUnreg, comm1, _, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer nUnreg.Stop()
	defer comm1.Stop()

	nEmpty, comm2, _, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer nEmpty.Stop()
	defer comm2.Stop()

	emptyStore, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nEmpty, emptyStore)

	assert.Equal(t, make([]byte, 8), nUnreg.FingerprintData())
	assert.Equal(t, nUnreg.FingerprintData(), nEmpty.FingerprintData())
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

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)
	defer n.Stop()

	rec := &stubStoreReconciler{
		fn: func(_ context.Context, _ string) (reconcile.Summary, error) {
			return reconcile.Summary{}, nil
		},
	}
	dataRec := &stubStoreReconciler{}
	installStubReconcilers(n, rec, &stubStoreReconciler{}, &stubStoreReconciler{}, dataRec)

	p1, _, err := createTestPeer()
	require.NoError(t, err)
	p1.Addr = "peer1-addr"
	p1.SetFingerprintData(n.FingerprintData())
	p1.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p1.SetFingerprintView(n.ViewFingerprintBytes())
	p1.SetFingerprintServices(n.ServiceFingerprintBytes())

	p2, _, err := createTestPeer()
	require.NoError(t, err)
	p2.Addr = "peer2-addr"
	p2.SetFingerprintData(n.FingerprintData())
	p2.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p2.SetFingerprintView(n.ViewFingerprintBytes())
	p2.SetFingerprintServices(n.ServiceFingerprintBytes())

	n.view.AddLive(p1)
	n.view.AddLive(p2)

	// Initially, peers have matching fingerprints -> IsDivergent returns false
	n.gossip()
	assert.Empty(t, rec.takeAddrs(), "In-sync peers should not be reconciled")
	assert.Empty(t, dataRec.takeAddrs(), "In-sync peers should not reconcile data")

	// Make p1 divergent in Data only -> reconciles data without triggering host control stores
	p1.SetFingerprintData([]byte("different-data"))
	n.gossip()
	assert.Equal(t, []string{"peer1-addr"}, dataRec.takeAddrs(), "Only divergent peer p1 should reconcile data")
	assert.Empty(t, rec.takeAddrs(), "Data-only divergence should not trigger host control reconcilers")

	// Bring p1 back into sync with local node
	p1.SetFingerprintData(n.FingerprintData())

	// Make p2 divergent in Accusations
	p2.SetFingerprintAccusations([]byte("different-acc"))
	n.gossip()
	assert.Equal(t, []string{"peer2-addr"}, rec.takeAddrs(), "Only divergent peer p2 should be reconciled")

	// Bring p2 back into sync with local node
	p2.SetFingerprintAccusations(n.AccusationFingerprintBytes())

	// Make p2 divergent in View
	p2.SetFingerprintView([]byte("different-view"))
	n.gossip()
	assert.Equal(t, []string{"peer2-addr"}, rec.takeAddrs(), "Only divergent peer p2 should be reconciled")
}

func TestNode_GossipConvergenceClearsDivergence(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)
	defer n.Stop()

	store, err := ratelessIBLT.NewReconcilableStore[string](digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	store.Insert("converged-item")
	RegisterDataStore(n, store)

	// Seed view fingerprints matching n's local cert ^ note.
	localCertFP := n.CertFingerprintBytes()
	localNoteFP := make([]byte, 8)
	binary.BigEndian.PutUint64(localNoteFP, uint64(n.view.NoteStore().Fingerprint()))
	localAccFP := n.AccusationFingerprintBytes()
	localDataFP := n.FingerprintData()

	certRec := &stubStoreReconciler{
		fn: func(context.Context, string) (reconcile.Summary, error) {
			return reconcile.Summary{RemoteFingerprint: localCertFP}, nil
		},
	}
	noteRec := &stubStoreReconciler{
		fn: func(context.Context, string) (reconcile.Summary, error) {
			return reconcile.Summary{RemoteFingerprint: localNoteFP}, nil
		},
	}
	accRec := &stubStoreReconciler{
		fn: func(context.Context, string) (reconcile.Summary, error) {
			return reconcile.Summary{RemoteFingerprint: localAccFP}, nil
		},
	}
	dataRec := &stubStoreReconciler{
		fn: func(context.Context, string) (reconcile.Summary, error) {
			return reconcile.Summary{RemoteFingerprint: localDataFP}, nil
		},
	}
	installStubReconcilers(n, certRec, noteRec, accRec, dataRec)

	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "peer-addr"
	p.SetFingerprintData([]byte("initial-diff"))
	p.SetFingerprintAccusations(localAccFP)
	p.SetFingerprintView(n.ViewFingerprintBytes())
	p.SetFingerprintServices(n.ServiceFingerprintBytes())
	n.view.AddLive(p)

	n.gossip()
	assert.Equal(t, []string{"peer-addr"}, dataRec.takeAddrs())

	// Fingerprint on peer should now be updated to local
	assert.False(t, n.IsDivergent(p), "Peer should no longer be divergent after summary fingerprints are stored")

	// Next gossip tick should NOT trigger reconciliation
	n.gossip()
	assert.Empty(t, dataRec.takeAddrs(), "Converged peer should not be reconciled again")
}

func TestNode_GossipPeerReconcileSessionFlow(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)
	defer n.Stop()

	p, _, err := createTestPeer()
	require.NoError(t, err)
	p.Addr = "peer-divergent-addr"
	p.SetFingerprintData([]byte("diff-data"))
	n.view.AddLive(p)

	var recErr error
	certRec := &stubStoreReconciler{
		fn: func(context.Context, string) (reconcile.Summary, error) {
			if recErr != nil {
				return reconcile.Summary{}, recErr
			}
			return reconcile.Summary{}, nil
		},
	}
	installStubReconcilers(n, certRec, &stubStoreReconciler{}, &stubStoreReconciler{}, &stubStoreReconciler{})

	// 1. Concurrency guard: while outbound gate is held, gossip tick skips peer.
	require.True(t, n.PeerGate().TryStartOutbound(p.Id))

	n.gossip()
	assert.Empty(t, certRec.takeAddrs(), "Peer must be skipped while session is busy")
	n.PeerGate().ReleaseOutbound(p.Id)

	// 2. Normal gossip completes and returns gate to idle (and prunes map entry).
	n.gossip()
	assert.Equal(t, []string{"peer-divergent-addr"}, certRec.takeAddrs())
	assert.True(t, n.PeerGate().IsIdle(p.Id))
	assert.Equal(t, 0, n.PeerGate().Len())

	// 3. Reconciler error also releases gate cleanly back to idle.
	p.SetFingerprintData([]byte("diverged-again"))
	recErr = errors.New("network dial failure")
	n.gossip()
	assert.True(t, n.PeerGate().IsIdle(p.Id))
	assert.Equal(t, 0, n.PeerGate().Len())
}

// -----------------------------------------------------------------------------
// Failure detector unit tests
// -----------------------------------------------------------------------------

type mockPingService struct {
	customPong func(p *pb.Ping) (*pb.Pong, error)
}

func (s *mockPingService) Pause(time.Duration)                              {}
func (s *mockPingService) Start()                                           {}
func (s *mockPingService) Stop()                                            {}
func (s *mockPingService) SetFingerprintsProvider(func() comm.Fingerprints) {}

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

func (s *mockPingService) PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte, fpServices []byte) []byte {
	return comm.PongContent(nonce, fpData, fpAcc, fpView, fpServices)
}

func createTestPeer() (*discovery.Peer, *cryptoStub, error) {
	priv, err := genKeys()
	if err != nil {
		return nil, nil, err
	}
	cert := genCert(priv, 1)
	cs := &cryptoStub{priv: priv}
	vs, err := newControlViewStores("naive")
	if err != nil {
		return nil, nil, err
	}
	v, err := discovery.NewView(1, cert, nil, cs, vs)
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
	expectedFPServices := []byte{0x55, 0x66, 0x77, 0x88}
	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		r, s, err := cs.Sign(ps.PongContent(p.GetNonce(), expectedFPData, expectedFPAcc, expectedFPView, expectedFPServices))
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
			FingerprintServices:    expectedFPServices,
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
	assert.Equal(t, expectedFPServices, destPeer.FingerprintServices(), "peer should store piggybacked services fingerprint")
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
		r, s, err := cs.Sign(ps.PongContent(p.GetNonce(), nil, nil, nil, nil))
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
		r, s, err := cs.Sign(ps.PongContent(p.GetNonce(), originalDataFP, originalAccFP, nil, nil))
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
		r, s, err := cs.Sign(ps.PongContent(wrongNonce, nil, nil, nil, nil))
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
