package core

import (
	"encoding/binary"
	"testing"

	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
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
	assert.Nil(t, ps.fpDataProvider(), "unregistered data store must produce nil data fingerprint")

	// Register an application data store with an element
	store, err := revIdxStore.NewDigestSet[string, revIdxStore.DigestSymbol](revIdxStore.DefaultHasher[string]())
	require.NoError(t, err)
	store.AddElement("app-data-element-1")

	RegisterDataStore(n, store)

	dataFP := ps.fpDataProvider()
	require.Len(t, dataFP, 8, "registered store must advertise 8-byte data fingerprint over UDP")
	assert.Equal(t, n.FingerprintData(), dataFP, "UDP provider must return n.FingerprintData()")

	expectedDigest := uint64(store.Fingerprint())
	assert.Equal(t, expectedDigest, binary.BigEndian.Uint64(dataFP), "data fingerprint must encode in BigEndian")
}

func TestFailureDetector_ProbeCapturesPiggybackedFingerprints(t *testing.T) {
	fd, ps, cs, destPeer := setupFDTest(t)

	expectedDataFP := []byte("data-fingerprint-payload")
	expectedAccFP := []byte("accusation-fingerprint-payload")
	expectedViewFP := []byte("view-fingerprint-payload")

	ps.customPong = func(p *pb.Ping) (*pb.Pong, error) {
		content := ps.PongContent(p.GetNonce(), expectedDataFP, expectedAccFP, expectedViewFP)
		r, s, err := cs.Sign(content)
		if err != nil {
			return nil, err
		}
		return &pb.Pong{
			Nonce: p.GetNonce(),
			Signature: &pb.Signature{
				R: r,
				S: s,
			},
			FingerprintData:        expectedDataFP,
			FingerprintAccusations: expectedAccFP,
			FingerprintView:        expectedViewFP,
		}, nil
	}

	err := fd.probe(destPeer)
	require.NoError(t, err)

	assert.Equal(t, expectedDataFP, destPeer.FingerprintData())
	assert.Equal(t, expectedAccFP, destPeer.FingerprintAccusations())
	assert.Equal(t, expectedViewFP, destPeer.FingerprintView())
}

func TestAccusationStore_AuditabilityAndGrowOnly(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	// In a grow-only store, all historical accusations are preserved and auditable
	p1 := "node-1"
	p2 := "node-2"

	// Epoch 1 accusation
	err = n.view.AddAccusation(p1, p2, 1, 1, []byte("r1"), []byte("s1"))
	require.NoError(t, err)

	fp1 := n.AccusationFingerprint()
	assert.NotEqual(t, revIdxStore.DigestSymbol(0), fp1)
	assert.Len(t, n.view.AccusationsForPeer(p1), 1)

	// Epoch 2 accusation arrives later
	err = n.view.AddAccusation(p1, p2, 2, 1, []byte("r2"), []byte("s2"))
	require.NoError(t, err)

	fp2 := n.AccusationFingerprint()
	assert.NotEqual(t, fp1, fp2)

	// Both accusations remain preserved for auditing / divergence checks
	history := n.view.AccusationsForPeer(p1)
	assert.Len(t, history, 2)

	// Duplicate addition is idempotent and does not corrupt the fingerprint
	err = n.view.AddAccusation(p1, p2, 1, 1, []byte("r1"), []byte("s1"))
	require.NoError(t, err)
	assert.Equal(t, fp2, n.AccusationFingerprint(), "idempotent addition must preserve fingerprint")
}

func TestNode_DivergenceDetection(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	p, _, err := createTestPeer()
	require.NoError(t, err)

	// Initially node and peer both have nil data fingerprints, but acc and view differ (node has 8-byte fingerprints, peer has nil)
	assert.True(t, n.IsDivergent(p))
	dataDiff, accDiff, viewDiff := n.DivergentSets(p)
	assert.False(t, dataDiff)
	assert.True(t, accDiff)
	assert.True(t, viewDiff)

	// Set peer fingerprints to match local node fingerprints
	p.SetFingerprintData(n.FingerprintData())
	p.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p.SetFingerprintView(n.ViewFingerprintBytes())

	// Now peer is fully in sync
	assert.False(t, n.IsDivergent(p))
	dataDiff, accDiff, viewDiff = n.DivergentSets(p)
	assert.False(t, dataDiff)
	assert.False(t, accDiff)
	assert.False(t, viewDiff)

	// Tamper data fingerprint -> only data diverges
	p.SetFingerprintData([]byte("different-data"))
	assert.True(t, n.IsDivergent(p))
	dataDiff, accDiff, viewDiff = n.DivergentSets(p)
	assert.True(t, dataDiff)
	assert.False(t, accDiff)
	assert.False(t, viewDiff)

	// Restore data, alter accusation -> only accusation diverges
	p.SetFingerprintData(n.FingerprintData())
	p.SetFingerprintAccusations([]byte("different-acc"))
	assert.True(t, n.IsDivergent(p))
	dataDiff, accDiff, viewDiff = n.DivergentSets(p)
	assert.False(t, dataDiff)
	assert.True(t, accDiff)
	assert.False(t, viewDiff)

	// Restore accusation, alter view -> only view diverges
	p.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p.SetFingerprintView([]byte("different-view"))
	assert.True(t, n.IsDivergent(p))
	dataDiff, accDiff, viewDiff = n.DivergentSets(p)
	assert.False(t, dataDiff)
	assert.False(t, accDiff)
	assert.True(t, viewDiff)
}

type recordingGossipComm struct {
	commStub
	gossipedAddrs []string
}

func (c *recordingGossipComm) Gossip(addr string, m *pb.State) (*pb.StateResponse, error) {
	c.gossipedAddrs = append(c.gossipedAddrs, addr)
	return &pb.StateResponse{}, nil
}

func TestProtocol_GossipSkipsNonDivergentPeers(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	comm := &recordingGossipComm{}
	n, err := NewNode(comm, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	// Create two peers
	p1, _, err := createTestPeer()
	require.NoError(t, err)
	p1.Addr = "peer-1-addr"

	p2, _, err := createTestPeer()
	require.NoError(t, err)
	p2.Addr = "peer-2-addr"

	// p1 is in sync
	p1.SetFingerprintData(n.FingerprintData())
	p1.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p1.SetFingerprintView(n.ViewFingerprintBytes())

	// p2 is divergent
	p2.SetFingerprintData([]byte("different-data"))
	p2.SetFingerprintAccusations(n.AccusationFingerprintBytes())
	p2.SetFingerprintView(n.ViewFingerprintBytes())

	n.view.AddLive(p1)
	n.view.AddLive(p2)

	// Run gossip
	n.p.Gossip(n)

	// Only p2 (divergent) should have been gossiped with; p1 was skipped
	assert.NotContains(t, comm.gossipedAddrs, "peer-1-addr")
	assert.Contains(t, comm.gossipedAddrs, "peer-2-addr")
}

func TestNode_CertificateStoreAndFingerprinting(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)
	defer n.Stop()

	// Initial certificate store contains self certificate
	require.NotNil(t, n.CertStore())
	assert.Equal(t, 1, n.CertStore().Size())
	assert.NotEqual(t, revIdxStore.DigestSymbol(0), n.CertFingerprint())
	assert.Len(t, n.CertFingerprintBytes(), 8)

	digests := n.CertDigests()
	assert.Len(t, digests, 1)
	assert.Len(t, n.CertDigestsUint64(), 1)

	// View fingerprint combines note store and cert store
	expectedViewFp := n.view.NoteStore().Fingerprint().XOR(n.CertFingerprint())
	assert.Equal(t, expectedViewFp, n.ViewFingerprint())

	// Pluggable session factory
	assert.Nil(t, n.getCertSessionFactory())
	customFactory := NewNaiveSessionFactory[*discovery.Certificate, revIdxStore.DigestSymbol]()
	n.SetCertSessionFactory(customFactory)
	assert.Equal(t, customFactory, n.getCertSessionFactory())
}
