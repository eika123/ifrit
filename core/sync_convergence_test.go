package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/joonnna/ifrit/comm"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genTLSKeys() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func genTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	caPriv, err := genTLSKeys()
	require.NoError(t, err)

	serial, err := genSerialNumber()
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDer)
	require.NoError(t, err)

	return caCert, caPriv
}

func genNodeCertSignedByCA(t *testing.T, priv *ecdsa.PrivateKey, caCert *x509.Certificate, caPriv *ecdsa.PrivateKey) *x509.Certificate {
	ringBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ringBytes[0:], 10)

	ext := pkix.Extension{
		Id:       []int{2, 5, 13, 37},
		Critical: false,
		Value:    ringBytes,
	}

	ip := net.ParseIP("127.0.0.1")
	serial, err := genSerialNumber()
	require.NoError(t, err)

	nodeTmpl := &x509.Certificate{
		SerialNumber:          serial,
		SubjectKeyId:          genId(),
		Subject:               pkix.Name{Locality: []string{"127.0.0.1:8000", "pingAddr", "httpAddr"}},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IPAddresses:           []net.IP{ip},
		ExtraExtensions:       []pkix.Extension{ext},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	der, err := x509.CreateCertificate(rand.Reader, nodeTmpl, caCert, &priv.PublicKey, caPriv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func createTestNodeWithComm(t *testing.T, caCert *x509.Certificate, caPriv *ecdsa.PrivateKey) (*Node, *comm.Comm, *x509.Certificate, *ecdsa.PrivateKey) {
	priv, err := genTLSKeys()
	require.NoError(t, err)
	cert := genNodeCertSignedByCA(t, priv, caCert, caPriv)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	c, err := comm.NewComm(cert, caCert, priv, l)
	require.NoError(t, err)

	n, err := NewNode(c, &pingStub{}, &cmStub{cert: cert, caCert: caCert}, &cryptoStub{priv: priv})
	require.NoError(t, err)

	go c.Start()

	return n, c, cert, priv
}

func pairNodes(
	t *testing.T,
	n1 *Node,
	cert1 *x509.Certificate,
	priv1 *ecdsa.PrivateKey,
	comm1 *comm.Comm,
	n2 *Node,
	cert2 *x509.Certificate,
	priv2 *ecdsa.PrivateKey,
	comm2 *comm.Comm,
) (*discovery.Peer, *discovery.Peer) {
	id1 := string(cert1.SubjectKeyId)
	id2 := string(cert2.SubjectKeyId)

	// Add n2 into n1's view
	err := n1.view.AddFull(id2, cert2)
	require.NoError(t, err)
	p2 := n1.view.Peer(id2)
	p2.Addr = comm2.Addr()
	n1.view.AddLive(p2)
	n1.view.AddTestNote(p2, priv2, 1)

	// Add n1 into n2's view
	err = n2.view.AddFull(id1, cert1)
	require.NoError(t, err)
	p1 := n2.view.Peer(id1)
	p1.Addr = comm1.Addr()
	n2.view.AddLive(p1)
	n2.view.AddTestNote(p1, priv1, 1)

	return p1, p2
}

func TestSync_TwoNodeDataConvergence(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	require.NotNil(t, peerAOnB)

	// 1. Set up data store on Node A and Node B
	t.Log("Setting up data stores")
	storeA, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nodeA, storeA)

	storeB, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nodeB, storeB)

	item1 := "bulk-dataset-record-alpha"
	item2 := "bulk-dataset-record-beta"
	d1, added1 := storeA.Insert(item1)
	require.True(t, added1)
	d2, added2 := storeA.Insert(item2)
	require.True(t, added2)

	assert.Equal(t, 2, storeA.Size())
	assert.Equal(t, 0, storeB.Size())
	assert.NotEqual(t, nodeA.FingerprintData(), nodeB.FingerprintData())

	// 2. Trigger reconciliation: Node A gossips to Node B
	t.Log("Triggering Gossip from Node A to Node B")
	nodeA.p.Gossip(nodeA)
	t.Log("Gossip call finished, waiting for storeB convergence")

	// 3. Wait for Node B to receive and ingest items via Sync stream
	require.Eventually(t, func() bool {
		return storeB.Size() == 2
	}, 5*time.Second, 20*time.Millisecond, "Node B store must converge to size 2")

	// 4. Verify exact items were ingested into Node B's store
	val1, ok1 := storeB.GetByDigest(d1)
	require.True(t, ok1)
	assert.Equal(t, item1, val1)

	val2, ok2 := storeB.GetByDigest(d2)
	require.True(t, ok2)
	assert.Equal(t, item2, val2)

	// 5. Verify fingerprint equality
	assert.Equal(t, nodeA.FingerprintData(), nodeB.FingerprintData(), "Fingerprints must match exactly after sync")

	// 6. Verify single-round quiescence: subsequent gossip detects in-sync and skips transfer
	nodeA.p.Gossip(nodeA)
	assert.False(t, nodeA.IsDivergent(peerBOnA), "Node A must recognize Node B is in sync")
}

func TestSync_BidirectionalMutualConvergence(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)

	// Set up stores
	storeA, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nodeA, storeA)

	storeB, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nodeB, storeB)

	// Node A has itemA; Node B has itemB
	itemA := "unique-item-from-node-a"
	itemB := "unique-item-from-node-b"
	dA, addedA := storeA.Insert(itemA)
	require.True(t, addedA)
	dB, addedB := storeB.Insert(itemB)
	require.True(t, addedB)

	assert.Equal(t, 1, storeA.Size())
	assert.Equal(t, 1, storeB.Size())

	// Node A initiates reconciliation with Node B
	nodeA.p.Gossip(nodeA)

	// Wait for mutual convergence: both nodes must possess both items (size 2)
	require.Eventually(t, func() bool {
		return storeA.Size() == 2 && storeB.Size() == 2
	}, 5*time.Second, 20*time.Millisecond, "Both stores must mutually converge to size 2")

	valAonB, ok := storeB.GetByDigest(dA)
	require.True(t, ok)
	assert.Equal(t, itemA, valAonB)

	valBonA, ok := storeA.GetByDigest(dB)
	require.True(t, ok)
	assert.Equal(t, itemB, valBonA)

	// Fingerprints must be equal
	assert.Equal(t, nodeA.FingerprintData(), nodeB.FingerprintData())

	// Both sides in sync
	nodeA.p.Gossip(nodeA)
	nodeB.p.Gossip(nodeB)
	assert.False(t, nodeA.IsDivergent(peerBOnA))
	assert.False(t, nodeB.IsDivergent(peerAOnB))
}

func TestSync_TelemetryAccountingDuringConvergence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "telemetry.db")
	t.Setenv("IFRIT_TELEMETRY_DB", dbPath)

	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	require.NotNil(t, peerAOnB)
	require.NotNil(t, peerBOnA)

	storeA, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nodeA, storeA)

	storeB, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(nodeB, storeB)

	item1 := "telemetry-bulk-record-one-12345"
	item2 := "telemetry-bulk-record-two-67890"
	d1, added1 := storeA.Insert(item1)
	require.True(t, added1)
	require.NotZero(t, d1)
	d2, added2 := storeA.Insert(item2)
	require.True(t, added2)
	require.NotZero(t, d2)

	nodeA.p.Gossip(nodeA)

	require.Eventually(t, func() bool {
		return storeB.Size() == 2
	}, 5*time.Second, 20*time.Millisecond)

	// Close comms to flush telemetry
	commA.Stop()
	commB.Stop()

	// Verify telemetry database has recorded the payload bytes from stream chunks
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	var totalBytes int64
	err = db.QueryRow("SELECT COALESCE(SUM(payload_data_size), 0) FROM gossip_exchange WHERE payload_data_size > 0").Scan(&totalBytes)
	require.NoError(t, err)

	expectedBytes := int64(len(item1) + len(item2))
	assert.GreaterOrEqual(t, totalBytes, expectedBytes, "Stream telemetry must record at least the chunked item payload bytes")
}

// TestSync_NewPeerNetworkIntegration verifies that an unobserved new peer integrates
// into an existing network via Spread digest negotiation followed by streaming Sync,
// without piggybacking certificates or notes on SpreadResponse.
func TestSync_NewPeerNetworkIntegration(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	// Node A is an established network node with its own certificate and self note
	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	// Ensure Node A has initialized its self note in view
	selfNoteA := nodeA.view.SelfNote()
	if selfNoteA == nil {
		nodeA.view.AddTestNote(nodeA.self, privA, 1)
	}

	// Node B is a fresh new peer with only its certificate and self note (no contact list / empty view)
	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	selfNoteB := nodeB.view.SelfNote()
	if selfNoteB == nil {
		nodeB.view.AddTestNote(nodeB.self, privB, 1)
		selfNoteB = nodeB.view.SelfNote()
	}

	idA := string(certA.SubjectKeyId)
	idB := string(certB.SubjectKeyId)

	// Pre-condition: Node B does not know about Node A
	require.False(t, nodeB.view.Exists(idA), "Node B must not have Node A in full view initially")
	require.False(t, nodeA.view.Exists(idB), "Node A must not have Node B in full view initially")

	// 1. Node B contacts Node A via Spread RPC (gossip bootstrap)
	msg := &pb.State{
		FingerprintCertificates: nodeB.CertFingerprintBytes(),
		FingerprintView:         nodeB.ViewFingerprintBytes(),
		FingerprintAccusations:  nodeB.AccusationFingerprintBytes(),
		FingerprintData:         nodeB.FingerprintData(),
	}
	if selfNoteB != nil {
		msg.OwnNote = selfNoteB.ToPbMsg()
	}

	reply, err := nodeB.comm.Gossip(commA.Addr(), msg)
	require.NoError(t, err, "Node B must successfully send Spread RPC to Node A")
	require.NotNil(t, reply, "SpreadResponse must not be nil")

	// 2. Verify Zero-Piggybacking invariant on SpreadResponse
	assert.Empty(t, reply.GetCertificates(), "SpreadResponse must not piggyback certificates")
	assert.Empty(t, reply.GetNotes(), "SpreadResponse must not piggyback notes")

	// 3. Verify non-empty fingerprints in SpreadResponse
	assert.NotEmpty(t, reply.GetFingerprintCertificates(), "SpreadResponse must return non-empty certificate fingerprint")
	assert.NotEmpty(t, reply.GetFingerprintView(), "SpreadResponse must return non-empty view fingerprint")
	assert.NotEmpty(t, reply.GetFingerprintAccusations(), "SpreadResponse must return non-empty accusations fingerprint")

	assert.Equal(t, nodeA.CertFingerprintBytes(), reply.GetFingerprintCertificates(),
		"SpreadResponse certificate fingerprint must match Node A's fingerprint")
	assert.Equal(t, nodeA.ViewFingerprintBytes(), reply.GetFingerprintView(),
		"SpreadResponse view fingerprint must match Node A's fingerprint")

	// 4. Verify deltas were negotiated
	deltas := ExtractReconcileDeltas(reply)
	require.True(t, deltas.HasDeltas(), "SpreadResponse must contain negotiated control deltas")

	// 5. Ingest fast-path accusations and trigger streaming Sync to pull down Node A's control items
	if accs := reply.GetAccusations(); len(accs) > 0 {
		nodeB.mergeAccusations(accs)
	}

	err = nodeB.syncBootstrap(commA.Addr(), deltas)
	require.NoError(t, err, "Node B must successfully stream sync with Node A")

	// 6. Verify Node B now has Node A's certificate and peer representation
	require.Eventually(t, func() bool {
		return nodeB.view.Exists(idA)
	}, 3*time.Second, 20*time.Millisecond, "Node B must have admitted Node A into full view via Sync")

	peerAOnB := nodeB.view.Peer(idA)
	require.NotNil(t, peerAOnB, "Node B must have Peer object for Node A")

	// 7. Verify Node B has converged on Node A's certificate fingerprint
	assert.Equal(t, nodeA.CertFingerprintBytes(), nodeB.CertFingerprintBytes(),
		"Certificate fingerprints must match after bootstrap sync")

	// 8. Verify single-round quiescence: subsequent gossip to Node A reports no deltas
	msgInSync := &pb.State{
		FingerprintCertificates: nodeB.CertFingerprintBytes(),
		FingerprintView:         nodeB.ViewFingerprintBytes(),
		FingerprintAccusations:  nodeB.AccusationFingerprintBytes(),
		FingerprintData:         nodeB.FingerprintData(),
	}
	replyInSync, err := nodeB.comm.Gossip(commA.Addr(), msgInSync)
	require.NoError(t, err)
	deltasInSync := ExtractReconcileDeltas(replyInSync)

	// 8. Verify control state quiescence: subsequent gossip to Node A reports zero control deltas
	assert.Empty(t, deltasInSync.AvailableCertificates, "Subsequent gossip must have zero available certificate deltas")
	assert.Empty(t, deltasInSync.RequestedCertificates, "Subsequent gossip must have zero requested certificate deltas")
	assert.Empty(t, deltasInSync.AvailableNotes, "Subsequent gossip must have zero available note deltas")
	assert.Empty(t, deltasInSync.RequestedNotes, "Subsequent gossip must have zero requested note deltas")
	assert.Empty(t, deltasInSync.AvailableAccusations, "Subsequent gossip must have zero available accusation deltas")
	assert.Empty(t, deltasInSync.RequestedAccusations, "Subsequent gossip must have zero requested accusation deltas")
}
