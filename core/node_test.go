package core

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/core/internal/testutil"
	"github.com/eika123/ifrit/crypto"
	pb "github.com/eika123/ifrit/protobuf"
	log "github.com/inconshreveable/log15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
)

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context
type NodeTestSuite struct {
	suite.Suite
	nodes []*Node
}

func TestNodeTestSuite(t *testing.T) {
	r := log.Root()

	r.SetHandler(log.CallerFileHandler(log.StreamHandler(os.Stdout, log.TerminalFormat())))

	suite.Run(t, new(NodeTestSuite))
}

func (suite *NodeTestSuite) SetupTest() {
	for i := 0; i < 30; i++ {

		priv, err := genKeys()
		require.NoError(suite.T(), err, "Failed to generate keys")

		ownCert := genCert(priv, 10)
		n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: ownCert}, &cryptoStub{priv: priv})
		require.NoError(suite.T(), err, "Failed to create node.")

		suite.nodes = append(suite.nodes, n)
	}
}

func (suite *NodeTestSuite) TestGossip() {
	// Six real Comm-backed nodes admit each other via thin Spread and converge control views
	// via StoreReconciler bootstrap control reconciliation, then assert identical views.
	caCert, caPriv := genTestCA(suite.T())
	const numNodes = 6

	nodes := make([]*Node, numNodes)
	comms := make([]*comm.Comm, numNodes)
	for i := 0; i < numNodes; i++ {
		n, c, _, _ := createTestNodeWithComm(suite.T(), caCert, caPriv)
		nodes[i] = n
		comms[i] = c
		defer n.Stop()
		defer c.Stop()
		go c.Start()
	}

	for _, n := range nodes {
		for _, n2 := range nodes {
			if n == n2 {
				continue
			}
			require.NoError(suite.T(), n.admitViaThinSpread(n2.comm.Addr()))
			require.NoError(suite.T(), n.reconcileBootstrapControl(n2.comm.Addr()))
		}
	}

	// Second pass ensures nodes joined earlier pick up notes/certs from later joiners.
	for _, n := range nodes {
		for _, n2 := range nodes {
			if n == n2 {
				continue
			}
			require.NoError(suite.T(), n.reconcileBootstrapControl(n2.comm.Addr()))
		}
	}

	for _, n := range nodes {
		for _, n2 := range nodes {
			require.NoError(suite.T(), testutil.CompareViews(n.view, n2.view), "Views are not equal.")
		}
	}
}

func (suite *NodeTestSuite) TestStopStopsComm() {
	cs := &commStub{}
	priv, err := genKeys()
	require.NoError(suite.T(), err)
	cert := genCert(priv, 10)

	n, err := NewNode(cs, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(suite.T(), err)

	require.False(suite.T(), cs.isStopped(), "Comm should not be stopped yet")
	n.Stop()
	require.True(suite.T(), cs.isStopped(), "Node.Stop() must call comm.Stop()")
}

type clientStub struct {
}

func (cs *clientStub) Init(config *tls.Config) {
}

func (cs *clientStub) Gossip(addr string, args *pb.State) (*pb.StateResponse, error) {
	return nil, nil
}

func (cs *clientStub) SendMsg(addr string, args *pb.Msg) (*pb.MsgResponse, error) {
	return nil, nil
}

func (cs *clientStub) CloseConn(addr string) {
}

type serverStub struct {
}

func (ss *serverStub) Init(config *tls.Config, n interface{}, maxConcurrent uint32) error {
	return nil
}

func (ss *serverStub) Addr() string {
	return "127.0.0.1:8000"
}

func (ss *serverStub) Start() error {
	return nil
}

func (ss *serverStub) ShutDown() {
}

type commStub struct {
	mu      sync.Mutex
	started bool
	stopped bool
}

func (cs *commStub) isStarted() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.started
}

func (cs *commStub) isStopped() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.stopped
}

func (cs *commStub) StreamMessenger(string, string, chan []byte, chan []byte) error {
	return nil
}

func (cs *commStub) Register(p pb.GossipServer) {
}

func (cs *commStub) RegisterService(*grpc.ServiceDesc, any) {
}

func (cs *commStub) ClientConn(string) (grpc.ClientConnInterface, error) {
	return nil, nil
}

func (cs *commStub) CloseConn(addr string) {
}

func (cs *commStub) Addr() string {
	return "addr"
}

func (cs *commStub) Start() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.started = true
}

func (cs *commStub) Stop() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.stopped = true
}

func (cs *commStub) Gossip(addr string, m *pb.State) (*pb.StateResponse, error) {
	return &pb.StateResponse{}, nil
}

func (cs *commStub) Send(serviceID, addr string, m *pb.Msg) (*pb.MsgResponse, error) {
	return &pb.MsgResponse{}, nil
}

type pingStub struct {
}

func (ps *pingStub) Pause(t time.Duration) {
}

func (ps *pingStub) Start() {
}

func (ps *pingStub) Stop() {
}

func (ps *pingStub) Ping(addr string, m *pb.Ping) (*pb.Pong, error) {
	return &pb.Pong{}, nil
}

func (ps *pingStub) PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte, fpServices []byte) []byte {
	return nil
}

func (ps *pingStub) SetFingerprintsProvider(func() comm.Fingerprints) {
}

func TestNewNode_ParallelDistinctOptions(t *testing.T) {
	priv1, err := genKeys()
	require.NoError(t, err)
	cert1 := genCert(priv1, 10)

	priv2, err := genKeys()
	require.NoError(t, err)
	cert2 := genCert(priv2, 10)

	opts1 := Options{
		GossipInterval:         2 * time.Second,
		ReconciliationStrategy: "naive",
		SyncConfig:             SyncConfig{MaxItemBytes: 1024, Timeout: 5 * time.Second},
	}
	opts2 := Options{
		GossipInterval:         15 * time.Second,
		ReconciliationStrategy: "riblt",
		SyncConfig:             SyncConfig{MaxItemBytes: 4096, Timeout: 12 * time.Second},
	}

	n1, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert1}, &cryptoStub{priv: priv1}, opts1)
	require.NoError(t, err)
	defer n1.Stop()

	n2, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert2}, &cryptoStub{priv: priv2}, opts2)
	require.NoError(t, err)
	defer n2.Stop()

	assert.Equal(t, 2*time.Second, n1.getGossipTimeout())
	assert.Equal(t, "naive", n1.reconciliationStrategy)
	assert.Equal(t, int64(1024), n1.SyncConfig().MaxItemBytes)

	assert.Equal(t, 15*time.Second, n2.getGossipTimeout())
	assert.Equal(t, "riblt", n2.reconciliationStrategy)
	assert.Equal(t, int64(4096), n2.SyncConfig().MaxItemBytes)
}

// TODO we need to decide upon stubs or not stubs etc, not just copy stuff, this is really ugly
type cryptoStub struct {
	priv *ecdsa.PrivateKey
}

func (cs *cryptoStub) Verify(data, r, s []byte, pub *ecdsa.PublicKey) bool {
	if pub == nil {
		log.Error("Peer had no publicKey")
		return false
	}

	var rInt, sInt big.Int

	b := crypto.HashContent(data)

	rInt.SetBytes(r)
	sInt.SetBytes(s)

	return ecdsa.Verify(pub, b, &rInt, &sInt)
}

func (cs *cryptoStub) Sign(data []byte) ([]byte, []byte, error) {
	hash := crypto.HashContent(data)

	r, s, err := ecdsa.Sign(rand.Reader, cs.priv, hash)
	if err != nil {
		return nil, nil, err
	}

	return r.Bytes(), s.Bytes(), nil
}

type cmStub struct {
	cert   *x509.Certificate
	caCert *x509.Certificate
}

func (cm *cmStub) Certificate() *x509.Certificate {
	return cm.cert
}

func (cm *cmStub) CaCertificate() *x509.Certificate {
	return cm.caCert
}

func (cm *cmStub) ContactList() []*x509.Certificate {
	return nil
}

func (cm *cmStub) NumRings() uint32 {
	return 32
}

func (cm *cmStub) Trusted() bool {
	return false
}
