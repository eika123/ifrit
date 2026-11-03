package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	proto "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
)

type HandlerTestSuite struct {
	suite.Suite
	n *Node

	priv    *ecdsa.PrivateKey
	privMap map[string]*ecdsa.PrivateKey
}

func TestHandlerTestSuite(t *testing.T) {
	r := log.Root()

	r.SetHandler(log.CallerFileHandler(log.StreamHandler(os.Stdout, log.TerminalFormat())))
	//r.SetHandler(log.DiscardHandler())

	suite.Run(t, new(HandlerTestSuite))
}

func (suite *HandlerTestSuite) SetupTest() {
	priv, err := genKeys()
	require.NoError(suite.T(), err, "Failed to generate keys")

	numTestPeers := 100

	ownCert := genCert(priv, 10)

	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: ownCert}, &cryptoStub{priv: priv})
	require.NoError(suite.T(), err, "Failed to create node.")

	suite.n = n

	suite.privMap = make(map[string]*ecdsa.PrivateKey)

	for i := 0; i < numTestPeers; i++ {
		p, priv, err := addPeer(suite.n)
		require.NoError(suite.T(), err, "Could not add peer.")
		suite.privMap[p.Id] = priv
	}

	suite.priv = priv
}

func (suite *HandlerTestSuite) TestSpread() {
	var nonExistingNeighbours []string
	var ringNum uint32 = 1

	node := suite.n

	testPeers := nonNeighbouringPeers(node, 5)

	for i, p := range testPeers {
		require.False(suite.T(), node.view.ShouldBeNeighbour(p.Id),
			"Peer should not be neighbour.")

		if i != 0 {
			require.False(suite.T(), node.view.IsAlive(p), "Peer should be dead.")
		} else {
			require.True(suite.T(), node.view.IsAlive(p), "Peer should be alive.")
		}
	}

	notNeighbour := testPeers[0]

	accusedNonNeighbour := testPeers[1]
	acc := discovery.NewAccusation(1, accusedNonNeighbour.Id, node.self.Id, 1,
		suite.priv)
	node.view.AddTestAccusation(acc)

	rebuttalPeer := testPeers[2]
	acc2 := discovery.NewAccusation(1, rebuttalPeer.Id, node.self.Id, 1, suite.priv)
	node.view.AddTestAccusation(acc2)

	accusedNote, _ := node.view.ActiveNote(accusedNonNeighbour.Id)

	nonExistingPeer := testPeers[3]
	nonExistingNote, _ := node.view.ActiveNote(nonExistingPeer.Id)
	node.view.RemoveTestFull(nonExistingPeer.Id)

	invalidNonExisting := testPeers[4]
	node.view.RemoveTestFull(invalidNonExisting.Id)

	succ, _ := node.view.MyRingNeighbours(ringNum)

	tests := []struct {
		ctx  context.Context
		args *proto.State

		peer *discovery.Peer

		specificErr error
		err         bool

		isAccused bool
		exists    bool
		live      bool

		certs []string
		notes []string
		accs  []string

		findNeighbours bool
	}{
		{
			ctx:    noCertPeerContext(succ),
			err:    true,
			exists: true,
			live:   true,
			peer:   succ,
		},

		{
			ctx:    invalidCertPeerContext(succ),
			err:    true,
			exists: true,
			live:   true,
			peer:   succ,
		},

		{
			ctx:    peerContext(succ),
			err:    false,
			exists: true,
			live:   true,
			peer:   succ,
		},

		{
			ctx:       peerContext(accusedNonNeighbour),
			err:       false,
			isAccused: true,
			accs:      []string{accusedNonNeighbour.Id},
			args: &proto.State{
				OwnNote: accusedNote.ToPbMsg(),
			},
			exists: true,
			live:   false,
			peer:   accusedNonNeighbour,
		},

		{
			ctx:       peerContext(rebuttalPeer),
			err:       false,
			isAccused: false,
			args: &proto.State{
				OwnNote: discovery.NewNote(rebuttalPeer.Id, 2, math.MaxUint32,
					suite.privMap[rebuttalPeer.Id]),
			},
			exists: true,
			live:   true,
			peer:   rebuttalPeer,
		},

		{
			ctx:         peerContext(notNeighbour),
			err:         false,
			specificErr: errNotMyNeighbour,
			exists:      true,
			live:        true,
			peer:        notNeighbour,
		},

		{
			ctx:    invalidCertPeerContext(invalidNonExisting),
			err:    true,
			exists: false,
			live:   false,
			peer:   invalidNonExisting,
		},

		{
			ctx:    peerContext(nonExistingPeer),
			err:    false,
			certs:  nonExistingNeighbours,
			notes:  nonExistingNeighbours,
			exists: true,
			live:   true,
			peer:   nonExistingPeer,
			args: &proto.State{
				OwnNote: nonExistingNote.ToPbMsg(),
			},
			findNeighbours: true,
		},
	}

	for i, t := range tests {
		reply, err := node.Spread(t.ctx, t.args)

		if !t.err {
			if t.specificErr != nil {
				require.EqualErrorf(suite.T(), err, t.specificErr.Error(),
					"Returned wrong  error in test %d.", i)
			}
		} else {
			require.Errorf(suite.T(), err, "Should return error in test %d.", i)
		}

		if !t.err && t.specificErr == nil {
			require.NotNil(suite.T(), reply, "Invalid response for test %d.", i)
		} else {
			require.Nil(suite.T(), reply, "Invalid response for test %d.", i)
		}

		require.Equalf(suite.T(), t.isAccused, node.view.IsAccused(t.peer),
			"Invalid accused state for test %d.", i)
		require.Equalf(suite.T(), t.exists, node.view.Exists(t.peer.Id),
			"Invalid exists state for test %d.", i)
		require.Equalf(suite.T(), t.live, node.view.IsAlive(t.peer),
			"Invalid live state for test %d.", i)

		var certs []string
		for _, c := range reply.GetCertificates() {
			cert, err := x509.ParseCertificate(c.GetRaw())
			require.NoError(suite.T(), err, "Failed to parse certificate.")

			certs = append(certs, string(cert.SubjectKeyId))
		}

		var notes []string
		for _, n := range reply.GetNotes() {
			notes = append(notes, string(n.GetId()))
		}

		var accs []string
		for _, a := range reply.GetAccusations() {
			accs = append(accs, string(a.GetAccused()))
		}

		if !t.findNeighbours {
			require.ElementsMatchf(suite.T(), t.certs, certs,
				"Invalid certificate output for test %d.", i)

			require.ElementsMatchf(suite.T(), t.notes, notes,
				"Invalid note output for test %d.", i)

			require.ElementsMatchf(suite.T(), t.accs, accs,
				"Invalid accusation output for test %d.", i)
		} else {
			// Zero-piggybacking invariant: non-neighbour Spread must not piggyback raw certificates or notes.
			require.Emptyf(suite.T(), reply.GetCertificates(),
				"SpreadResponse must not piggyback certificates in test %d.", i)
			require.Emptyf(suite.T(), reply.GetNotes(),
				"SpreadResponse must not piggyback notes in test %d.", i)

			// Fingerprints must be populated and non-empty for control state reconciliation
			require.NotEmptyf(suite.T(), reply.GetFingerprintCertificates(),
				"SpreadResponse must include non-empty certificate fingerprint in test %d.", i)
			require.NotEmptyf(suite.T(), reply.GetFingerprintView(),
				"SpreadResponse must include non-empty view fingerprint in test %d.", i)
			require.NotEmptyf(suite.T(), reply.GetFingerprintAccusations(),
				"SpreadResponse must include non-empty accusations fingerprint in test %d.", i)
		}
	}
}

func (suite *HandlerTestSuite) TestMessenger() {

}

func (suite *HandlerTestSuite) TestSpread_UnconditionalIngestion() {
	node := suite.n

	testPeers := nonNeighbouringPeers(node, 2)
	notNeighbour := testPeers[0]
	ctx := peerContext(notNeighbour)

	badSigPb := discovery.NewNote(notNeighbour.Id, 50, math.MaxUint32, suite.privMap[notNeighbour.Id])
	badSigPb.Signature = &proto.Signature{R: []byte("bogus_r"), S: []byte("bogus_s")}

	args := &proto.State{
		OwnNote: badSigPb,
	}

	_, err := node.Spread(ctx, args)
	require.Error(suite.T(), err)

	rawNote := discovery.NoteFromPb(badSigPb)
	stored, found := node.view.NoteStore().Contains(rawNote)
	require.True(suite.T(), found, "Spread must unconditionally ingest caller's note into NoteStore")
	require.Equal(suite.T(), rawNote.Epoch(), stored.Epoch())
}

func peerContext(p *discovery.Peer) context.Context {
	cert, err := x509.ParseCertificate(p.Certificate())
	if err != nil {
		panic(err)
	}

	authInfo := &grpcPeer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}

	return grpcPeer.NewContext(context.Background(), authInfo)
}

func noCertPeerContext(p *discovery.Peer) context.Context {
	authInfo := &grpcPeer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{},
		},
	}

	return grpcPeer.NewContext(context.Background(), authInfo)
}

func invalidCertPeerContext(p *discovery.Peer) context.Context {
	cert, err := x509.ParseCertificate(p.Certificate())
	if err != nil {
		panic(err)
	}

	cert.Signature = []byte("Invalid signature")

	authInfo := &grpcPeer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}

	return grpcPeer.NewContext(context.Background(), authInfo)
}

func nonNeighbouringPeers(n *Node, amount int) []*discovery.Peer {
	var fetched []*discovery.Peer

	for i := 0; i < amount; i++ {
		for _, p := range n.view.Full() {
			if !n.view.ShouldBeNeighbour(p.Id) {
				counter := 0
				for _, p2 := range fetched {
					if p.Id == p2.Id {
						break
					}
					counter++
				}

				if counter == len(fetched) {
					if i != 0 {
						n.view.RemoveLive(p)
					}
					fetched = append(fetched, p)
					break
				}
			}
		}
	}

	invalid := checkPeerPlacement(n, fetched)
	if invalid != nil {
		for _, p := range invalid {
			n.view.AddLive(p)
		}

		return nonNeighbouringPeers(n, amount)
	}

	return fetched
}

func checkPeerPlacement(n *Node, peers []*discovery.Peer) []*discovery.Peer {
	var invalid []*discovery.Peer

	for _, p := range peers {
		if n.view.ShouldBeNeighbour(p.Id) {
			invalid = append(invalid, p)
		}

	}

	return invalid
}

func addPeer(node *Node) (*discovery.Peer, *ecdsa.PrivateKey, error) {
	privKey, err := genKeys()
	if err != nil {
		return nil, nil, err
	}

	c := genCert(privKey, node.view.NumRings())

	id := string(c.SubjectKeyId)

	err = node.view.AddFull(id, c)
	if err != nil {
		return nil, nil, err
	}

	p := node.view.Peer(id)

	node.view.AddLive(p)

	node.view.AddTestNote(p, privKey, 1)

	return p, privKey, nil
}

func genCert(priv *ecdsa.PrivateKey, rings uint32) *x509.Certificate {
	pk := pkix.Name{
		Locality: []string{"127.0.0.1:8000", "pingAddr", "httpAddr"},
	}

	c, err := selfSignedCert(priv, pk)
	if err != nil {
		panic(err)
	}

	return c
}

func genInvalidSignatureCert(priv *ecdsa.PrivateKey, rings uint32) *x509.Certificate {
	pk := pkix.Name{
		Locality: []string{"127.0.0.1:8000", "pingAddr", "httpAddr"},
	}

	c, err := selfSignedCert(priv, pk)
	if err != nil {
		panic(err)
	}

	c.Signature = []byte("Invalid signature")

	return c
}

func genInvalidIdCert(priv *ecdsa.PrivateKey, rings uint32) *x509.Certificate {
	pk := pkix.Name{
		Locality: []string{"127.0.0.1:8000", "pingAddr", "httpAddr"},
	}

	c, err := selfSignedCert(priv, pk)
	if err != nil {
		panic(err)
	}

	c.SubjectKeyId = []byte("Invalid id")

	return c
}

func genKeys() (*ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func selfSignedCert(priv *ecdsa.PrivateKey, pk pkix.Name) (*x509.Certificate, error) {
	ringBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ringBytes[0:], uint32(32))

	ext := pkix.Extension{
		Id:       []int{2, 5, 13, 37},
		Critical: false,
		Value:    ringBytes,
	}

	serviceAddr := strings.Split(pk.Locality[0], ":")
	if len(serviceAddr) <= 0 {
		return nil, errors.New("No service addr in identity")
	}

	ip := net.ParseIP(serviceAddr[0])
	if ip == nil {
		return nil, errors.New("Could not parse ip address")
	}

	serial, err := genSerialNumber()
	if err != nil {
		return nil, err
	}

	// TODO generate ids and serial numbers differently
	newCert := &x509.Certificate{
		SerialNumber:          serial,
		SubjectKeyId:          genId(),
		Subject:               pk,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().AddDate(-10, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtraExtensions:       []pkix.Extension{ext},
		PublicKey:             &priv.PublicKey,
		IPAddresses:           []net.IP{ip},
		IsCA:                  true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign,
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, newCert,
		newCert, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	parsed, err := x509.ParseCertificate(signedCert)
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func genId() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce

}

func genSerialNumber() (*big.Int, error) {
	sLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, sLimit)
	if err != nil {
		return nil, err
	}

	return s, nil
}

type rebuttalTrackingComm struct {
	commStub
	gossipedStates []*proto.State
}

func (r *rebuttalTrackingComm) Gossip(addr string, m *proto.State) (*proto.StateResponse, error) {
	r.gossipedStates = append(r.gossipedStates, m)
	return &proto.StateResponse{}, nil
}

func (suite *HandlerTestSuite) TestSelfAccusationRebuttalTelemetryFlow() {
	node := suite.n
	var ringNum uint32 = 1

	_, prev := node.view.MyRingNeighbours(ringNum)
	require.NotNil(suite.T(), prev, "predecessor must exist on ring")

	originalComm := node.comm
	defer func() {
		node.comm = originalComm
	}()

	trackingComm := &rebuttalTrackingComm{}
	node.comm = trackingComm

	currentNote := node.view.SelfNote()
	require.NotNil(suite.T(), currentNote)
	currentEpoch := currentNote.Epoch()

	// Create valid accusation against self from legitimate predecessor
	acc := discovery.NewAccusation(currentEpoch, node.self.Id, prev.Id, ringNum, suite.privMap[prev.Id])

	// Process accusation against self
	err := node.evalAccusation(acc, prev, node.self)
	require.NoError(suite.T(), err)

	// Verify that rebuttal was dispatched
	require.NotEmpty(suite.T(), trackingComm.gossipedStates, "Rebuttal should have sent at least one gossip message")
	rebuttalMsg := trackingComm.gossipedStates[0]

	// Verify message matches the telemetry rebuttal rule:
	// isRebuttal := !hasFingerprints && stateReq.GetOwnNote() != nil
	hasFingerprints := rebuttalMsg.GetFingerprintView() != nil ||
		rebuttalMsg.GetFingerprintAccusations() != nil ||
		rebuttalMsg.GetFingerprintData() != nil ||
		rebuttalMsg.GetFingerprintCertificates() != nil
	isRebuttal := !hasFingerprints && rebuttalMsg.GetOwnNote() != nil
	require.True(suite.T(), isRebuttal, "Outbound message must be classified as a Rebuttal by telemetry interceptor")

	// Verify epoch was advanced in the rebuttal message
	require.Greater(suite.T(), rebuttalMsg.GetOwnNote().GetEpoch(), currentEpoch)
	require.Equal(suite.T(), node.view.SelfNote().Epoch(), rebuttalMsg.GetOwnNote().GetEpoch())
}
