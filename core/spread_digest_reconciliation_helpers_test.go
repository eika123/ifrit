package core

import (
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/joonnna/ifrit/core/discovery"
	"github.com/joonnna/ifrit/crypto/pki"
	proto "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

func (suite *HandlerTestSuite) TestSpread_InSyncAccusationsReturnsZeroAccusations() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	args := &proto.State{
		FingerprintAccusations: node.AccusationFingerprintBytes(),
		FingerprintView:        node.ViewFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Empty(suite.T(), reply.GetAccusations(), "In-sync accusations must return 0 accusations")
	require.Empty(suite.T(), reply.GetRequestedAccusationDigests())
	require.Equal(suite.T(), node.AccusationFingerprintBytes(), reply.GetFingerprintAccusations())
}

func (suite *HandlerTestSuite) TestSpread_DivergentAccusationDigestsReturnsOnlyMissingDelta() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	// Add an accusation to the node
	acc := discovery.NewAccusation(1, succ.Id, node.self.Id, 1, suite.priv)
	node.view.AddTestAccusation(acc)

	// Caller diverges (different fingerprint and 0 digests)
	args := &proto.State{
		FingerprintAccusations: []byte("divergent-fp"),
		AccusationDigests:      []uint64{},
		FingerprintView:        node.ViewFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Empty(suite.T(), reply.GetAccusations(), "Bulk items must not be piggybacked on Spread")
	expectedDigests := node.AccusationDigestsUint64()
	require.Equal(suite.T(), expectedDigests, reply.GetAvailableAccusationDigests(), "Divergent accusation set must return missing delta digests")
	require.Equal(suite.T(), node.AccusationFingerprintBytes(), reply.GetFingerprintAccusations())
}

func (suite *HandlerTestSuite) TestSpread_ProtocolAgnosticAccusationReconciliation() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	invoked := false
	origProto := node.ReconciliationProtocol()
	customProto := origProto
	customProto.NewAccSession = func(store ReverseIndexStore[*discovery.Accusation, DigestSymbol]) (ReconcilerSession[*discovery.Accusation, DigestSymbol], error) {
		invoked = true
		return NewNaiveSession(store)
	}
	node.SetReconciliationProtocol(customProto)
	defer node.SetReconciliationProtocol(origProto)

	args := &proto.State{
		FingerprintAccusations: []byte("divergent-fp"),
		AccusationDigests:      []uint64{},
		FingerprintView:        node.ViewFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), reply)
	require.True(suite.T(), invoked, "Accusation reconciliation must use pluggable session constructor")
}

func (suite *HandlerTestSuite) TestSpread_DivergentNoteDigestsReturnsOnlyMissingDelta() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	allDigests, err := node.view.NoteDigests()
	require.NoError(suite.T(), err)
	require.NotEmpty(suite.T(), allDigests)

	// Caller has all digests except the first one
	callerDigests := make([]uint64, 0, len(allDigests)-1)
	for _, d := range allDigests[1:] {
		callerDigests = append(callerDigests, uint64(d))
	}

	args := &proto.State{
		FingerprintView:        []byte("divergent-fp"),
		NoteDigests:            callerDigests,
		FingerprintAccusations: node.AccusationFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Empty(suite.T(), reply.GetNotes(), "Bulk items must not be piggybacked on Spread")
	require.Equal(suite.T(), []uint64{uint64(allDigests[0])}, reply.GetAvailableNoteDigests(), "Divergent note set must return only missing delta digest")
	require.Equal(suite.T(), node.ViewFingerprintBytes(), reply.GetFingerprintView())
}

func (suite *HandlerTestSuite) TestSpread_ProtocolAgnosticNoteReconciliation() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	invoked := false
	origProto := node.ReconciliationProtocol()
	customProto := origProto
	customProto.NewNoteSession = func(store ReverseIndexStore[*discovery.Note, DigestSymbol]) (ReconcilerSession[*discovery.Note, DigestSymbol], error) {
		invoked = true
		return NewNaiveSession(store)
	}
	node.SetReconciliationProtocol(customProto)
	defer node.SetReconciliationProtocol(origProto)

	args := &proto.State{
		FingerprintView:        []byte("divergent-fp"),
		NoteDigests:            []uint64{},
		FingerprintAccusations: node.AccusationFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), reply)
	require.True(suite.T(), invoked, "Note reconciliation must use pluggable session constructor")
}

func (suite *HandlerTestSuite) TestSpread_InSyncNotesReturnsZeroNotes() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	args := &proto.State{
		FingerprintView:        node.ViewFingerprintBytes(),
		FingerprintAccusations: node.AccusationFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Empty(suite.T(), reply.GetNotes(), "In-sync view must return 0 notes")
	require.Empty(suite.T(), reply.GetCertificates(), "In-sync view must return 0 certificates")
	require.Equal(suite.T(), node.ViewFingerprintBytes(), reply.GetFingerprintView())
}

func (suite *HandlerTestSuite) TestSpread_DataDigestReconciliationOmitsBulkBytes() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	store, err := revIdxStore.NewDigestSet[uint64, DigestSymbol](func(elem uint64) DigestSymbol {
		return DigestSymbol(elem)
	})
	require.NoError(suite.T(), err)
	store.AddElement(101)
	store.AddElement(102)

	node.SetFingerprintData([]byte("local-data-fp-8b"))
	RegisterDataStore(node, store)
	defer func() {
		node.SetDataReconciler(nil)
	}()

	// Caller has item 101 and 103 (node is missing 103 from caller)
	args := &proto.State{
		FingerprintData:        []byte("caller-data-fp-8"),
		DataDigests:            []uint64{101, 103},
		FingerprintAccusations: node.AccusationFingerprintBytes(),
		FingerprintView:        node.ViewFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Equal(suite.T(), []uint64{103}, reply.GetRequestedDataDigests(), "Node must request missing digest 103 from caller")
	require.Equal(suite.T(), []uint64{102}, reply.GetAvailableDataDigests(), "Node must report missing local digest 102 available for caller")
	require.Equal(suite.T(), []byte("local-data-fp-8b"), reply.GetFingerprintData())
}

func (suite *HandlerTestSuite) TestSpread_DataReconciliationWithTypedDataStore() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	type testItem struct {
		ID   string
		Data string
	}

	hasher := func(item testItem) DigestSymbol {
		return DigestSymbol(len(item.ID)*1000 + len(item.Data))
	}

	store, err := revIdxStore.NewDigestSet[testItem, DigestSymbol](hasher)
	require.NoError(suite.T(), err)

	store.AddElement(testItem{ID: "item1", Data: "alpha"})
	store.AddElement(testItem{ID: "item2", Data: "beta"})

	RegisterDataStore(node, store)
	defer func() {
		node.SetDataReconciler(nil)
	}()

	// Caller is missing one local item and has an unknown item 9999
	args := &proto.State{
		FingerprintData:        []byte("caller-different-fp"),
		DataDigests:            []uint64{5005, 9999},
		FingerprintAccusations: node.AccusationFingerprintBytes(),
		FingerprintView:        node.ViewFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Equal(suite.T(), []uint64{9999}, reply.GetRequestedDataDigests(), "Node must request missing digest 9999 from caller")
	require.Equal(suite.T(), node.FingerprintData(), reply.GetFingerprintData())
}

func (suite *HandlerTestSuite) TestSpread_InSyncCertificatesReturnsZeroCertificates() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	args := &proto.State{
		FingerprintCertificates: node.CertFingerprintBytes(),
		FingerprintView:         node.ViewFingerprintBytes(),
		FingerprintAccusations:  node.AccusationFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Empty(suite.T(), reply.GetCertificates())
	require.Empty(suite.T(), reply.GetAvailableCertificateDigests())
	require.Empty(suite.T(), reply.GetRequestedCertificateDigests())
}

func (suite *HandlerTestSuite) TestSpread_DivergentCertificateDigestsReturnsOnlyMissingDelta() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	certStore := node.view.CertStore()
	require.NotNil(suite.T(), certStore)

	allDigests := certStore.DigestsCopy()
	require.NotEmpty(suite.T(), allDigests)

	// Caller has all digests except the first one, and also an unknown digest 0xfeedbeef
	callerDigests := make([]uint64, 0, len(allDigests)-1)
	for _, d := range allDigests[1:] {
		callerDigests = append(callerDigests, uint64(d))
	}
	callerDigests = append(callerDigests, uint64(0xfeedbeef))

	args := &proto.State{
		FingerprintCertificates: []byte("divergent-cert-fp"),
		CertificateDigests:      callerDigests,
		FingerprintView:         node.ViewFingerprintBytes(),
		FingerprintAccusations:  node.AccusationFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.Empty(suite.T(), reply.GetCertificates(), "Bulk items must not be piggybacked on Spread")
	require.Equal(suite.T(), []uint64{0xfeedbeef}, reply.GetRequestedCertificateDigests(), "Node must request unknown certificate digest")
	require.Equal(suite.T(), []uint64{uint64(allDigests[0])}, reply.GetAvailableCertificateDigests(), "Node must offer available delta digest")
}

func (suite *HandlerTestSuite) TestSpread_ProtocolAgnosticCertReconciliation() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	invoked := false
	origProto := node.ReconciliationProtocol()
	customProto := origProto
	customProto.NewCertSession = func(store ReverseIndexStore[*pki.Certificate, DigestSymbol]) (ReconcilerSession[*pki.Certificate, DigestSymbol], error) {
		invoked = true
		return NewNaiveSession(store)
	}
	node.SetReconciliationProtocol(customProto)
	defer node.SetReconciliationProtocol(origProto)

	args := &proto.State{
		FingerprintCertificates: []byte("divergent-cert-fp"),
		CertificateDigests:      []uint64{},
		FingerprintView:         node.ViewFingerprintBytes(),
		FingerprintAccusations:  node.AccusationFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, args)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), reply)
	require.True(suite.T(), invoked, "Certificate reconciliation must use pluggable session constructor")
}

func (suite *HandlerTestSuite) TestSpread_PeerReconcileSessionStateTransitions() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	// Case 1: In-sync arguments (no deltas) -> session must end in SessionIdle
	inSyncArgs := &proto.State{
		FingerprintView:         node.ViewFingerprintBytes(),
		FingerprintAccusations:  node.AccusationFingerprintBytes(),
		FingerprintCertificates: node.CertFingerprintBytes(),
	}

	reply, err := node.Spread(ctx, inSyncArgs)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), reply)

	sess := node.sessionManager.Get(succ.Id)
	require.NotNil(suite.T(), sess)
	require.Equal(suite.T(), SessionIdle, sess.State())
	require.False(suite.T(), sess.HasDeltas())

	// Case 2: Divergent arguments (deltas computed) -> session must end in SessionAwaitingStream
	divergentArgs := &proto.State{
		FingerprintCertificates: []byte("divergent-fp"),
		CertificateDigests:      []uint64{0x12345678},
		FingerprintView:         node.ViewFingerprintBytes(),
		FingerprintAccusations:  node.AccusationFingerprintBytes(),
	}

	reply2, err := node.Spread(ctx, divergentArgs)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), reply2)

	sess2 := node.sessionManager.Get(succ.Id)
	require.NotNil(suite.T(), sess2)
	require.Equal(suite.T(), SessionAwaitingStream, sess2.State())
	require.True(suite.T(), sess2.HasDeltas())
	require.Equal(suite.T(), []uint64{0x12345678}, sess2.Deltas().RequestedCertificates)
	require.Equal(suite.T(), []uint64{0x12345678}, sess2.Deltas().IngressCertificates(false))
	require.NotEmpty(suite.T(), sess2.Deltas().AvailableCertificates)
	require.NotEmpty(suite.T(), sess2.Deltas().EgressCertificates(false))
}

func (suite *HandlerTestSuite) TestSpread_CrossedWiresTieBreaker() {
	node := suite.n
	succ, _ := node.view.MyRingNeighbours(1)
	ctx := peerContext(succ)

	args := &proto.State{
		FingerprintCertificates: []byte("divergent-fp"),
		CertificateDigests:      []uint64{0x9999},
		FingerprintView:         node.ViewFingerprintBytes(),
		FingerprintAccusations:  node.AccusationFingerprintBytes(),
	}

	origSelfId := node.self.Id
	defer func() {
		node.self.Id = origSelfId
	}()

	// SCENARIO 1: Local node holds priority (selfID < remoteID).
	// Higher peer succ must yield; local node rejects succ's inbound Spread with codes.Aborted.
	node.self.Id = "\x00" // guarantee selfID < succ.Id
	sess := node.sessionManager.GetOrCreate(succ.Id)
	seqOut, ok := sess.TryStartOutboundReconciling()
	require.True(suite.T(), ok)
	require.Equal(suite.T(), SessionOutboundReconciling, sess.State())

	reply, err := node.Spread(ctx, args)
	require.Error(suite.T(), err)
	require.Nil(suite.T(), reply)
	require.Equal(suite.T(), codes.Aborted, status.Code(err))
	// Session must still be in SessionOutboundReconciling with the same sequence number!
	require.Equal(suite.T(), SessionOutboundReconciling, sess.State())
	require.Equal(suite.T(), seqOut, sess.Seq())

	// SCENARIO 2: Remote peer wins priority (remoteID < selfID).
	// Higher peer local node yields to succ; local node accepts succ's inbound Spread!
	node.self.Id = "\xff\xff\xff\xff" // guarantee succ.Id < selfID
	reply2, err2 := node.Spread(ctx, args)
	require.NoError(suite.T(), err2)
	require.NotNil(suite.T(), reply2)
	// Local session must have transitioned to SessionAwaitingStream (due to deltas) with incremented seq!
	require.Equal(suite.T(), SessionAwaitingStream, sess.State())
	require.Greater(suite.T(), sess.Seq(), seqOut)
}

