package core

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"testing"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/pki"
	"github.com/eika123/ifrit/digestmaps"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type stubControlDetector[T any] struct {
	mu           sync.Mutex
	validated    []T
	misbehaved   []error
	onValidateFn func(T)
}

func (d *stubControlDetector[T]) ValidateItem(_ context.Context, item T) error {
	d.mu.Lock()
	d.validated = append(d.validated, item)
	fn := d.onValidateFn
	d.mu.Unlock()
	if fn != nil {
		fn(item)
	}
	return nil
}

func (d *stubControlDetector[T]) OnMisbehavior(_ context.Context, err error, _ []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.misbehaved = append(d.misbehaved, err)
}

func (d *stubControlDetector[T]) validatedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.validated)
}

func TestControlCodecs_RoundTripAndDigestPreservation(t *testing.T) {
	caCert, caPriv := genTestCA(t)
	priv, err := genTLSKeys()
	require.NoError(t, err)
	cert := genNodeCertSignedByCA(t, priv, caCert, caPriv)

	// 1. Certificate codec
	pkiCert := pki.CertificateFromX509(cert)
	certHasher := digestmaps.MustDefaultHasher[*pki.Certificate]()
	rawCert, err := (certCodec{}).Encode(pkiCert)
	require.NoError(t, err)
	decodedCert, err := (certCodec{}).Decode(rawCert)
	require.NoError(t, err)
	assert.Equal(t, certHasher(pkiCert), certHasher(decodedCert))

	// 2. Note codec
	pbNote := &pb.Note{
		Epoch: 7,
		Id:    cert.SubjectKeyId,
		Mask:  0x3,
		Signature: &pb.Signature{
			R: []byte{1, 2, 3},
			S: []byte{4, 5, 6},
		},
	}
	noteItem := discovery.NoteFromPb(pbNote)
	noteHasher := digestmaps.MustDefaultHasher[*discovery.Note]()
	rawNote, err := (noteCodec{}).Encode(noteItem)
	require.NoError(t, err)
	decodedNote, err := (noteCodec{}).Decode(rawNote)
	require.NoError(t, err)
	assert.Equal(t, noteHasher(noteItem), noteHasher(decodedNote))

	// 3. Accusation codec
	pbAcc := &pb.Accusation{
		Epoch:   7,
		Accuser: []byte("accuser-id"),
		Accused: cert.SubjectKeyId,
		RingNum: 1,
		Signature: &pb.Signature{
			R: []byte{7, 8},
			S: []byte{9, 10},
		},
	}
	accItem := discovery.AccusationFromPb(pbAcc)
	accHasher := digestmaps.MustDefaultHasher[*discovery.Accusation]()
	rawAcc, err := (accusationCodec{}).Encode(accItem)
	require.NoError(t, err)
	decodedAcc, err := (accusationCodec{}).Decode(rawAcc)
	require.NoError(t, err)
	assert.Equal(t, accHasher(accItem), accHasher(decodedAcc))
}

func TestControlReconcilers_SequentialControlAndConcurrentData(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	require.NotNil(t, peerAOnB)

	// Extra third-party control items on Node A that Node B lacks.
	privC, err := genTLSKeys()
	require.NoError(t, err)
	certC := genNodeCertSignedByCA(t, privC, caCert, caPriv)
	_, insertedCert := nodeA.view.CertStore().Insert(pki.CertificateFromX509(certC))
	require.True(t, insertedCert)

	extraNote := discovery.NoteFromPb(&pb.Note{
		Epoch:     42,
		Id:        certC.SubjectKeyId,
		Mask:      1,
		Signature: &pb.Signature{R: []byte{1}, S: []byte{2}},
	})
	_, insertedNote := nodeA.view.NoteStore().Insert(extraNote)
	require.True(t, insertedNote)

	extraAcc := discovery.AccusationFromPb(&pb.Accusation{
		Epoch:     42,
		Accuser:   certA.SubjectKeyId,
		Accused:   certC.SubjectKeyId,
		RingNum:   1,
		Signature: &pb.Signature{R: []byte{3}, S: []byte{4}},
	})
	_, insertedAcc := nodeA.view.AccusationStore().Insert(extraAcc)
	require.True(t, insertedAcc)

	// Data stores on both nodes.
	dataStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	dataStoreB, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	dataStoreA.InsertBatch("blob-alpha", "blob-beta")
	dataStoreB.Insert("blob-gamma")
	RegisterReconcilableDataStore(nodeA, dataStoreA, nil)
	RegisterReconcilableDataStore(nodeB, dataStoreB, nil)

	// Install stub hooks on Node B to verify causal order (certs -> notes -> accusations)
	// and hook invocation for every received control item.
	var seqMu sync.Mutex
	var applyOrder []string

	certDet := &stubControlDetector[*pki.Certificate]{}
	noteDet := &stubControlDetector[*discovery.Note]{}
	accDet := &stubControlDetector[*discovery.Accusation]{}

	nodeB.SetControlReconcilerHooks(ControlReconcilerHooks{
		CertDetector: certDet,
		CertApplier: func(_ context.Context, item *pki.Certificate) error {
			seqMu.Lock()
			applyOrder = append(applyOrder, storeIDCerts)
			seqMu.Unlock()
			nodeB.view.CertStore().Insert(item)
			return nil
		},
		NoteDetector: noteDet,
		NoteApplier: func(_ context.Context, item *discovery.Note) error {
			seqMu.Lock()
			applyOrder = append(applyOrder, storeIDNotes)
			seqMu.Unlock()
			nodeB.view.NoteStore().Insert(item)
			return nil
		},
		AccDetector: accDet,
		AccApplier: func(_ context.Context, item *discovery.Accusation) error {
			seqMu.Lock()
			applyOrder = append(applyOrder, storeIDAccs)
			seqMu.Unlock()
			nodeB.view.AccusationStore().Insert(item)
			return nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.True(t, nodeA.IsDivergent(peerBOnA))

	err = nodeA.reconcilePeerStores(ctx, peerBOnA)
	require.NoError(t, err)

	// 1. All control stores and data store converged.
	assert.Equal(t, nodeA.CertFingerprint(), nodeB.CertFingerprint())
	assert.Equal(t, nodeA.view.NoteStore().Fingerprint(), nodeB.view.NoteStore().Fingerprint())
	assert.Equal(t, nodeA.AccusationFingerprint(), nodeB.AccusationFingerprint())
	assert.Equal(t, dataStoreA.Fingerprint(), dataStoreB.Fingerprint())
	assert.Equal(t, 3, dataStoreA.Size())
	assert.Equal(t, 3, dataStoreB.Size())

	// 2. Stub hooks fired in strict sequential order: certs -> notes -> accusations.
	assert.Equal(t, 1, certDet.validatedCount())
	assert.Equal(t, 1, noteDet.validatedCount())
	assert.Equal(t, 1, accDet.validatedCount())
	assert.Equal(t, []string{storeIDCerts, storeIDNotes, storeIDAccs}, applyOrder)

	// 3. Peer fingerprints updated on Node A -> no longer divergent.
	assert.False(t, nodeA.IsDivergent(peerBOnA))
}

func validAllRingsMask(numRings uint32) uint32 {
	if numRings >= 32 {
		return ^uint32(0)
	}
	return (uint32(1) << numRings) - 1
}

func signTestPbNote(t *testing.T, priv *ecdsa.PrivateKey, id []byte, epoch uint64, mask uint32) *pb.Note {
	t.Helper()
	n := &pb.Note{Epoch: epoch, Id: id, Mask: mask}
	raw, err := proto.Marshal(n)
	require.NoError(t, err)
	cs := &cryptoStub{priv: priv}
	r, s, err := cs.Sign(raw)
	require.NoError(t, err)
	n.Signature = &pb.Signature{R: r, S: s}
	return n
}

func signTestPbAccusation(t *testing.T, priv *ecdsa.PrivateKey, accuser, accused []byte, epoch uint64, ringNum uint32) *pb.Accusation {
	t.Helper()
	a := &pb.Accusation{
		Epoch:   epoch,
		Accuser: accuser,
		Accused: accused,
		RingNum: ringNum,
	}
	raw, err := proto.Marshal(a)
	require.NoError(t, err)
	cs := &cryptoStub{priv: priv}
	r, s, err := cs.Sign(raw)
	require.NoError(t, err)
	a.Signature = &pb.Signature{R: r, S: s}
	return a
}

func TestControlReconcilers_DefaultHooks_ColdStartCausalPromotion(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	_, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)

	// Admit peer C only on Node A (Node B does not know C yet).
	privC, err := genTLSKeys()
	require.NoError(t, err)
	certC := genNodeCertSignedByCA(t, privC, caCert, caPriv)
	idC := string(certC.SubjectKeyId)
	require.NoError(t, nodeA.view.AddFull(idC, certC))
	peerCOnA := nodeA.view.Peer(idC)
	require.NotNil(t, peerCOnA)
	nodeA.view.AddLive(peerCOnA)

	pbNoteC := signTestPbNote(t, privC, certC.SubjectKeyId, 5, validAllRingsMask(nodeA.view.NumRings()))
	require.NoError(t, nodeA.evalNote(pbNoteC))

	// Determine a ring where Node A is a valid accuser for C (with 3 nodes, A or B is predecessor;
	// if A is valid on ring 1, A signs the accusation; otherwise B is valid—in either case
	// test causal cert -> note -> accusation promotion using whichever ring A is predecessor on,
	// or all rings 1..10 until we find one where A is ValidAccuser for C).
	var accRing uint32
	for r := uint32(1); r <= nodeA.view.NumRings(); r++ {
		if nodeA.view.ValidAccuser(peerCOnA, nodeA.self, r) {
			accRing = r
			break
		}
	}
	require.NotZero(t, accRing, "expected at least one ring where Node A is predecessor of C")

	pbAccC := signTestPbAccusation(t, privA, certA.SubjectKeyId, certC.SubjectKeyId, 5, accRing)
	nodeA.view.AccusationStore().Insert(discovery.AccusationFromPb(pbAccC))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.False(t, nodeB.view.Exists(idC))
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))

	// Single sequential pass must admit C, promote Note(C), and promote Accusation(C) with timer.
	assert.True(t, nodeB.view.Exists(idC))
	peerCOnB := nodeB.view.Peer(idC)
	require.NotNil(t, peerCOnB)
	assert.True(t, nodeB.view.IsAlive(peerCOnB))
	activeNote, ok := nodeB.view.ActiveNote(idC)
	require.True(t, ok)
	assert.Equal(t, uint64(5), activeNote.Epoch())
	assert.True(t, nodeB.view.HasTimer(peerCOnB))
}

func TestControlReconcilers_CertGuards(t *testing.T) {
	caCert, caPriv := genTestCA(t)
	rogueCA, rogueCAPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	_, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)

	// Insert an untrusted CA-signed cert on Node A.
	roguePriv, err := genTLSKeys()
	require.NoError(t, err)
	rogueCert := genNodeCertSignedByCA(t, roguePriv, rogueCA, rogueCAPriv)
	nodeA.view.CertStore().Insert(pki.CertificateFromX509(rogueCert))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = nodeA.reconcilePeerStores(ctx, peerBOnA)
	require.Error(t, err)
	assert.False(t, nodeB.view.Exists(string(rogueCert.SubjectKeyId)))
	assert.False(t, nodeB.view.CertStore().ContainsDigest(nodeA.view.CertStore().Digest(pki.CertificateFromX509(rogueCert))))
}

func TestControlReconcilers_NoteGuards(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Valid rebuttal note (higher epoch) stops active suspicion timer on Node B.
	noteA, ok := nodeB.view.ActiveNote(peerAOnB.Id)
	require.True(t, ok)
	nodeB.view.StartTimer(peerAOnB, noteA, nodeB.self)
	require.True(t, nodeB.view.HasTimer(peerAOnB))

	rebuttal := signTestPbNote(t, privA, certA.SubjectKeyId, 10, validAllRingsMask(nodeB.view.NumRings()))
	nodeA.view.NoteStore().Insert(discovery.NoteFromPb(rebuttal))
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))

	assert.False(t, nodeB.view.HasTimer(peerAOnB))
	assert.True(t, nodeB.view.IsAlive(peerAOnB))
	gotNote, ok := nodeB.view.ActiveNote(peerAOnB.Id)
	require.True(t, ok)
	assert.Equal(t, uint64(10), gotNote.Epoch())

	// 2. Benign stale-epoch note (epoch 2 when B already has epoch 10) must NOT abort sync.
	staleNote := signTestPbNote(t, privA, certA.SubjectKeyId, 2, validAllRingsMask(nodeB.view.NumRings()))
	nodeA.view.NoteStore().Insert(discovery.NoteFromPb(staleNote))
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	gotNote, ok = nodeB.view.ActiveNote(peerAOnB.Id)
	require.True(t, ok)
	assert.Equal(t, uint64(10), gotNote.Epoch())

	// 3. Rule 6 upper-bit mask bypass (all active rings 0 while setting upper bits) must be rejected.
	badMaskNote := signTestPbNote(t, privA, certA.SubjectKeyId, 11, ^validAllRingsMask(nodeB.view.NumRings()))
	badMaskItem := discovery.NoteFromPb(badMaskNote)
	nodeA.view.NoteStore().Insert(badMaskItem)
	err := nodeA.reconcilePeerStores(ctx, peerBOnA)
	require.Error(t, err)
	assert.False(t, nodeB.view.NoteStore().ContainsDigest(nodeA.view.NoteStore().Digest(badMaskItem)))

	// 4. Forged signature note must be rejected.
	nodeA2, commA2, certA2, privA2 := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA2.Stop()
	defer commA2.Stop()
	nodeB2, commB2, certB2, privB2 := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB2.Stop()
	defer commB2.Stop()
	_, peerBOnA2 := pairNodes(t, nodeA2, certA2, privA2, commA2, nodeB2, certB2, privB2, commB2)

	forgedNote := discovery.NoteFromPb(&pb.Note{
		Epoch:     20,
		Id:        certA2.SubjectKeyId,
		Mask:      validAllRingsMask(nodeB2.view.NumRings()),
		Signature: &pb.Signature{R: []byte{1, 2, 3}, S: []byte{4, 5, 6}},
	})
	nodeA2.view.NoteStore().Insert(forgedNote)
	err = nodeA2.reconcilePeerStores(ctx, peerBOnA2)
	require.Error(t, err)
	assert.False(t, nodeB2.view.NoteStore().ContainsDigest(nodeA2.view.NoteStore().Digest(forgedNote)))
}

func TestControlReconcilers_AccusationGuards(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	// 1. Self-accusation triggers handleSelfAccusation (rebuttal increments Node B's epoch).
	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ensure Node B has a valid self-note at epoch 1 and find a ring where A is B's predecessor.
	selfNoteBefore := nodeB.view.SelfNote()
	require.NotNil(t, selfNoteBefore)
	var predRing uint32
	for r := uint32(1); r <= nodeB.view.NumRings(); r++ {
		if nodeB.view.ValidAccuser(nodeB.self, peerAOnB, r) {
			predRing = r
			break
		}
	}
	require.NotZero(t, predRing)

	selfAcc := signTestPbAccusation(t, privA, certA.SubjectKeyId, certB.SubjectKeyId, selfNoteBefore.Epoch(), predRing)
	nodeA.view.AccusationStore().Insert(discovery.AccusationFromPb(selfAcc))
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))

	selfNoteAfter := nodeB.view.SelfNote()
	require.NotNil(t, selfNoteAfter)
	assert.Greater(t, selfNoteAfter.Epoch(), selfNoteBefore.Epoch(), "self-accusation must trigger rebuttal epoch increment")

	// 2. Non-predecessor false accusation (with 3 nodes, pick a ring where C is NOT B's predecessor) must NOT start timer.
	nodeA2, commA2, certA2, privA2 := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA2.Stop()
	defer commA2.Stop()
	nodeB2, commB2, certB2, privB2 := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB2.Stop()
	defer commB2.Stop()
	_, peerBOnA2 := pairNodes(t, nodeA2, certA2, privA2, commA2, nodeB2, certB2, privB2, commB2)

	privC, err := genTLSKeys()
	require.NoError(t, err)
	certC := genNodeCertSignedByCA(t, privC, caCert, caPriv)
	idC := string(certC.SubjectKeyId)
	for _, n := range []*Node{nodeA2, nodeB2} {
		require.NoError(t, n.view.AddFull(idC, certC))
		pC := n.view.Peer(idC)
		n.view.AddLive(pC)
		require.NoError(t, n.evalNote(signTestPbNote(t, privC, certC.SubjectKeyId, 1, validAllRingsMask(n.view.NumRings()))))
	}
	peerCOnB2 := nodeB2.view.Peer(idC)
	peerAOnB2 := nodeB2.view.Peer(string(certA2.SubjectKeyId))

	// Find a ring where A is NOT C's predecessor (with 3 nodes, one of {A, B} is not C's predecessor).
	var nonPredRing uint32
	for r := uint32(1); r <= nodeB2.view.NumRings(); r++ {
		if !nodeB2.view.ValidAccuser(peerCOnB2, peerAOnB2, r) {
			nonPredRing = r
			break
		}
	}
	if nonPredRing != 0 {
		falseAcc := signTestPbAccusation(t, privA2, certA2.SubjectKeyId, certC.SubjectKeyId, 1, nonPredRing)
		nodeA2.view.AccusationStore().Insert(discovery.AccusationFromPb(falseAcc))
		require.NoError(t, nodeA2.reconcilePeerStores(ctx, peerBOnA2))
		assert.False(t, nodeB2.view.HasTimer(peerCOnB2), "non-predecessor accusation must not start suspicion timer")
	}

	// 3. Forged signature accusation must be rejected by ValidateItem.
	// Use Epoch 2 so its CryptographicIdentity never collides with falseAcc above when nonPredRing == 1.
	forgedAcc := discovery.AccusationFromPb(&pb.Accusation{
		Epoch:     2,
		Accuser:   certA2.SubjectKeyId,
		Accused:   certC.SubjectKeyId,
		RingNum:   1,
		Signature: &pb.Signature{R: []byte{9, 9}, S: []byte{8, 8}},
	})
	nodeA2.view.AccusationStore().Insert(forgedAcc)
	err = nodeA2.reconcilePeerStores(ctx, peerBOnA2)
	require.Error(t, err)
	assert.False(t, nodeB2.view.AccusationStore().ContainsDigest(nodeA2.view.AccusationStore().Digest(forgedAcc)))

	// 4. Out-of-bounds ring number (0) must be rejected by ValidateItem.
	nodeA3, commA3, certA3, privA3 := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA3.Stop()
	defer commA3.Stop()
	nodeB3, commB3, certB3, privB3 := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB3.Stop()
	defer commB3.Stop()
	_, peerBOnA3 := pairNodes(t, nodeA3, certA3, privA3, commA3, nodeB3, certB3, privB3, commB3)

	badRingAcc := discovery.AccusationFromPb(signTestPbAccusation(t, privA3, certA3.SubjectKeyId, certB3.SubjectKeyId, 1, 0))
	nodeA3.view.AccusationStore().Insert(badRingAcc)
	err = nodeA3.reconcilePeerStores(ctx, peerBOnA3)
	require.Error(t, err)
	assert.False(t, nodeB3.view.AccusationStore().ContainsDigest(nodeA3.view.AccusationStore().Digest(badRingAcc)))
}

func TestControlReconcilers_ThinSpreadAndBootstrapJoin(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	// Entry node A and bootstrap joiner B (B is NOT in A's view yet).
	nodeA, commA, certA, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()
	nodeB, commB, certB, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	// Start both mTLS gRPC servers (createTestNodeWithComm registers services; Start serves them).
	go commA.Start()
	go commB.Start()

	// Seed entry node A with a third peer C (cert + note) and an application data item.
	privC, err := genTLSKeys()
	require.NoError(t, err)
	certC := genNodeCertSignedByCA(t, privC, caCert, caPriv)
	idC := string(certC.SubjectKeyId)
	require.NoError(t, nodeA.evalValidCertificate(certC))
	noteC := signTestPbNote(t, privC, certC.SubjectKeyId, 3, validAllRingsMask(nodeA.view.NumRings()))
	require.NoError(t, nodeA.evalNote(noteC))

	dataStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterReconcilableDataStore(nodeA, dataStoreA, nil)
	dataStoreA.Insert("entry-only-data")

	dataStoreB, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterReconcilableDataStore(nodeB, dataStoreB, nil)

	require.Nil(t, nodeA.view.Peer(string(certB.SubjectKeyId)), "B must not be in A's view before thin Spread")

	// 1. Thin Spread admits B into A's view and returns no legacy cert/note slices.
	err = nodeB.admitViaThinSpread(commA.Addr())
	require.NoError(t, err)
	require.NotNil(t, nodeA.view.Peer(string(certB.SubjectKeyId)), "thin Spread must admit B into A's view")

	// 2. Bootstrap control reconciliation syncs certs + notes (discovering A and C) without syncing data.
	require.NoError(t, nodeB.reconcileBootstrapControl(commA.Addr()))
	require.NotNil(t, nodeB.view.Peer(string(certA.SubjectKeyId)), "bootstrap control reconciliation must discover entry peer A")
	assert.True(t, nodeB.view.Exists(idC), "bootstrap control reconciliation must discover peer C cert")
	peerCOnB := nodeB.view.Peer(idC)
	require.NotNil(t, peerCOnB)
	assert.True(t, nodeB.view.IsAlive(peerCOnB), "bootstrap control reconciliation must activate peer C note")
	_, hasData := dataStoreB.Contains("entry-only-data")
	assert.False(t, hasData, "bootstrap control reconciliation must defer data store sync")
}

func TestControlReconcilers_GossipSwitchoverAndReadmission(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()
	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	dataStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterReconcilableDataStore(nodeA, dataStoreA, nil)

	dataStoreB, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterReconcilableDataStore(nodeB, dataStoreB, nil)

	peerAOnB, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	require.NotNil(t, peerAOnB)

	// 1. When fingerprints match, Node.gossip() must not reconcile.
	peerBOnA.SetFingerprints(
		nodeA.FingerprintData(),
		nodeA.AccusationFingerprintBytes(),
		nodeA.ViewFingerprintBytes(),
	)
	require.False(t, nodeA.IsDivergent(peerBOnA))
	nodeA.gossip()
	assert.Equal(t, 0, dataStoreB.Size())

	// 2. Make dataStoreA divergent AND evict A from B's view to exercise PermissionDenied -> thin Spread re-admission.
	dataStoreA.Insert("item-from-a")
	require.NoError(t, nodeB.view.RemoveTestFull(string(certA.SubjectKeyId)))
	require.Nil(t, nodeB.view.Peer(string(certA.SubjectKeyId)))
	require.True(t, nodeA.IsDivergent(peerBOnA))

	nodeA.gossip()

	// Re-admission + retry should converge dataStoreB and clear divergence on A.
	_, ok := dataStoreB.Contains("item-from-a")
	assert.True(t, ok, "Node.gossip() must re-admit via thin Spread and converge data store")
	assert.False(t, nodeA.IsDivergent(peerBOnA), "Node.gossip() must update peer fingerprints and clear divergence")
}

func TestControlReconcilers_CrossedWiresTieBreaker(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	n1, comm1, cert1, priv1 := createTestNodeWithComm(t, caCert, caPriv)
	defer n1.Stop()
	defer comm1.Stop()
	n2, comm2, cert2, priv2 := createTestNodeWithComm(t, caCert, caPriv)
	defer n2.Stop()
	defer comm2.Stop()

	// Order by ID so lowNode.self.Id < highNode.self.Id deterministically.
	lowNode, highNode := n1, n2
	lowPeerOnHigh, highPeerOnLow := pairNodes(t, n1, cert1, priv1, comm1, n2, cert2, priv2, comm2)
	if n2.self.Id < n1.self.Id {
		lowNode, highNode = n2, n1
		lowPeerOnHigh, highPeerOnLow = highPeerOnLow, lowPeerOnHigh
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Low-ID node holds active outbound lock for high-ID node -> high-ID inbound request must be aborted (codes.Aborted).
	seqLow, ok := lowNode.SessionManager().GetOrCreate(highNode.self.Id).TryStartOutboundReconciling()
	require.True(t, ok)

	err := highNode.reconcilePeerStores(ctx, lowPeerOnHigh)
	require.Error(t, err)
	var se interface{ GRPCStatus() *status.Status }
	require.ErrorAs(t, err, &se)
	assert.Equal(t, codes.Aborted, se.GRPCStatus().Code())
	assert.True(t, lowNode.SessionManager().Get(highNode.self.Id).ResetIfSeq(seqLow))

	// 2. High-ID node holds outbound lock for low-ID node -> low-ID inbound request wins,
	//    high-ID yields cleanly, and high-ID's stale ResetIfSeq cannot clobber low-ID's session.
	seqHigh, ok := highNode.SessionManager().GetOrCreate(lowNode.self.Id).TryStartOutboundReconciling()
	require.True(t, ok)

	require.NoError(t, lowNode.reconcilePeerStores(ctx, highPeerOnLow))
	// After lowNode's inbound streams finish cleanly, highNode's session returned to Idle via ReleaseInbound (seq > seqHigh).
	assert.False(t, highNode.SessionManager().Get(lowNode.self.Id).ResetIfSeq(seqHigh))
	assert.Equal(t, SessionIdle, highNode.SessionManager().Get(lowNode.self.Id).State())
}

type errRecordingReconciler struct {
	inner reconcile.StoreReconciler
	mu    sync.Mutex
	errs  []error
}

func (r *errRecordingReconciler) ReconcileWithPeer(ctx context.Context, addr string) (reconcile.Summary, error) {
	sum, err := r.inner.ReconcileWithPeer(ctx, addr)
	if err != nil {
		r.mu.Lock()
		r.errs = append(r.errs, err)
		r.mu.Unlock()
	}
	return sum, err
}

func (r *errRecordingReconciler) errors() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

func TestControlReconcilers_ConcurrentCrossedWiresGossip(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	n1, comm1, cert1, priv1 := createTestNodeWithComm(t, caCert, caPriv)
	defer n1.Stop()
	defer comm1.Stop()
	n2, comm2, cert2, priv2 := createTestNodeWithComm(t, caCert, caPriv)
	defer n2.Stop()
	defer comm2.Stop()

	lowNode, highNode := n1, n2
	lowPeerOnHigh, highPeerOnLow := pairNodes(t, n1, cert1, priv1, comm1, n2, cert2, priv2, comm2)
	if n2.self.Id < n1.self.Id {
		lowNode, highNode = n2, n1
		lowPeerOnHigh, highPeerOnLow = highPeerOnLow, lowPeerOnHigh
	}

	storeLow, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(lowNode, storeLow)
	storeLow.Insert("item-from-low")

	storeHigh, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(highNode, storeHigh)
	storeHigh.Insert("item-from-high")

	lowCertRec := &errRecordingReconciler{inner: lowNode.certReconciler}
	lowDataRec := &errRecordingReconciler{inner: lowNode.dataStoreReconciler}
	lowNode.certReconciler = lowCertRec
	lowNode.dataStoreReconciler = lowDataRec

	highCertRec := &errRecordingReconciler{inner: highNode.certReconciler}
	highDataRec := &errRecordingReconciler{inner: highNode.dataStoreReconciler}
	highNode.certReconciler = highCertRec
	highNode.dataStoreReconciler = highDataRec

	require.True(t, lowNode.IsDivergent(highPeerOnLow))
	require.True(t, highNode.IsDivergent(lowPeerOnHigh))

	// Fire both nodes' gossip() concurrently against each other behind a barrier.
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		lowNode.gossip()
	}()
	go func() {
		defer wg.Done()
		<-start
		highNode.gossip()
	}()
	close(start)
	wg.Wait()

	// Lower-ID node holds priority and must complete without errors; any error on the
	// higher-ID node during crossed-wires overlap must be codes.Aborted from the tie-breaker.
	assert.Empty(t, lowCertRec.errors())
	assert.Empty(t, lowDataRec.errors())
	for _, recErr := range append(highCertRec.errors(), highDataRec.errors()...) {
		code, ok := grpcStatusCode(recErr)
		require.True(t, ok, "expected gRPC status error, got %v", recErr)
		assert.Equal(t, codes.Aborted, code)
	}

	// Both sessions must return cleanly to SessionIdle with no deadlock or leaked locks.
	assert.Equal(t, SessionIdle, lowNode.SessionManager().GetOrCreate(highNode.self.Id).State())
	assert.Equal(t, SessionIdle, highNode.SessionManager().GetOrCreate(lowNode.self.Id).State())

	// Even if highNode aborted mid-round, lowNode's bidirectional session converged both stores.
	assert.Equal(t, 2, storeLow.Size())
	assert.Equal(t, 2, storeHigh.Size())
	_, hasLowOnHigh := storeHigh.Contains("item-from-low")
	_, hasHighOnLow := storeLow.Contains("item-from-high")
	assert.True(t, hasLowOnHigh)
	assert.True(t, hasHighOnLow)
	assert.False(t, lowNode.IsDivergent(highPeerOnLow))
}

func TestControlReconcilers_NaiveStrategyEndToEnd(t *testing.T) {
	prev := viper.GetString("reconciliation_strategy")
	viper.Set("reconciliation_strategy", "naive")
	t.Cleanup(func() {
		viper.Set("reconciliation_strategy", prev)
	})

	caCert, caPriv := genTestCA(t)

	n1, comm1, _, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer n1.Stop()
	defer comm1.Stop()
	n2, comm2, _, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer n2.Stop()
	defer comm2.Stop()

	require.Equal(t, "naive", n1.reconciliationStrategy)
	require.Equal(t, "naive", n2.reconciliationStrategy)

	// 1. Seed a third peer C on n1 and verify thin Spread + bootstrap control reconciliation under naive.
	privC, err := genTLSKeys()
	require.NoError(t, err)
	certC := genNodeCertSignedByCA(t, privC, caCert, caPriv)
	require.NoError(t, n1.evalValidCertificate(certC))
	require.NoError(t, n1.evalNote(signTestPbNote(t, privC, certC.SubjectKeyId, 2, validAllRingsMask(n1.view.NumRings()))))

	require.NoError(t, n2.admitViaThinSpread(comm1.Addr()))
	require.NoError(t, n2.reconcileBootstrapControl(comm1.Addr()))
	assert.True(t, n2.view.Exists(string(certC.SubjectKeyId)))

	// 2. Pair two fresh naive nodes + register naive data stores and test concurrent crossed-wires gossip convergence.
	n3, comm3, cert3, priv3 := createTestNodeWithComm(t, caCert, caPriv)
	defer n3.Stop()
	defer comm3.Stop()
	n4, comm4, cert4, priv4 := createTestNodeWithComm(t, caCert, caPriv)
	defer n4.Stop()
	defer comm4.Stop()

	lowNode, highNode := n3, n4
	lowPeerOnHigh, highPeerOnLow := pairNodes(t, n3, cert3, priv3, comm3, n4, cert4, priv4, comm4)
	if n4.self.Id < n3.self.Id {
		lowNode, highNode = n4, n3
		lowPeerOnHigh, highPeerOnLow = highPeerOnLow, lowPeerOnHigh
	}

	storeLow, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(lowNode, storeLow)
	storeLow.Insert("naive-low-item")

	storeHigh, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(highNode, storeHigh)
	storeHigh.Insert("naive-high-item")

	require.True(t, lowNode.IsDivergent(highPeerOnLow))
	require.True(t, highNode.IsDivergent(lowPeerOnHigh))

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		lowNode.gossip()
	}()
	go func() {
		defer wg.Done()
		<-start
		highNode.gossip()
	}()
	close(start)
	wg.Wait()

	assert.Equal(t, SessionIdle, lowNode.SessionManager().GetOrCreate(highNode.self.Id).State())
	assert.Equal(t, SessionIdle, highNode.SessionManager().GetOrCreate(lowNode.self.Id).State())
	assert.Equal(t, 2, storeLow.Size())
	assert.Equal(t, 2, storeHigh.Size())
	assert.False(t, lowNode.IsDivergent(highPeerOnLow))
}
