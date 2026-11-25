package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/eika123/ifrit/crypto"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testServiceSigner struct {
	priv *ecdsa.PrivateKey
}

func (s *testServiceSigner) Sign(content []byte) ([]byte, []byte, error) {
	hash := crypto.HashContent(content)
	r, sigS, err := ecdsa.Sign(rand.Reader, s.priv, hash)
	if err != nil {
		return nil, nil, err
	}
	return r.Bytes(), sigS.Bytes(), nil
}

func genTestServicePeer(t *testing.T, idx int) (*Peer, *testServiceSigner) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	idSum := sha256.Sum256(fmt.Appendf(nil, "service-test-peer-%d", idx))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(idx + 1)),
		Subject: pkix.Name{
			Locality: []string{
				fmt.Sprintf("127.0.0.1:%d", 20000+idx*2),
				fmt.Sprintf("127.0.0.1:%d", 20001+idx*2),
			},
		},
		SubjectKeyId: idSum[:],
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	p, err := newPeer(cert, 5)
	require.NoError(t, err)
	return p, &testServiceSigner{priv: priv}
}

func TestServiceNote_BinaryRoundTripAndDistinctEpochs(t *testing.T) {
	peer, sig := genTestServicePeer(t, 1)
	hasher := digestmaps.MustDefaultHasher[*ServiceNote]()

	v0 := NewServiceVector()
	v1, ok := v0.AddItem(digestmaps.VersionedItem[string]{Item: "dht", Version: 1})
	require.True(t, ok)
	note1, err := NewSignedServiceNote(peer.Id, v1, sig)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), note1.Epoch())
	assert.True(t, note1.HasService("dht"))
	ver, ok := note1.ServiceVersion("dht")
	require.True(t, ok)
	assert.Equal(t, uint64(1), ver)

	raw, err := note1.MarshalBinary()
	require.NoError(t, err)
	decoded, err := UnmarshalServiceNote(raw)
	require.NoError(t, err)
	assert.Equal(t, note1.Id(), decoded.Id())
	assert.Equal(t, note1.Epoch(), decoded.Epoch())
	assert.Equal(t, note1.VectorFingerprint(), decoded.VectorFingerprint())
	assert.Equal(t, hasher(note1), hasher(decoded))

	// Removing "dht" at epoch 2 and re-adding "dht" v1 at epoch 3 must produce a DISTINCT
	// CryptographicIdentity digest even though VectorFingerprint() is identical to epoch 1.
	v2, removed := v1.Remove("dht")
	require.True(t, removed)
	v3, added := v2.AddItem(digestmaps.VersionedItem[string]{Item: "dht", Version: 1})
	require.True(t, added)
	note3, err := NewSignedServiceNote(peer.Id, v3, sig)
	require.NoError(t, err)

	assert.Equal(t, uint64(3), note3.Epoch())
	assert.Equal(t, note1.VectorFingerprint(), note3.VectorFingerprint())
	assert.NotEqual(t, hasher(note1), hasher(note3), "distinct epochs with same services must produce distinct store digests")
}

func TestServiceAccusation_BinaryRoundTrip(t *testing.T) {
	accuser, sig := genTestServicePeer(t, 1)
	accused, _ := genTestServicePeer(t, 2)
	hasher := digestmaps.MustDefaultHasher[*ServiceAccusation]()

	acc, err := NewSignedServiceAccusation(accused.Id, accuser.Id, "dht", 4, 2, sig)
	require.NoError(t, err)

	raw, err := acc.MarshalBinary()
	require.NoError(t, err)
	decoded, err := UnmarshalServiceAccusation(raw)
	require.NoError(t, err)

	assert.Equal(t, acc.Accused(), decoded.Accused())
	assert.Equal(t, acc.Accuser(), decoded.Accuser())
	assert.Equal(t, acc.ServiceID(), decoded.ServiceID())
	assert.Equal(t, acc.ServiceVersion(), decoded.ServiceVersion())
	assert.Equal(t, acc.RingNum(), decoded.RingNum())
	assert.Equal(t, hasher(acc), hasher(decoded))
}

func newTestServiceDirectory(t *testing.T, self *Peer, numRings uint32) *ServiceDirectory {
	t.Helper()
	svcStore, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*ServiceNote]())
	require.NoError(t, err)
	accStore, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*ServiceAccusation]())
	require.NoError(t, err)
	sd, err := NewServiceDirectory(self, numRings, svcStore, accStore)
	require.NoError(t, err)
	return sd
}

func TestNewServiceDirectory_FailsClosedOnNilStores(t *testing.T) {
	self, _ := genTestServicePeer(t, 0)
	svcStore, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*ServiceNote]())
	require.NoError(t, err)
	accStore, err := naive.NewReconcilableStore(digestmaps.MustDefaultHasher[*ServiceAccusation]())
	require.NoError(t, err)

	_, err = NewServiceDirectory(self, 3, nil, accStore)
	require.Error(t, err)

	_, err = NewServiceDirectory(self, 3, svcStore, nil)
	require.Error(t, err)
}

func TestServiceDirectory_SparseRingSuperOverlayAndPredecessorVerification(t *testing.T) {
	const numRings = 5
	self, selfSig := genTestServicePeer(t, 0)
	sd := newTestServiceDirectory(t, self, numRings)

	// Create 49 other live peers; only 3 of them (indices 7, 23, 41) plus self host "dht".
	liveMap := map[string]*Peer{self.Id: self}
	isLive := func(id string) (*Peer, bool) {
		p, ok := liveMap[id]
		return p, ok
	}

	sparseIndices := map[int]bool{7: true, 23: true, 41: true}
	var sparsePeers []*Peer
	var nonDHTPeer *Peer

	for i := 1; i < 50; i++ {
		p, pSig := genTestServicePeer(t, i)
		liveMap[p.Id] = p
		if sparseIndices[i] {
			sparsePeers = append(sparsePeers, p)
			v, _ := NewServiceVector().AddItem(digestmaps.VersionedItem[string]{Item: "dht", Version: 1})
			note, err := NewSignedServiceNote(p.Id, v, pSig)
			require.NoError(t, err)
			require.True(t, sd.PromoteServiceNote(note, isLive))
		} else if nonDHTPeer == nil {
			nonDHTPeer = p
		}
	}

	_, overlay, err := sd.RegisterLocalService(selfSig, "dht", 1, nil)
	require.NoError(t, err)
	require.NotNil(t, overlay)

	// Members("dht") returns only the 3 remote sparse peers (not the 46 non-dht peers).
	members := sd.Members("dht")
	require.Len(t, members, 3)

	// RingSuperOverlay connects self directly to the sparse peers (ignoring the 46 non-dht peers).
	neighbours := overlay.Neighbours()
	require.NotEmpty(t, neighbours)
	sparseIDSet := make(map[string]bool)
	for _, sp := range sparsePeers {
		sparseIDSet[sp.Id] = true
	}
	for _, nb := range neighbours {
		assert.True(t, sparseIDSet[nb.ID], "super-overlay neighbour must belong to S_dht")
	}

	// Predecessor verification: find the true predecessor of sparsePeers[0] on ring 1 in S_dht.
	target := sparsePeers[0]
	allDHT := append([]*Peer{self}, sparsePeers...)
	truePredecessors := 0
	for _, candidate := range allDHT {
		if candidate.Id == target.Id {
			continue
		}
		if sd.IsServicePredecessor("dht", target.Id, candidate.Id, 1) {
			truePredecessors++
			// Also verify standalone IsPredecessorInMemberSet agrees with RingSuperOverlay.
			assert.True(t, IsPredecessorInMemberSet(sd.membersByService["dht"], target.Id, candidate.Id, 1))
		}
	}
	assert.Equal(t, 1, truePredecessors, "exactly one member in S_dht must be the predecessor of target on ring 1")

	// A non-dht peer is never a valid predecessor in S_dht.
	assert.False(t, sd.IsServicePredecessor("dht", target.Id, nonDHTPeer.Id, 1))
}

func TestServiceDirectory_PerServiceRebuttalIsolationAndEviction(t *testing.T) {
	const numRings = 3
	self, selfSig := genTestServicePeer(t, 0)
	peerB, sigB := genTestServicePeer(t, 1)

	sd := newTestServiceDirectory(t, self, numRings)

	liveMap := map[string]*Peer{self.Id: self, peerB.Id: peerB}
	isLive := func(id string) (*Peer, bool) {
		p, ok := liveMap[id]
		return p, ok
	}

	// Both self and peerB host "dht" v1 and "pubsub" v1.
	_, _, err := sd.RegisterLocalService(selfSig, "dht", 1, nil)
	require.NoError(t, err)
	_, _, err = sd.RegisterLocalService(selfSig, "pubsub", 1, nil)
	require.NoError(t, err)

	vB1, _ := NewServiceVector().AddItem(digestmaps.VersionedItem[string]{Item: "dht", Version: 1})
	vB2, _ := vB1.AddItem(digestmaps.VersionedItem[string]{Item: "pubsub", Version: 1})
	noteB, err := NewSignedServiceNote(peerB.Id, vB2, sigB)
	require.NoError(t, err)
	require.True(t, sd.PromoteServiceNote(noteB, isLive))

	// In a 2-node super-overlay {self, peerB}, self is peerB's predecessor on ring 1.
	_, err = sd.CreateServiceAccusation(selfSig, peerB, "dht", 1, isLive)
	require.NoError(t, err)
	assert.True(t, sd.HasServiceTimeout(peerB.Id, "dht"))

	// Unrelated service "pubsub" upgrades to v2 on peerB (advancing ServiceNote.Epoch()),
	// while "dht" remains at v1. The suspicion timer for "dht" MUST NOT be cancelled!
	vB3, _ := vB2.AddItem(digestmaps.VersionedItem[string]{Item: "pubsub", Version: 2})
	noteBPubsubBump, err := NewSignedServiceNote(peerB.Id, vB3, sigB)
	require.NoError(t, err)
	require.True(t, sd.PromoteServiceNote(noteBPubsubBump, isLive))
	assert.True(t, sd.HasServiceTimeout(peerB.Id, "dht"), "unrelated service update must not cancel dht accusation")

	// When removalTimeout elapses without a "dht" version bump, peerB is evicted from "dht"
	// while staying in "pubsub" (and host peerB remains alive).
	sd.CheckTimeouts(time.Now().Add(2*time.Minute), 60.0)
	assert.Empty(t, sd.Members("dht"), "expired service suspicion must evict peerB from dht")
	assert.Len(t, sd.Members("pubsub"), 1, "peerB must remain a member of pubsub")

	// When peerB later bumps "dht" to v2, it is re-admitted to "dht".
	vB4, _ := vB3.AddItem(digestmaps.VersionedItem[string]{Item: "dht", Version: 2})
	noteBRebut, err := NewSignedServiceNote(peerB.Id, vB4, sigB)
	require.NoError(t, err)
	require.True(t, sd.PromoteServiceNote(noteBRebut, isLive))
	assert.Len(t, sd.Members("dht"), 1)

	// Verify local health-check-gated rebuttal:
	healthy := true
	_, _, err = sd.RegisterLocalService(selfSig, "worker", 1, func() bool { return healthy })
	require.NoError(t, err)

	rebutAnn, rebutted, err := sd.ShouldRebutService(selfSig, "worker", 1)
	require.NoError(t, err)
	assert.True(t, rebutted)
	ver, ok := rebutAnn.ServiceVersion("worker")
	require.True(t, ok)
	assert.Equal(t, uint64(2), ver)

	// When health check returns false, ShouldRebutService unregisters "worker" instead of rebutting.
	healthy = false
	unregAnn, rebutted, err := sd.ShouldRebutService(selfSig, "worker", 2)
	require.NoError(t, err)
	assert.False(t, rebutted)
	assert.False(t, unregAnn.HasService("worker"))
}
