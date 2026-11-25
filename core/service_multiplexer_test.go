package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// what the hell is R5?
func TestControlReconcilers_R5DataErrorDoesNotBlockControlOrServiceFingerprints(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	_, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	require.NotNil(t, peerBOnA)

	// Register a service on nodeB so serviceFP diverges too.
	_, err := nodeB.RegisterService("dht", 1, nil)
	require.NoError(t, err)

	// Install a failing ifrit/data reconciler on nodeA.
	failingDataRec := &stubStoreReconciler{
		fn: func(context.Context, string) (reconcile.Summary, error) {
			return reconcile.Summary{}, errors.New("simulated ifrit/data failure")
		},
	}
	nodeA.registerStoreReconciler(failingDataRec, func() []byte { return []byte{1, 2, 3, 4, 5, 6, 7, 8} })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// reconcilePeerStores returns the data error, yet MUST still update viewFP, accFP, and serviceFP!
	err = nodeA.reconcilePeerStores(ctx, peerBOnA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated ifrit/data failure")

	assert.Equal(t, nodeB.ViewFingerprintBytes(), peerBOnA.FingerprintView(), "viewFP must update despite ifrit/data error")
	assert.Equal(t, nodeB.AccusationFingerprintBytes(), peerBOnA.FingerprintAccusations(), "accFP must update despite ifrit/data error")
	assert.Equal(t, nodeB.ServiceFingerprintBytes(), peerBOnA.FingerprintServices(), "serviceFP must update despite ifrit/data error")
	assert.Len(t, nodeA.ServiceMembers("dht"), 1, "nodeA must discover nodeB's dht service despite ifrit/data error")
}

func TestServiceMultiplexer_SparseStoreConvergenceAndMessagingIsolation(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	nodeC, commC, certC, privC := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeC.Stop()
	defer commC.Stop()

	// Pair A<->B and B<->C and A<->C so all 3 are live in the base view.
	_, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	_, peerCOnB := pairNodes(t, nodeB, certB, privB, commB, nodeC, certC, privC, commC)
	_, peerCOnA := pairNodes(t, nodeA, certA, privA, commA, nodeC, certC, privC, commC)

	// Sparse service "dht" runs ONLY on A and C (B does not run "dht").
	// Service "pubsub" runs on A and B.
	_, err := nodeA.RegisterService("dht", 1, nil)
	require.NoError(t, err)
	_, err = nodeC.RegisterService("dht", 1, nil)
	require.NoError(t, err)

	_, err = nodeA.RegisterService("pubsub", 1, nil)
	require.NoError(t, err)
	_, err = nodeB.RegisterService("pubsub", 1, nil)
	require.NoError(t, err)

	// Attach typed reconcilable stores to "dht" (A, C) and "pubsub" (A, B).
	dhtStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	dhtStoreC, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	require.NoError(t, RegisterServiceStore(nodeA, "dht", dhtStoreA, nil))
	require.NoError(t, RegisterServiceStore(nodeC, "dht", dhtStoreC, nil))

	pubsubStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	pubsubStoreB, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	require.NoError(t, RegisterServiceStore(nodeA, "pubsub", pubsubStoreA, nil))
	require.NoError(t, RegisterServiceStore(nodeB, "pubsub", pubsubStoreB, nil))

	// Reconcile Service Discovery across the cluster.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	require.NoError(t, nodeB.reconcilePeerStores(ctx, peerCOnB))
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerCOnA))

	// Verify sparse discovery: A sees C in "dht" (and NOT B), and sees B in "pubsub" (and NOT C).
	dhtMembersOnA := nodeA.ServiceMembers("dht")
	require.Len(t, dhtMembersOnA, 1)
	assert.Equal(t, nodeC.Id(), dhtMembersOnA[0].ID)

	pubsubMembersOnA := nodeA.ServiceMembers("pubsub")
	require.Len(t, pubsubMembersOnA, 1)
	assert.Equal(t, nodeB.Id(), pubsubMembersOnA[0].ID)

	// Insert into dhtStoreA and pubsubStoreB; background reconcileServiceStores must converge each
	// store across its own RingSuperOverlay without cross-talk.
	dhtStoreA.Insert("dht-record-1")
	dhtStoreC.Insert("dht-record-2")
	pubsubStoreB.Insert("pubsub-topic-1")

	nodeA.reconcileServiceStores()

	assert.Equal(t, dhtStoreA.Fingerprint(), dhtStoreC.Fingerprint(), "sparse dht stores must converge directly between A and C")
	assert.Equal(t, 2, dhtStoreA.Size())
	assert.Equal(t, 2, dhtStoreC.Size())

	assert.Equal(t, pubsubStoreA.Fingerprint(), pubsubStoreB.Fingerprint(), "pubsub stores must converge between A and B")
	assert.Equal(t, 1, pubsubStoreA.Size())
	assert.Equal(t, 1, pubsubStoreB.Size())

	// Verify multiplexed unary messaging and bidirectional streaming by service-id.
	require.NoError(t, nodeA.SetServiceMsgHandler("dht", func(b []byte) ([]byte, error) {
		return []byte("dht:" + string(b)), nil
	}))
	require.NoError(t, nodeA.SetServiceMsgHandler("pubsub", func(b []byte) ([]byte, error) {
		return []byte("pubsub:" + string(b)), nil
	}))
	require.NoError(t, nodeA.SetServiceStreamHandler("dht", func(in, out chan []byte) {
		defer close(out)
		for m := range in {
			out <- []byte("dht-stream:" + string(m))
		}
	}))
	require.NoError(t, nodeA.SetServiceStreamHandler("pubsub", func(in, out chan []byte) {
		defer close(out)
		for m := range in {
			out <- []byte("pubsub-stream:" + string(m))
		}
	}))

	chDHT := make(chan *Message, 1)
	nodeC.SendServiceMessage("dht", nodeA.Addr(), chDHT, []byte("ping"))
	respDHT := <-chDHT
	require.NotNil(t, respDHT)
	require.NoError(t, respDHT.Error)
	assert.Equal(t, "dht:ping", string(respDHT.Data))

	chPubsub := make(chan *Message, 1)
	nodeB.SendServiceMessage("pubsub", nodeA.Addr(), chPubsub, []byte("ping"))
	respPubsub := <-chPubsub
	require.NotNil(t, respPubsub)
	require.NoError(t, respPubsub.Error)
	assert.Equal(t, "pubsub:ping", string(respPubsub.Data))

	// Bidirectional stream routed to "dht" must hit "dht" handler, not "pubsub".
	inCh := make(chan []byte, 1)
	outCh := make(chan []byte, 1)
	nodeC.OpenServiceStream("dht", nodeA.Addr(), inCh, outCh)
	inCh <- []byte("hello")
	close(inCh)
	got := <-outCh
	assert.Equal(t, "dht-stream:hello", string(got))

	// Unregister "dht" on C -> reconcile -> A drops C from ServiceMembers("dht") while C stays live!
	require.NoError(t, nodeC.UnregisterService("dht"))
	peerCOnA.SetFingerprintServices(nil) // simulate Pong detecting new serviceFP
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerCOnA))
	assert.Empty(t, nodeA.ServiceMembers("dht"), "unregistered dht service must be removed from A's service catalog")

	// Confirm C is still alive in A's base Fireflies view.
	foundC := false
	for _, lp := range nodeA.LivePeers() {
		if lp.ID == nodeC.Id() {
			foundC = true
			break
		}
	}
	assert.True(t, foundC, "unregistering a service must keep the host alive in the base view")

	// Verify reconcile.Mux rejected unknown service store after UnregisterService.
	_, err = nodeA.services.storeEntry("dht").rec.ReconcileWithPeer(ctx, nodeC.Addr())
	require.Error(t, err, fmt.Sprintf("reconciling unregistered service store on C should fail (got %v)", err))
}

func TestServiceMultiplexer_MessagingOnlyServiceWithoutStore(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, certA, privA := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	nodeB, commB, certB, privB := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeB.Stop()
	defer commB.Stop()

	_, peerBOnA := pairNodes(t, nodeA, certA, privA, commA, nodeB, certB, privB, commB)
	require.NotNil(t, peerBOnA)

	// Announce a messaging-only "chat" service on both nodes without attaching any store.
	_, err := nodeA.RegisterService("chat", 1, nil)
	require.NoError(t, err)
	_, err = nodeB.RegisterService("chat", 1, nil)
	require.NoError(t, err)

	require.NoError(t, nodeB.SetServiceMsgHandler("chat", func(b []byte) ([]byte, error) {
		return append([]byte("chat-reply:"), b...), nil
	}))
	require.NoError(t, nodeB.SetServiceStreamHandler("chat", func(in, out chan []byte) {
		defer close(out)
		for m := range in {
			out <- append([]byte("chat-stream:"), m...)
		}
	}))

	// Confirm no store entry is attached for "chat" on either node.
	assert.Nil(t, nodeA.services.storeEntry("chat"))
	assert.Nil(t, nodeB.services.storeEntry("chat"))

	// Reconcile service discovery so A discovers B hosts "chat".
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.reconcilePeerStores(ctx, peerBOnA))
	require.Len(t, nodeA.ServiceMembers("chat"), 1)
	assert.Equal(t, nodeB.Id(), nodeA.ServiceMembers("chat")[0].ID)

	// Unary Messaging.Send routed to "chat" works with zero stores attached.
	ch := make(chan *Message, 1)
	nodeA.SendServiceMessage("chat", nodeB.Addr(), ch, []byte("hi"))
	resp := <-ch
	require.NotNil(t, resp)
	require.NoError(t, resp.Error)
	assert.Equal(t, "chat-reply:hi", string(resp.Data))

	// Bidirectional Messaging.Stream routed to "chat" works with zero stores attached.
	inCh := make(chan []byte, 1)
	outCh := make(chan []byte, 1)
	nodeA.OpenServiceStream("chat", nodeB.Addr(), inCh, outCh)
	inCh <- []byte("stream-hi")
	close(inCh)
	got := <-outCh
	assert.Equal(t, "chat-stream:stream-hi", string(got))
}
