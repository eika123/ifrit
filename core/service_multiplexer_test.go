package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/digestmaps"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestControlReconcilers_DataErrorDoesNotBlockControlOrServiceFingerprints(t *testing.T) {
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

func TestServiceMultiplexer_SparseStoreConvergenceAndUnregistration(t *testing.T) {
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

	// Attach multiple typed reconcilable stores to "dht" (A, C: "items" and "meta")
	// and a single store to "pubsub" (A, B: "topics").
	dhtStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	dhtStoreC, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	require.NoError(t, RegisterServiceStore(nodeA, "dht", "items", dhtStoreA, nil))
	require.NoError(t, RegisterServiceStore(nodeC, "dht", "items", dhtStoreC, nil))

	dhtMetaA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	dhtMetaC, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	require.NoError(t, RegisterServiceStore(nodeA, "dht", "meta", dhtMetaA, nil))
	require.NoError(t, RegisterServiceStore(nodeC, "dht", "meta", dhtMetaC, nil))

	pubsubStoreA, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	pubsubStoreB, err := ratelessIBLT.NewReconcilableStore(digestmaps.MustDefaultHasher[string]())
	require.NoError(t, err)
	require.NoError(t, RegisterServiceStore(nodeA, "pubsub", "topics", pubsubStoreA, nil))
	require.NoError(t, RegisterServiceStore(nodeB, "pubsub", "topics", pubsubStoreB, nil))

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

	// Insert into dhtStoreA, dhtMetaC, and pubsubStoreB; background reconcileServiceStores must
	// converge each named store across its own RingSuperOverlay without cross-talk.
	dhtStoreA.Insert("dht-record-1")
	dhtStoreC.Insert("dht-record-2")
	dhtMetaC.Insert("dht-meta-1")
	pubsubStoreB.Insert("pubsub-topic-1")

	nodeA.reconcileServiceStores()

	assert.Equal(t, dhtStoreA.Fingerprint(), dhtStoreC.Fingerprint(), "sparse dht/items stores must converge directly between A and C")
	assert.Equal(t, 2, dhtStoreA.Size())
	assert.Equal(t, 2, dhtStoreC.Size())

	assert.Equal(t, dhtMetaA.Fingerprint(), dhtMetaC.Fingerprint(), "sparse dht/meta stores must converge independently between A and C")
	assert.Equal(t, 1, dhtMetaA.Size())
	assert.Equal(t, 1, dhtMetaC.Size())

	assert.Equal(t, pubsubStoreA.Fingerprint(), pubsubStoreB.Fingerprint(), "pubsub stores must converge between A and B")
	assert.Equal(t, 1, pubsubStoreA.Size())
	assert.Equal(t, 1, pubsubStoreB.Size())

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

	// Verify reconcile.Mux rejected all unregistered service stores ("items" and "meta") after UnregisterService.
	_, err = nodeA.services.storeEntry("dht", "items").rec.ReconcileWithPeer(ctx, nodeC.Addr())
	require.Error(t, err, fmt.Sprintf("reconciling unregistered dht/items store on C should fail (got %v)", err))
	_, err = nodeA.services.storeEntry("dht", "meta").rec.ReconcileWithPeer(ctx, nodeC.Addr())
	require.Error(t, err, fmt.Sprintf("reconciling unregistered dht/meta store on C should fail (got %v)", err))
}

func TestServiceMultiplexer_CustomGRPCServiceAndPreStartGuard(t *testing.T) {
	caCert, caPriv := genTestCA(t)

	nodeA, commA, _, _ := createTestNodeWithComm(t, caCert, caPriv)
	defer nodeA.Stop()
	defer commA.Stop()

	privC, err := genTLSKeys()
	require.NoError(t, err)
	certC := genNodeCertSignedByCA(t, privC, caCert, caPriv)
	lisC, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	commC, err := comm.NewComm(certC, caCert, privC, lisC)
	require.NoError(t, err)
	defer commC.Stop()

	nodeC, err := NewNode(commC, &pingStub{}, &cmStub{cert: certC, caCert: caCert}, &cryptoStub{priv: privC})
	require.NoError(t, err)
	defer nodeC.Stop()

	type customEchoServer interface {
		Echo(context.Context, *pb.Ping) (*pb.Ping, error)
	}
	echoImpl := customEchoFunc(func(ctx context.Context, req *pb.Ping) (*pb.Ping, error) {
		cert, err := nodeC.ValidatePeerCtx(ctx)
		if err != nil {
			return nil, err
		}
		return &pb.Ping{Nonce: append(append([]byte("echo:"), req.GetNonce()...), []byte(":"+string(cert.SubjectKeyId))...)}, nil
	})
	echoDesc := &grpc.ServiceDesc{
		ServiceName: "custom.Echo",
		HandlerType: (*customEchoServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Echo",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := new(pb.Ping)
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(customEchoServer).Echo(ctx, in)
				},
			},
		},
	}

	require.NoError(t, nodeC.RegisterGRPCService(echoDesc, echoImpl))
	assert.ErrorIs(t, nodeC.RegisterGRPCService(echoDesc, echoImpl), ErrGRPCServiceAlreadyRegistered)
	go nodeC.Start()
	<-nodeC.startedChan

	// Post-Start() registration of a new service must fail cleanly with ErrAlreadyStarted.
	otherDesc := &grpc.ServiceDesc{ServiceName: "custom.Other", HandlerType: (*customEchoServer)(nil)}
	assert.ErrorIs(t, nodeC.RegisterGRPCService(otherDesc, echoImpl), ErrAlreadyStarted)

	// Dial custom.Echo from nodeA using nodeA.ConnProvider() over mTLS.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ccC, err := nodeA.ConnProvider()(ctx, commC.Addr())
	require.NoError(t, err)
	out := new(pb.Ping)
	require.NoError(t, ccC.Invoke(ctx, "/custom.Echo/Echo", &pb.Ping{Nonce: []byte("ping")}, out))
	assert.Equal(t, "echo:ping:"+nodeA.Id(), string(out.GetNonce()))
}

type customEchoFunc func(context.Context, *pb.Ping) (*pb.Ping, error)

func (f customEchoFunc) Echo(ctx context.Context, req *pb.Ping) (*pb.Ping, error) {
	return f(ctx, req)
}
