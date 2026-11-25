package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eika123/ifrit/core/discovery"
	pb "github.com/eika123/ifrit/protobuf"
	"github.com/eika123/ifrit/reconcile"
	log "github.com/inconshreveable/log15"
	"google.golang.org/grpc"
)

var (
	errNoId         = errors.New("No id present in received certificate")
	errNoData       = errors.New("Gossip data has zero length")
	errNoCaAddr     = errors.New("No ca addr set in config with use_ca enabled")
	errNoEntryAddrs = errors.New("No entry_addrs set in config with use_ca disabled")
)

// ErrAlreadyStarted is returned when attempting to register a gRPC service
// on a Node after Start() has been called (gRPC-Go forbids RegisterService after Serve).
var ErrAlreadyStarted = errors.New("cannot register gRPC service after Node.Start")

type Node struct {
	view *discovery.View
	self *discovery.Peer

	adversary      *AdversarialPolicy
	adversaryMutex sync.RWMutex

	wg       *sync.WaitGroup
	exitChan chan bool

	exitFlag  bool
	exitMutex sync.RWMutex

	// startedChan is closed once Start() has initialized all background workers (gossipLoop, monitorLoop, etc.).
	// This prevents a data race where Stop() could call wg.Wait() concurrently with Start() calling wg.Add(2).
	startedChan chan struct{}
	startCalled bool
	startMutex  sync.Mutex

	viewUpdateTimeout time.Duration

	gossipTimeout      time.Duration
	gossipTimeoutMutex sync.RWMutex

	ringsPingedPerInterval int
	monitorTimeout         time.Duration
	nodeDeadTimeout        float64

	services *serviceRegistry

	reconciliationStrategy string
	dataStoreReconciler    reconcile.StoreReconciler
	dataStoreFP            func() []byte
	dataReconcilerMutex    sync.RWMutex

	certReconciler       reconcile.StoreReconciler
	noteReconciler       reconcile.StoreReconciler
	accReconciler        reconcile.StoreReconciler
	serviceReconciler    reconcile.StoreReconciler
	serviceAccReconciler reconcile.StoreReconciler
	reconcileRegistry    *reconcile.Registry
	defaultNegotiator    reconcile.Negotiator
	reconcileMux         *reconcile.Mux

	peerGate *PeerGate

	syncConfig SyncConfig
	syncCtx    context.Context
	syncCancel context.CancelFunc

	entryAddrs []string

	fd *failureDetector

	comm       commService
	announceFn func(context.Context, string, *pb.AnnounceRequest) (*pb.AnnounceResponse, error)
	cs         cryptoService
	idCatalog  NodeIdentityCatalog

	useViz bool
	viz    *viz
}

type commService interface {
	grpc.ServiceRegistrar
	ClientConn(string) (grpc.ClientConnInterface, error)
	CloseConn(string)
	Addr() string
	Start()
	Stop()
}

type NodeIdentityCatalog interface {
	Certificate() *x509.Certificate
	CaCertificate() *x509.Certificate
	NumRings() uint32
	ContactList() []*x509.Certificate
	Trusted() bool
}

type cryptoService interface {
	Verify([]byte, []byte, []byte, *ecdsa.PublicKey) bool
	Sign([]byte) ([]byte, []byte, error)
}

func NewNode(comm commService, ps pingService, idCatalog NodeIdentityCatalog, cs cryptoService, opts ...Options) (*Node, error) {
	cfg := DefaultOptions()
	if len(opts) > 0 {
		cfg = opts[0].withDefaults()
	}

	viewStores, err := newControlViewStores(cfg.ReconciliationStrategy)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	viewStores.RemovalTimeout = cfg.RemovalTimeout
	viewStores.UpdateInterval = cfg.ViewUpdateInterval

	v, err := discovery.NewView(idCatalog.NumRings(), idCatalog.Certificate(), comm, cs, viewStores)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	perInterval := cfg.PingsPerInterval
	if rings := int(v.NumRings()); perInterval > rings {
		perInterval = rings
	}
	log.Info(fmt.Sprintf("running with %d pings per interval", perInterval))

	n := &Node{
		exitChan:               make(chan bool, 1),
		startedChan:            make(chan struct{}),
		wg:                     &sync.WaitGroup{},
		gossipTimeout:          cfg.GossipInterval,
		monitorTimeout:         cfg.MonitorInterval,
		entryAddrs:             append([]string(nil), cfg.EntryAddrs...),
		ringsPingedPerInterval: perInterval,

		fd:        newFd(ps, cs, cfg.PingLimit),
		idCatalog: idCatalog,
		cs:        cs,
		comm:      comm,
		self:      v.Self(),
		view:      v,

		// NB! consider moving msgHandlers and streamHandlers into serviceStores
		services: newServiceRegistry(),

		reconciliationStrategy: cfg.ReconciliationStrategy,
		peerGate:               NewPeerGate(),
		syncConfig:             cfg.SyncConfig,

		// Visualizer specific
		useViz: cfg.UseViz,
	}

	syncCtx, syncCancel := context.WithCancel(context.Background())
	n.syncCtx = syncCtx
	n.syncCancel = syncCancel

	if n.useViz {
		viz, err := newViz(n, cfg.VizAddr, cfg.VizUpdateInterval, idCatalog.Trusted())
		if err != nil {
			return nil, err
		}
		n.viz = viz
	}

	pb.RegisterFirefliesServer(n.comm, &firefliesRPCServer{node: n})
	if err := n.initControlReconcilers(n.defaultControlReconcilerHooks()); err != nil {
		return nil, err
	}

	ps.SetFingerprintsProvider(n.Fingerprints)

	if n.idCatalog.CaCertificate() != nil {
		for _, c := range n.idCatalog.ContactList() {
			if n.self.Id == string(c.SubjectKeyId) {
				continue
			}
			if err := n.validateCertificate(c); err != nil {
				log.Error("Invalid contact certificate", "err", err)
				continue
			}
			err := n.evalValidCertificate(c)
			if err != nil {
				log.Error(err.Error())
			}
		}

		// We add all our initial contacts to the live view without notes
		// to ensure that we have someone to gossip with at startup.
		for _, p := range n.view.Full() {
			n.view.AddLive(p)
		}
	}

	return n, nil
}

// isStopped safely reports whether teardown has already been initiated on this node.
func (n *Node) isStopped() bool {
	n.exitMutex.RLock()
	defer n.exitMutex.RUnlock()
	return n.exitFlag
}

// isStopping atomically sets exitFlag and closes exitChan on the first call.
// Returns true if the node was already stopping.
func (n *Node) isStopping() bool {
	n.exitMutex.Lock()
	defer n.exitMutex.Unlock()

	if n.exitFlag {
		return true
	}

	n.exitFlag = true
	close(n.exitChan)
	if n.syncCancel != nil {
		n.syncCancel()
	}

	return false
}

func (n *Node) Stop() {
	if n.isStopping() {
		return
	}

	// Concurrency guard: If Start() was invoked in a background goroutine, wait until
	// background workers have completed registration (n.wg.Add(2)) and closed startedChan.
	// This guarantees that n.wg.Wait() below never executes concurrently with n.wg.Add(2).
	n.startMutex.Lock()
	started := n.startCalled
	n.startMutex.Unlock()

	if started {
		<-n.startedChan
	}

	if n.useViz && n.viz != nil {
		n.viz.stop()
	}

	if n.view != nil {
		n.view.Stop()
	}
	if n.fd != nil {
		n.fd.stop()
	}

	if n.wg != nil {
		n.wg.Wait()
	}

	if n.comm != nil {
		n.comm.Stop()
	}
}

// RegisterGRPCService mounts a custom gRPC service on the node's shared mTLS
// gRPC server. Must be called before Start() (returns ErrAlreadyStarted after).
func (n *Node) RegisterGRPCService(desc *grpc.ServiceDesc, impl any) error {
	n.startMutex.Lock()
	defer n.startMutex.Unlock()
	if n.startCalled {
		return ErrAlreadyStarted
	}
	n.comm.RegisterService(desc, impl)
	return nil
}

// ValidatePeerCtx extracts and verifies the mTLS client certificate from an
// incoming gRPC context against the node's identity catalog (CA or self-signed).
func (n *Node) ValidatePeerCtx(ctx context.Context) (*x509.Certificate, error) {
	return n.validateCtx(ctx)
}

func (n *Node) Start() {
	n.startMutex.Lock()
	// If Stop() was already called before Start() began, abort immediately to avoid spawning orphaned goroutines.
	if n.isStopped() {
		n.startMutex.Unlock()
		return
	}
	n.startCalled = true
	n.startMutex.Unlock()

	log.Info("Started Node")

	go n.fd.start()
	go n.comm.Start()
	go n.view.Start()

	n.wg.Add(2)
	go n.gossipLoop()
	go n.monitorLoop()

	if n.useViz {
		n.viz.start()
	}

	// Signal to Stop() that all background workers have completed n.wg registration.
	close(n.startedChan)

	// With no ca we need to contact existing hosts.
	// TODO retry if we fail to contact them?
	if n.idCatalog.CaCertificate() == nil {
		for _, addr := range n.entryAddrs {
			// Fast exit check so we don't attempt network dials if Stop() was requested.
			select {
			case <-n.exitChan:
				log.Info("Exiting node")
				return
			default:
			}
			if err := n.announceToPeer(addr); err != nil {
				log.Error(err.Error(), "addr", addr)
				continue
			}
			if err := n.reconcileBootstrapControl(addr); err != nil {
				log.Error("Bootstrap control reconciliation failed", "addr", addr, "err", err)
			}
		}
	}

	// Block until Stop() is called by the owner/consumer.
	// Note: We deliberately do NOT call n.Stop() here on exit because n.exitChan is ONLY
	// closed by n.Stop(). Calling n.Stop() here would race with the caller's ongoing teardown.
	<-n.exitChan
	log.Info("Exiting node")
}

// //////////  Communication: Messages and Streaming //////////////////////////
func (n *Node) IdToAddr(id []byte) (string, error) {
	peer := n.view.Peer(string(id))
	if peer == nil {
		return "", errors.New("Could not find peer with specified id")
	}

	return peer.Addr, nil
}

/////////////////////////////////////////////////////////

// //////////////////////  Visibility //////////////////////////
func (n *Node) LiveMembers() []string {
	live := n.view.Live()

	ret := make([]string, 0, len(live))

	for _, peer := range n.view.Live() {
		ret = append(ret, peer.Addr)
	}

	return ret
}

func (n *Node) HttpAddr() string {
	return n.self.HttpAddr
}

func (n *Node) Id() string {
	return n.self.Id
}

func (n *Node) Addr() string {
	return n.comm.Addr()
}

///////////////////////////////////////////////////////////////
