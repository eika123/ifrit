package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/joonnna/workerpool"
	"github.com/spf13/viper"
)

var (
	errNoId         = errors.New("No id present in received certificate")
	errNoData       = errors.New("Gossip data has zero length")
	errNoCaAddr     = errors.New("No ca addr set in config with use_ca enabled")
	errNoEntryAddrs = errors.New("No entry_addrs set in config with use_ca disabled")
)

type Message struct {
	Data  []byte
	Error error
}

type processMsg func([]byte) ([]byte, error)
type streamMsg func(chan []byte, chan []byte)

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

	msgHandler      processMsg
	msgHandlerMutex sync.RWMutex

	streamHandler      streamMsg
	streamHandlerMutex sync.RWMutex

	reconProtocol      ProtocolDefinition
	reconProtocolMutex sync.RWMutex

	dataReconciler      DataReconciler
	dataReconcilerMutex sync.RWMutex

	sessionManager *PeerSessionManager

	syncConfig      SyncConfig
	syncConfigMutex sync.RWMutex
	syncCtx         context.Context
	syncCancel      context.CancelFunc

	dispatcher *workerpool.Dispatcher

	entryAddrs []string

	fd *failureDetector

	comm      commService
	cs        cryptoService
	idCatalog NodeIdentityCatalog

	useViz bool
	viz    *viz
}

type commService interface {
	Register(pb.GossipServer)
	CloseConn(string)
	Addr() string
	Start()
	Stop()

	Gossip(string, *pb.State) (*pb.StateResponse, error)
	Send(string, *pb.Msg) (*pb.MsgResponse, error)
	StreamMessenger(string, chan []byte, chan []byte) error
	OpenSyncStream(context.Context, string) (pb.Gossip_SyncClient, error)
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

func NewNode(comm commService, ps pingService, idCatalog NodeIdentityCatalog, cs cryptoService) (*Node, error) {
	var perInterval int

	v, err := discovery.NewView(idCatalog.NumRings(), idCatalog.Certificate(), comm, cs)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	num := viper.GetInt("pings_per_interval")
	if num == 0 {
		perInterval = 1
	} else if rings := int(v.NumRings()); num > rings {
		perInterval = rings
	} else {
		perInterval = num
	}
	log.Info(fmt.Sprintf("running with %d pings per interval", perInterval))

	staleTimeout := time.Second * time.Duration(viper.GetInt32("session_timeout"))
	if staleTimeout <= 0 {
		staleTimeout = 30 * time.Second
	}

	strategy := viper.GetString("reconciliation_strategy")
	protoDef := ResolveProtocol(strategy)

	n := &Node{
		exitChan:       make(chan bool, 1),
		startedChan:    make(chan struct{}),
		wg:             &sync.WaitGroup{},
		gossipTimeout:  time.Second * time.Duration(viper.GetInt32("gossip_interval")),
		monitorTimeout: time.Second * time.Duration(viper.GetInt32("monitor_interval")),
		dispatcher: workerpool.NewDispatcher(uint32(viper.
			GetInt32("max_concurrent_messages"))),
		entryAddrs:             viper.GetStringSlice("entry_addrs"),
		ringsPingedPerInterval: perInterval,

		fd:        newFd(ps, cs, uint32(viper.GetInt32("ping_limit"))),
		idCatalog: idCatalog,
		cs:        cs,
		comm:      comm,
		self:      v.Self(),
		view:      v,

		sessionManager: NewPeerSessionManager(staleTimeout),
		reconProtocol:  protoDef,
		syncConfig:     DefaultSyncConfig(),

		// Visualizer specific
		useViz: viper.GetBool("use_viz"),
	}

	syncCtx, syncCancel := context.WithCancel(context.Background())
	n.syncCtx = syncCtx
	n.syncCancel = syncCancel

	if n.useViz {
		interval := time.Second * time.Duration(viper.GetInt32("viz_update_interval"))
		viz, err := newViz(n, viper.GetString("viz_addr"), interval, idCatalog.Trusted())
		if err != nil {
			return nil, err
		}
		n.viz = viz
	}

	n.comm.Register(n)

	if fpSetter, ok := ps.(interface{ SetFingerprintDataProvider(func() []byte) }); ok {
		fpSetter.SetFingerprintDataProvider(n.FingerprintData)
	} else if fpSetter, ok := ps.(interface{ SetFingerprintProvider(func() []byte) }); ok {
		fpSetter.SetFingerprintProvider(n.self.FingerprintData)
	}

	if fpAccSetter, ok := ps.(interface{ SetFingerprintAccusationsProvider(func() []byte) }); ok {
		fpAccSetter.SetFingerprintAccusationsProvider(n.AccusationFingerprintBytes)
	}

	if fpViewSetter, ok := ps.(interface{ SetFingerprintViewProvider(func() []byte) }); ok {
		fpViewSetter.SetFingerprintViewProvider(n.ViewFingerprintBytes)
	}

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

	if n.dispatcher != nil {
		n.dispatcher.Stop()
	}
	if n.wg != nil {
		n.wg.Wait()
	}

	if n.comm != nil {
		n.comm.Stop()
	}
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

	n.dispatcher.Start()

	if n.useViz {
		n.viz.start()
	}

	// Signal to Stop() that all background workers have completed n.wg registration.
	close(n.startedChan)

	// With no ca we need to contact existing hosts.
	// TODO retry if we fail to contact them?
	if n.idCatalog.CaCertificate() == nil {
		msg := &pb.State{}
		if selfNote := n.view.SelfNote(); selfNote != nil {
			msg.OwnNote = selfNote.ToPbMsg()
		}

		for _, addr := range n.entryAddrs {
			// Fast exit check so we don't attempt network dials if Stop() was requested.
			select {
			case <-n.exitChan:
				log.Info("Exiting node")
				return
			default:
			}
			reply, err := n.comm.Gossip(addr, msg)
			if err != nil {
				log.Error(err.Error(), "addr", addr)
				continue
			}

			n.mergeCertificates(reply.GetCertificates())
			n.mergeNotes(reply.GetNotes())
			n.mergeAccusations(reply.GetAccusations())

			deltas := ExtractReconcileDeltas(reply)
			if deltas.HasDeltas() {
				if err := n.syncBootstrap(addr, deltas); err != nil {
					log.Error("Bootstrap sync stream failed", "addr", addr, "err", err)
				}
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
func (n *Node) SendMessage(dest string, ch chan *Message, data []byte) {
	msg := &pb.Msg{
		Content: data,
	}

	n.dispatcher.Submit(func() {
		n.sendMsg(dest, ch, msg)
	})
}

func (n *Node) IdToAddr(id []byte) (string, error) {
	peer := n.view.Peer(string(id))
	if peer == nil {
		return "", errors.New("Could not find peer with specified id")
	}

	return peer.Addr, nil
}

func (n *Node) SendMessages(dest []string, ch chan *Message, data []byte) {
	msg := &pb.Msg{
		Content: data,
	}

	for _, addr := range dest {
		a := addr
		n.dispatcher.Submit(func() {
			n.sendMsg(a, ch, msg)
		})
	}
}

func (n *Node) OpenStream(dest string, input, reply chan []byte) {
	n.dispatcher.Submit(func() {
		n.openStream(dest, input, reply)
	})
}

func (n *Node) SendStream(ch chan<- []byte, data []byte) {
	ch <- data
}

func (n *Node) openStream(dest string, input, reply chan []byte) {
	if err := n.comm.StreamMessenger(dest, input, reply); err != nil {
		log.Error(err.Error())
	}
}

func (n *Node) sendMsg(dest string, ch chan *Message, msg *pb.Msg) {
	//defer close(ch)
	reply, err := n.comm.Send(dest, msg)
	if err != nil {
		log.Error(err.Error())
		ch <- nil
		//	return
	}

	if reply.GetError() == "" {
		err = nil
	} else {
		err = errors.New(reply.GetError())
	}

	ch <- &Message{Data: reply.GetContent(), Error: err}
}

// Expose so that client can set new handler directly
func (n *Node) SetMsgHandler(newHandler processMsg) {
	n.msgHandlerMutex.Lock()
	defer n.msgHandlerMutex.Unlock()

	n.msgHandler = newHandler
}

func (n *Node) getMsgHandler() processMsg {
	n.msgHandlerMutex.RLock()
	defer n.msgHandlerMutex.RUnlock()

	return n.msgHandler
}

// Expose so that client can set new handler directly
func (n *Node) SetStreamHandler(newHandler streamMsg) {
	n.streamHandlerMutex.Lock()
	defer n.streamHandlerMutex.Unlock()

	n.streamHandler = newHandler
}

func (n *Node) getStreamHandler() streamMsg {
	n.streamHandlerMutex.RLock()
	defer n.streamHandlerMutex.RUnlock()

	return n.streamHandler
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
