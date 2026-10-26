package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
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

	p             protocol
	protocolMutex sync.RWMutex

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

	gossipHandler      processMsg
	gossipHandlerMutex sync.RWMutex

	responseHandler      func([]byte)
	responseHandlerMutex sync.RWMutex

	externalGossip      []byte
	externalGossipMutex sync.RWMutex

	streamHandler      streamMsg
	streamHandlerMutex sync.RWMutex

	accusationSessionFactory      SessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol]
	accusationSessionFactoryMutex sync.RWMutex

	dataReconciler      DataReconciler
	dataReconcilerMutex sync.RWMutex

	dispatcher *workerpool.Dispatcher

	entryAddrs []string

	fd *failureDetector

	comm commService
	cs   cryptoService
	cm   certManager

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
}

type certManager interface {
	Certificate() *x509.Certificate
	CaCertificate() *x509.Certificate
	Priv() *ecdsa.PrivateKey // Added for Saving private-key.
	ContactList() []*x509.Certificate
	NumRings() uint32
	Trusted() bool
	SavePrivateKey() error
	SaveCertificate() error
}

type cryptoService interface {
	Verify([]byte, []byte, []byte, *ecdsa.PublicKey) bool
	Sign([]byte) ([]byte, []byte, error)
}

type protocol interface {
	Monitor(n *Node)
	Gossip(n *Node)
	Rebuttal(n *Node)
}

func (n *Node) gossipLoop() {
	defer n.wg.Done()

	for {
		select {
		case <-n.exitChan:
			log.Info("Exiting gossiping")
			return
		case <-time.After(n.getGossipTimeout()):
			n.protocol().Gossip(n)
		}
	}
}

func (n *Node) monitorLoop() {
	defer n.wg.Done()

	for {
		select {
		case <-n.exitChan:
			log.Info("Stopping monitoring")
			return
		case <-time.After(n.monitorTimeout):
			n.protocol().Monitor(n)
		}
	}
}

func NewNode(comm commService, ps pingService, cm certManager, cs cryptoService) (*Node, error) {
	var perInterval int

	v, err := discovery.NewView(cm.NumRings(), cm.Certificate(), comm, cs)
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

	n := &Node{
		exitChan:       make(chan bool, 1),
		startedChan:    make(chan struct{}),
		wg:             &sync.WaitGroup{},
		gossipTimeout:  time.Second * time.Duration(viper.GetInt32("gossip_interval")),
		monitorTimeout: time.Second * time.Duration(viper.GetInt32("monitor_interval")),
		dispatcher: workerpool.NewDispatcher(uint32(viper.
			GetInt32("max_concurrent_messages"))),
		entryAddrs:             viper.GetStringSlice("entry_addrs"),
		p:                      correct{},
		ringsPingedPerInterval: perInterval,

		fd:   newFd(ps, cs, uint32(viper.GetInt32("ping_limit"))),
		cm:   cm,
		cs:   cs,
		comm: comm,
		self: v.Self(),
		view: v,

		// Visualizer specific
		useViz: viper.GetBool("use_viz"),
	}

	if n.useViz {
		interval := time.Second * time.Duration(viper.GetInt32("viz_update_interval"))
		viz, err := newViz(n, viper.GetString("viz_addr"), interval, cm.Trusted())
		if err != nil {
			return nil, err
		}
		n.viz = viz
	}

	n.comm.Register(n)

	if fpSetter, ok := ps.(interface{ SetFingerprintDataProvider(func() []byte) }); ok {
		fpSetter.SetFingerprintDataProvider(n.self.FingerprintData)
	} else if fpSetter, ok := ps.(interface{ SetFingerprintProvider(func() []byte) }); ok {
		fpSetter.SetFingerprintProvider(n.self.Fingerprint)
	}

	if fpAccSetter, ok := ps.(interface{ SetFingerprintAccusationsProvider(func() []byte) }); ok {
		fpAccSetter.SetFingerprintAccusationsProvider(n.AccusationFingerprintBytes)
	}

	if fpViewSetter, ok := ps.(interface{ SetFingerprintViewProvider(func() []byte) }); ok {
		fpViewSetter.SetFingerprintViewProvider(n.ViewFingerprintBytes)
	}

	if n.cm.CaCertificate() != nil {
		for _, c := range n.cm.ContactList() {
			if n.self.Id == string(c.SubjectKeyId) {
				continue
			}
			err := n.evalCertificate(c)
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

func (n *Node) SendMessage(dest string, ch chan *Message, data []byte) {
	msg := &pb.Msg{
		Content: data,
	}

	n.dispatcher.Submit(func() {
		n.sendMsg(dest, ch, msg)
	})
}

func (n *Node) Sign(content []byte) ([]byte, []byte, error) {
	r, s, err := n.cs.Sign(content)
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil
}

func (n *Node) Verify(r, s, content []byte, id string) bool {
	p := n.view.Peer(id)
	if p == nil {
		return false
	}

	return n.cs.Verify(content, r, s, p.PublicKey())
}

func (n *Node) SetFingerprint(fp []byte) {
	n.self.SetFingerprint(fp)
}

func (n *Node) Fingerprint() []byte {
	return n.self.Fingerprint()
}

func (n *Node) SetFingerprintData(fp []byte) {
	n.self.SetFingerprintData(fp)
}

func (n *Node) FingerprintData() []byte {
	if selfFp := n.self.FingerprintData(); len(selfFp) > 0 {
		return selfFp
	}
	n.dataReconcilerMutex.RLock()
	defer n.dataReconcilerMutex.RUnlock()
	if n.dataReconciler != nil {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(n.dataReconciler.Fingerprint()))
		return buf[:]
	}
	return nil
}

func (n *Node) AccusationFingerprint() revIdxStore.DigestSymbol {
	return n.view.AccusationFingerprint()
}

// TODO: Check this big endian stuff
func (n *Node) AccusationFingerprintBytes() []byte {
	fp := n.view.AccusationFingerprint()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

func (n *Node) ViewFingerprint() revIdxStore.DigestSymbol {
	fp, err := n.view.Fingerprint()
	if err != nil {
		log.Error("Failed to get view fingerprint", "err", err)
		return 0
	}
	return fp
}

func (n *Node) ViewFingerprintBytes() []byte {
	fp, err := n.view.Fingerprint()
	if err != nil {
		log.Error("Failed to get view fingerprint", "err", err)
		return nil
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(fp))
	return buf[:]
}

// IsDivergent checks if peer p's reported fingerprints differ from local node's current fingerprints.
func (n *Node) IsDivergent(p *discovery.Peer) bool {
	dataDiff, accDiff, viewDiff := n.DivergentSets(p)
	return dataDiff || accDiff || viewDiff
}

// DivergentSets returns boolean indicators for which specific sets differ between peer p and the local node.
func (n *Node) DivergentSets(p *discovery.Peer) (dataDiff, accDiff, viewDiff bool) {
	if p == nil {
		return false, false, false
	}
	dataDiff = !bytes.Equal(p.FingerprintData(), n.FingerprintData())
	accDiff = !bytes.Equal(p.FingerprintAccusations(), n.AccusationFingerprintBytes())
	viewDiff = !bytes.Equal(p.FingerprintView(), n.ViewFingerprintBytes())
	return
}

// AccusationDigests returns the digest symbols of all local accusations.
func (n *Node) AccusationDigests() []revIdxStore.DigestSymbol {
	return n.view.AccusationStore().DigestsCopy()
}

// AccusationDigestsUint64 returns the 64-bit uint64 digests of all local accusations for wire serialization.
func (n *Node) AccusationDigestsUint64() []uint64 {
	return revIdxStore.AsUint64Slice(n.AccusationDigests())
}

// NoteDigests returns the digest symbols of all local notes in the version vector.
func (n *Node) NoteDigests() []revIdxStore.DigestSymbol {
	digests, err := n.view.NoteDigests()
	if err != nil {
		log.Error("Failed to get note digests", "err", err)
		return nil
	}
	return digests
}

// NoteDigestsUint64 returns the 64-bit uint64 digests of all local notes in the version vector for wire serialization.
func (n *Node) NoteDigestsUint64() []uint64 {
	return revIdxStore.AsUint64Slice(n.NoteDigests())
}

// DataDigests returns the local digest symbols, or nil if no reconciler is registered.
func (n *Node) DataDigests() []revIdxStore.DigestSymbol {
	n.dataReconcilerMutex.RLock()
	defer n.dataReconcilerMutex.RUnlock()
	if n.dataReconciler != nil {
		return n.dataReconciler.Digests()
	}
	return nil
}

// DataDigestsUint64 returns the local 64-bit uint64 data digests, or nil if no provider is registered.
func (n *Node) DataDigestsUint64() []uint64 {
	return revIdxStore.AsUint64Slice(n.DataDigests())
}

// SetDataReconciler registers a DataReconciler on the node.
func (n *Node) SetDataReconciler(r DataReconciler) {
	n.dataReconcilerMutex.Lock()
	defer n.dataReconcilerMutex.Unlock()
	n.dataReconciler = r
}

// GetDataReconciler returns the currently registered DataReconciler, or nil.
func (n *Node) GetDataReconciler() DataReconciler {
	n.dataReconcilerMutex.RLock()
	defer n.dataReconcilerMutex.RUnlock()
	return n.dataReconciler
}

// RegisterDataStore registers an application's typed data store on the node,
// wrapping it into a DataReconciler using the default or configured session factory.
func RegisterDataStore[T any](n *Node, store ReverseIndexStore[T, revIdxStore.DigestSymbol]) {
	if n == nil {
		return
	}
	n.SetDataReconciler(NewTypedDataReconciler(store, nil))
}

// SetAccusationSessionFactory allows the Fireflies layer (e.g. tests or internal protocol configuration)
// to specify a custom reconciliation session factory (e.g. RIBLTSessionFactory or NaiveSessionFactory).
func (n *Node) SetAccusationSessionFactory(f SessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol]) {
	n.accusationSessionFactoryMutex.Lock()
	defer n.accusationSessionFactoryMutex.Unlock()
	n.accusationSessionFactory = f
}

func (n *Node) getAccusationSessionFactory() SessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol] {
	n.accusationSessionFactoryMutex.RLock()
	defer n.accusationSessionFactoryMutex.RUnlock()
	return n.accusationSessionFactory
}

func (n *Node) IdToAddr(id []byte) (string, error) {
	p := n.view.Peer(string(id))
	if p == nil {
		return "", errors.New("Could not find peer with specified id")
	}

	return p.Addr, nil
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

func (n *Node) LiveMembers() []string {
	live := n.view.Live()

	ret := make([]string, 0, len(live))

	for _, p := range n.view.Live() {
		ret = append(ret, p.Addr)
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

	msg := n.collectGossipContent()

	// With no ca we need to contact existing hosts.
	// TODO retry if we fail to contact them?
	if n.cm.CaCertificate() == nil {
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
		}
	}

	// Block until Stop() is called by the owner/consumer.
	// Note: We deliberately do NOT call n.Stop() here on exit because n.exitChan is ONLY
	// closed by n.Stop(). Calling n.Stop() here would race with the caller's ongoing teardown.
	<-n.exitChan
	log.Info("Exiting node")
}

func (n *Node) SavePrivateKey() error {
	return n.cm.SavePrivateKey()
}

func (n *Node) SaveCertificate() error {
	return n.cm.SaveCertificate()
}
