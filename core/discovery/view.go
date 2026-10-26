package discovery

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"math/bits"
	"sync"
	"time"

	gpb "github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
	proto "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/joonnna/ifrit/versionvector"
	"github.com/spf13/viper"
)

var (
	errInvalidNeighbours  = errors.New("Neighbours are nil ?!")
	errPeerAlreadyExists  = errors.New("Peer id already exists in the full view")
	errAlreadyDeactivated = errors.New("Ring was already deactivated")
	errZeroDeactivate     = errors.New("No ring can be deactivated, maxbyz is 0")
	errNoNote             = errors.New("Note was nil.")
	errAccusedIsNil        = errors.New("Accused was nil.")
	errObsIsNil            = errors.New("Observer was nil")
	errWrongNote           = errors.New("Note does not belong to accused.")
	ErrNotesNotInitialized = errors.New("Notes version vector is not initialized")
)

type View struct {
	viewStore revIdxStore.ReverseIndexStore[*Peer, revIdxStore.DigestSymbol]
	viewMutex sync.RWMutex

	liveStore revIdxStore.ReverseIndexStore[*Peer, revIdxStore.DigestSymbol]

	accusationStore revIdxStore.ReverseIndexStore[*Accusation, revIdxStore.DigestSymbol]

	notes versionvector.VersionVector[*Note, revIdxStore.DigestSymbol]

	// maps Peer.Id to a timeout. Cannot use ReverseIndexStore because
	// timeout is not a boolean group
	timeoutMap   map[string]*timeout
	timeoutMutex sync.RWMutex

	rings *rings

	currGossipRing  uint32
	currMonitorRing uint32

	// max number of corrupt monitors this node can tolerate,
	// e.g. t in k=2t+1, where k is the number of rings,
	// so maxByz = floor((rings - 1)/2). See fireflies paper p.7.
	maxByz           uint32
	deactivatedRings uint32

	removalTimeout float64
	updateTimeout  time.Duration

	self *Peer

	cm connectionManager
	s  signer

	exitChan chan bool
}

type connectionManager interface {
	CloseConn(addr string)
}

// Should return a signature consisting of two components.
// For ecdsa (Elliptic Curve Digital Signature Algorithm) this is r and s.
// For ecdsa with elliptic curves using a generator G, a nonce k is chosen and a point (x, y) is generated as kG.
//
// Example for ECDSA:
// The value of r is the x-coordinate of (x, y) modulo n (where n is the order of the curve).
// The value of s binds the hash of the data to the nonce, the private key, the nonce and r.
// Together, (r, s) mathematically prove that whoever produced the signature possesses the corresponding private key for that message hash, without revealing the private key.
type signer interface {
	Sign([]byte) ([]byte, []byte, error)
}

// NewView initializes and returns a new View instance, configuring the local peer,
// multi-ring overlay topology, timeout settings, and signing an initial local note (epoch 1).
//
// Prerequisites / Expected Services:
//   - Requires initialized and valid certificate manager / certificates (cert).
//   - Requires a cryptoService / signer capable of signing protobuf Notes.
//   - Requires a connectionManager / commService to manage connection lifecycles.
//   - Viper configuration must be loaded (keys: "removal_timeout", "view_update_interval").
func NewView(numRings uint32, cert *x509.Certificate, cm connectionManager, s signer) (*View, error) {
	var i, mask uint32

	// max tolerable corrupt nodes, i.e t in k=2t+1, where t is the max number of corrupt nodes.
	var maxByz uint32
	if numRings > 1 {
		maxByz = (numRings - 1) / 2
	}

	self, err := newPeer(cert, numRings)
	if err != nil {
		return nil, err
	}

	rings, err := createRings(self, numRings)
	if err != nil {
		return nil, err
	}

	removalTimeout := viper.GetFloat64("removal_timeout")
	if removalTimeout <= 0 {
		removalTimeout = 60.0
	}

	updateInterval := viper.GetInt32("view_update_interval")
	if updateInterval <= 0 {
		updateInterval = 10
	}

	peerHasher := func(p *Peer) revIdxStore.DigestSymbol {
		h := fnv.New64a()
		h.Write([]byte(p.Id))
		return revIdxStore.DigestSymbol(h.Sum64())
	}

	viewStore, err := revIdxStore.NewDigestSet(peerHasher)
	if err != nil {
		return nil, err
	}

	liveStore, err := revIdxStore.NewDigestSet(peerHasher)
	if err != nil {
		return nil, err
	}

	accHasher := func(a *Accusation) revIdxStore.DigestSymbol {
		h := fnv.New64a()
		h.Write([]byte(a.accused))
		h.Write([]byte(a.accuser))
		var buf [12]byte
		binary.BigEndian.PutUint32(buf[0:4], a.ringNum)
		binary.BigEndian.PutUint64(buf[4:12], a.epoch)
		h.Write(buf[:])
		return revIdxStore.DigestSymbol(h.Sum64())
	}

	accusationStore, err := revIdxStore.NewDigestSet(accHasher)
	if err != nil {
		return nil, err
	}

	noteKeyFunc := func(n *Note) revIdxStore.DigestSymbol {
		h := fnv.New64a()
		h.Write([]byte(n.id))
		return revIdxStore.DigestSymbol(h.Sum64())
	}

	noteHasher := func(key revIdxStore.DigestSymbol, n *Note, version uint64) revIdxStore.DigestSymbol {
		h := fnv.New64a()
		var buf [20]byte
		binary.BigEndian.PutUint64(buf[0:8], uint64(key))
		binary.BigEndian.PutUint32(buf[8:12], n.mask)
		binary.BigEndian.PutUint64(buf[12:20], version)
		h.Write(buf[:])
		return revIdxStore.DigestSymbol(h.Sum64())
	}

	notesVV := versionvector.NewVersionVector(noteKeyFunc, noteHasher)

	v := &View{
		rings:           rings,
		viewStore:       viewStore,
		liveStore:       liveStore,
		accusationStore: accusationStore,
		notes:           notesVV,
		timeoutMap:      make(map[string]*timeout),
		maxByz:          maxByz,
		currGossipRing:  1,
		currMonitorRing: 1,
		self:            self,
		cm:              cm,
		exitChan:        make(chan bool, 1),
		s:               s,

		removalTimeout: removalTimeout,
		updateTimeout:  time.Second * time.Duration(updateInterval),
	}

	for i = 0; i < numRings; i++ {
		mask = setBit(mask, i)
	}

	localNote := &Note{
		epoch: 1,
		mask:  mask,
		id:    self.Id,
	}

	err = v.signLocalNote(localNote)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// Start begins the periodic timeout checking routine, which monitors accused peers
// and evicts them from the live view and rings when their suspicion timeout expires.
//
// Prerequisites / Expected Services:
//   - Typically spawned as a background goroutine during node startup (e.g. Node.Start).
//   - The connectionManager must be active to handle connection closures on evicted peers.
//   - Accusations must be continuously populated into View by gossip / failure detection services.
func (v *View) Start() {
	for {
		select {
		case <-v.exitChan:
			log.Info("Stopping view update")
			return
		case <-time.After(v.updateTimeout):
			v.checkTimeouts()
		}
	}
}

// Stop signals the timeout checker loop started in Start to terminate.
//
// Prerequisites / Expected Services:
//   - Called during node teardown (e.g. Node.Stop). Start must have been called, or exitChan will simply close.
func (v *View) Stop() {
	close(v.exitChan)
}

// NumRings returns the total number of rings configured in the view topology.
//
// Prerequisites / Expected Services:
//   - View must be initialized via NewView.
func (v *View) NumRings() uint32 {
	return v.rings.numRings
}

// Self returns the local node's Peer representation.
//
// Prerequisites / Expected Services:
//   - View must be initialized via NewView with valid local peer certificate and identity.
func (v *View) Self() *Peer {
	return v.self
}

// hashId computes the deterministic 64-bit digest for a peer ID string.
func (v *View) hashId(id string) revIdxStore.DigestSymbol {
	h := fnv.New64a()
	h.Write([]byte(id))
	return revIdxStore.DigestSymbol(h.Sum64())
}

// Peer returns the Peer with the given ID from the full view, or nil if not present.
func (v *View) Peer(id string) *Peer {
	if p, found := v.viewStore.Contains(&Peer{Id: id}); found && p.Id == id {
		return p
	}
	return nil
}

// Full returns a slice of all known peers in the full view.
func (v *View) Full() []*Peer {
	return v.viewStore.Elements()
}

// Exists reports whether a peer with the specified ID exists in the full view.
func (v *View) Exists(id string) bool {
	return v.Peer(id) != nil
}

// Live returns a slice of all currently active/live peers.
//
// Prerequisites / Expected Services:
//   - Peers must have been inserted into the live view (e.g. initial contacts or validated gossip notes).
//   - Used by application services, failure detectors, or visualizers to query active cluster membership.
func (v *View) Live() []*Peer {
	return v.liveStore.Elements()
}

// AddFull registers a new peer in the full view map using their ID and certificate.
// Returns an error if the peer already exists or if peer initialization fails.
//
// Prerequisites / Expected Services:
//   - Certificate validation (CA validation, TLS verification) should be performed before calling.
//   - Called during gossip/state exchange when discovering previously unknown certificates.
func (v *View) AddFull(id string, cert *x509.Certificate) error {
	v.viewMutex.Lock()
	defer v.viewMutex.Unlock()

	if p, found := v.viewStore.Contains(&Peer{Id: id}); found && p.Id == id {
		log.Error("Tried to add peer twice to full view")
		return errPeerAlreadyExists
	}

	p, err := newPeer(cert, v.rings.numRings)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	v.viewStore.AddElement(p)

	return nil
}

// Fingerprint returns the commutative XOR fingerprint of all active peer notes in the view (including self).
// Returns ErrNotesNotInitialized if the underlying VersionVector has not been initialized.
func (v *View) Fingerprint() (revIdxStore.DigestSymbol, error) {
	if v.notes == nil {
		return 0, ErrNotesNotInitialized
	}
	return v.notes.Fingerprint(), nil
}

// Notes returns the underlying VersionVector backing peer notes, or ErrNotesNotInitialized if uninitialized.
func (v *View) Notes() (versionvector.VersionVector[*Note, revIdxStore.DigestSymbol], error) {
	if v.notes == nil {
		return nil, ErrNotesNotInitialized
	}
	return v.notes, nil
}

// AddNote updates or applies a verified note to both the peer and the view's monotonic Note version vector.
// Returns ErrNotesNotInitialized if the underlying VersionVector has not been initialized.
func (v *View) AddNote(p *Peer, mask uint32, epoch uint64, r, s []byte) (bool, error) {
	if v.notes == nil {
		return false, ErrNotesNotInitialized
	}
	if p == nil {
		return false, errors.New("peer is nil")
	}
	p.AddNote(mask, epoch, r, s)
	n := p.Note()
	if n == nil {
		return false, errNoNote
	}
	return v.notes.AddItem(n, epoch), nil
}

// ViewStore returns the underlying ReverseIndexStore backing the full view.
func (v *View) ViewStore() revIdxStore.ReverseIndexStore[*Peer, revIdxStore.DigestSymbol] {
	return v.viewStore
}

// LiveStore returns the underlying ReverseIndexStore backing the live view.
func (v *View) LiveStore() revIdxStore.ReverseIndexStore[*Peer, revIdxStore.DigestSymbol] {
	return v.liveStore
}

// LiveSubsetOfView reports whether every peer in liveStore is also present in viewStore.
// This enforces the invariant that live members are always a subset of admitted members.
func (v *View) LiveSubsetOfView() bool {
	for _, p := range v.liveStore.Elements() {
		if !v.Exists(p.Id) {
			return false
		}
	}
	return true
}

// MyNeighbours returns all distinct neighbours (predecessors and successors) across all active rings.
//
// Prerequisites / Expected Services:
//   - Used by gossip protocols and failure detectors to discover which nodes to monitor/probe.
func (v *View) MyNeighbours() []*Peer {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	return v.rings.allMyNeighbours()
}

// GossipPartners returns the ring neighbours for the current gossip ring and
// advances the gossip ring index round-robin for the next call.
//
// Prerequisites / Expected Services:
//   - Expected to be called by the periodic gossip loop (Node.gossipLoop) on each gossip round.
func (v *View) GossipPartners() []*Peer {
	v.viewMutex.Lock()
	defer v.viewMutex.Unlock()
	defer v.incrementGossipRing()

	return v.rings.myRingNeighbours(v.currGossipRing)
}

// MonitorTarget returns the successor peer to monitor on the current monitoring ring,
// along with the ring number, and advances the monitor ring index round-robin.
//
// Prerequisites / Expected Services:
//   - Expected to be called by the periodic failure detector / monitoring loop (Node.monitorLoop).
//   - The failure detector service (PingService / commService) will probe the returned peer.
func (v *View) MonitorTarget() (*Peer, uint32) {
	v.viewMutex.Lock()
	defer v.viewMutex.Unlock()

	ringNum := v.currMonitorRing
	defer v.incrementMonitorRing()

	return v.rings.myRingSuccessor(v.currMonitorRing), ringNum
}

// AddLive inserts a peer into the live store and places them into the ring structures,
// closing connections to any peers that are no longer direct ring neighbours.
//
// Prerequisites / Expected Services:
//   - Peer must have been validated (valid certificate and fresh signed Note) before adding to live view.
//   - connectionManager (commService) must be initialized to close connections to displaced ring neighbours.
func (v *View) AddLive(p *Peer) {
	v.viewMutex.Lock()

	if existing, found := v.liveStore.Contains(p); found && existing.Id == p.Id {
		v.viewMutex.Unlock()
		log.Error("Tried to add peer twice to live store", "addr", p.Addr)
		return
	}

	v.liveStore.AddElement(p)

	old := v.rings.add(p)
	v.viewMutex.Unlock()

	for _, addr := range old {
		v.cm.CloseConn(addr)
	}
}

// MyRingNeighbours returns the successor and predecessor peers for the local node on a specific ring.
//
// Prerequisites / Expected Services:
//   - Ring number must be in range [1, numRings].
//   - Used during accusation validation to verify monitoring relationships.
func (v *View) MyRingNeighbours(ringNum uint32) (*Peer, *Peer) {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	return v.rings.myRingSuccessor(ringNum), v.rings.myRingPredecessor(ringNum)
}

// RemoveLive removes a peer from the live store and ring structures, closing any active connection to them.
//
// Prerequisites / Expected Services:
//   - connectionManager (commService) must be initialized to close the open transport connection to the removed peer.
//   - Called when a suspicion timeout expires (Start / checkTimeouts) or on explicit eviction.
func (v *View) RemoveLive(p *Peer) {
	if p == nil {
		return
	}

	v.viewMutex.Lock()
	peer, ok := v.liveStore.Contains(p)
	if !ok || peer.Id != p.Id {
		v.viewMutex.Unlock()
		log.Debug("Tried to remove non-existing peer from live view.")
		return
	}

	v.liveStore.Remove(peer)
	v.rings.remove(peer)
	v.viewMutex.Unlock()

	v.cm.CloseConn(peer.Addr)

	log.Debug("Removed livePeer", "addr", peer.Addr)
}

// RemoveLiveId removes a peer from the live store by their ID string.
func (v *View) RemoveLiveId(id string) {
	v.RemoveLive(&Peer{Id: id})
}

// StartTimer begins or updates a suspicion timeout timer for an accused peer based on a received accusation.
//
// Prerequisites / Expected Services:
//   - Accusation signature and observer predecessor relationship must be validated by the accusation handler beforehand.
//   - View.Start() background timeout checker must be running to eventually evict timed-out accused peers.
func (v *View) StartTimer(accused *Peer, n *Note, observer *Peer) error {
	v.timeoutMutex.Lock()
	defer v.timeoutMutex.Unlock()

	var newTimeout *timeout

	if accused == nil {
		return errAccusedIsNil
	}

	if n == nil {
		return errNoNote
	}

	if observer == nil {
		return errObsIsNil
	}

	if n.id != accused.Id {
		return errWrongNote
	}

	if t, ok := v.timeoutMap[accused.Id]; ok {
		if t.lastNote.epoch < n.epoch {
			newTimeout = &timeout{
				observer:  observer,
				timeStamp: t.timeStamp,
				lastNote:  n,
				accused:   accused,
			}
		} else {
			return nil
		}
	} else {
		newTimeout = &timeout{
			observer:  observer,
			timeStamp: time.Now(),
			lastNote:  n,
			accused:   accused,
		}
	}

	v.timeoutMap[accused.Id] = newTimeout

	log.Debug("Started timer", "addr", accused.Addr)

	return nil
}

// HasTimer checks whether an active suspicion timer exists for the given peer.
//
// Prerequisites / Expected Services:
//   - Used during gossip and note evaluation to check if an accused peer currently has a pending timeout.
func (v *View) HasTimer(p *Peer) bool {
	if p == nil {
		return false
	}
	v.timeoutMutex.RLock()
	defer v.timeoutMutex.RUnlock()

	_, ok := v.timeoutMap[p.Id]
	return ok
}

// HasTimerId checks whether an active suspicion timer exists for the given peer ID string.
func (v *View) HasTimerId(id string) bool {
	return v.HasTimer(&Peer{Id: id})
}

// DeleteTimeout removes the active suspicion timer for the specified peer.
//
// Prerequisites / Expected Services:
//   - Called when a valid rebuttal Note is received or when a peer is evicted after timeout expiration.
func (v *View) DeleteTimeout(p *Peer) {
	if p == nil {
		return
	}
	v.timeoutMutex.Lock()
	defer v.timeoutMutex.Unlock()

	delete(v.timeoutMap, p.Id)
}

// DeleteTimeoutId removes the active suspicion timer for the specified peer ID string.
func (v *View) DeleteTimeoutId(id string) {
	v.DeleteTimeout(&Peer{Id: id})
}

func (v *View) allTimeouts() []*timeout {
	v.timeoutMutex.RLock()
	defer v.timeoutMutex.RUnlock()

	ret := make([]*timeout, 0, len(v.timeoutMap))

	for _, t := range v.timeoutMap {
		ret = append(ret, t)
	}

	return ret
}

func (v *View) checkTimeouts() {
	timeouts := v.allTimeouts()
	if numTimeouts := len(timeouts); numTimeouts > 0 {
		log.Debug("Have timeouts", "amount", numTimeouts)
	}

	for _, t := range timeouts {
		if time.Since(t.timeStamp).Seconds() > v.removalTimeout {
			log.Debug("Timeout expired, removing from live", "addr", t.accused.Addr)
			v.RemoveLive(t.accused)
			v.DeleteTimeout(t.accused)
		}
	}
}

// ShouldRebuttal verifies if an accusation against the local node targets the current epoch.
// If valid, it increments the node's epoch, deactivates the accused ring if allowed, signs a new Note, and returns true.
//
// Prerequisites / Expected Services:
//   - The cryptoService / signer must be active to sign the newly created rebuttal Note.
//   - Invoked by accusation handling logic when an incoming accusation targets the local node.
//   - If true is returned, the caller is expected to trigger an immediate rebuttal broadcast via the protocol service.
func (v *View) ShouldRebuttal(epoch uint64, ringNum uint32) bool {
	v.self.noteMutex.Lock()
	defer v.self.noteMutex.Unlock()

	if eq := v.self.note.Equal(epoch); eq {
		newMask := v.self.note.mask

		mask, err := v.deactivateRing(ringNum)
		if err != nil {
			log.Error(err.Error())
		} else {
			newMask = mask
		}

		newNote := &Note{
			id:    v.self.Id,
			epoch: v.self.note.epoch + 1,
			mask:  newMask,
		}

		err = v.signLocalNote(newNote)
		if err != nil {
			log.Error(err.Error())
		}

		v.self.note = newNote

		return true
	} else {
		return false
	}
}

// ShouldBeNeighbour reports whether a peer with the given ID should be a direct neighbour of the local node on any ring.
//
// Prerequisites / Expected Services:
//   - Used by incoming gossip RPC handlers (e.g. Spread) to verify whether incoming gossip from a sender should be accepted and merged.
func (v *View) ShouldBeNeighbour(id string) bool {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	return v.rings.shouldBeMyNeighbour(id)
}

// FindNeighbours returns all neighbours of the given peer ID across all rings.
//
// Prerequisites / Expected Services:
//   - Used during peer placement checks and diagnostic/visualizer services.
func (v *View) FindNeighbours(id string) []*Peer {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	return v.rings.findNeighbours(id)
}

// ValidAccuser checks whether the accuser peer is the valid predecessor of the accused peer on the specified ring.
//
// Prerequisites / Expected Services:
//   - Used by accusation validation handlers (Node.evalAccusation) to verify accusation legitimacy before accepting.
func (v *View) ValidAccuser(accused, accuser *Peer, ringNum uint32) bool {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	return v.rings.isPredecessor(accused, accuser, ringNum)
}

// IsAlive checks whether a peer with the given ID or peer object currently exists in the live store.
// Performs a collision check comparing the stored peer's ID with the provided peer's ID.
func (v *View) IsAlive(peer *Peer) bool {
	if peer == nil {
		return false
	}
	p, found := v.liveStore.Contains(peer)
	return found && p.Id == peer.Id
}

// IsAliveId checks whether a peer with the given ID string currently exists in the live store.
func (v *View) IsAliveId(id string) bool {
	return v.IsAlive(&Peer{Id: id})
}

func (v *View) incrementGossipRing() {
	v.currGossipRing = ((v.currGossipRing + 1) % (v.rings.numRings + 1))
	if v.currGossipRing == 0 {
		v.currGossipRing = 1
	}
}

func (v *View) incrementMonitorRing() {
	v.currMonitorRing = ((v.currMonitorRing + 1) % (v.rings.numRings + 1))
	if v.currMonitorRing == 0 {
		v.currMonitorRing = 1
	}
}

func (v *View) selfNote() *proto.Note {
	v.self.noteMutex.RLock()
	defer v.self.noteMutex.RUnlock()

	return v.self.note.ToPbMsg()
}

// State returns a protobuf State message containing the local node's latest note
// and the note epoch numbers of all known peers in the full view.
//
// Prerequisites / Expected Services:
//   - Used by the gossip service to prepare the outgoing State digest for periodic gossip exchange.
func (v *View) State() *proto.State {
	ownNote := v.selfNote()

	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	ret := &proto.State{
		ExistingHosts: make(map[string]uint64),
		OwnNote:       ownNote,
	}

	for _, p := range v.viewStore.Elements() {
		id := hex.EncodeToString([]byte(p.Id))
		if note := p.Note(); note != nil {
			ret.ExistingHosts[id] = note.epoch
		} else {
			ret.ExistingHosts[id] = 0
		}
	}

	return ret
}

// ExistingHostsMap returns a map of hex-encoded peer IDs to their latest known note epoch.
func (v *View) ExistingHostsMap() map[string]uint64 {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	hosts := make(map[string]uint64, v.viewStore.Size())
	for _, p := range v.viewStore.Elements() {
		id := hex.EncodeToString([]byte(p.Id))
		if note := p.Note(); note != nil {
			hosts[id] = note.epoch
		} else {
			hosts[id] = 0
		}
	}
	return hosts
}

// ValidMask checks whether a ring bitmask does not deactivate more rings than allowed by Byzantine fault tolerance limits.
//
// Prerequisites / Expected Services:
//   - Used by note evaluation handlers (Node.evalNote) when receiving gossip to validate peer note masks against Byzantine thresholds.
func (v *View) ValidMask(mask uint32) bool {
	err := validMask(mask, v.rings.numRings, v.maxByz)
	if err != nil {
		log.Error(err.Error())
		return false
	}

	return true
}

func (v *View) deactivateRing(ringNumber uint32) (uint32, error) {
	var idx uint32

	if v.maxByz == 0 {
		return 0, errZeroDeactivate
	}

	ringIdx := ringNumber - 1

	maxIdx := v.rings.numRings - 1

	// removed dead condition: || ringNumber < 0
	if ringIdx > maxIdx {
		return 0, errNonExistingRing
	}

	currMask := v.self.note.mask
	if active := hasBit(currMask, ringIdx); !active {
		return 0, errAlreadyDeactivated
	}

	if v.deactivatedRings == v.maxByz {
		for idx = 0; idx <= maxIdx; idx++ {
			if idx != ringIdx && !hasBit(currMask, idx) {
				break
			}
		}
		currMask = setBit(currMask, idx)
	} else {
		v.deactivatedRings++
	}

	return clearBit(currMask, ringIdx), nil
}

func (v *View) signLocalNote(n *Note) error {
	pbNote := &pb.Note{
		Epoch: n.epoch,
		Mask:  n.mask,
		Id:    []byte(n.id),
	}

	bytes, err := gpb.Marshal(pbNote)
	if err != nil {
		return err
	}

	r, s, err := v.s.Sign(bytes)
	if err != nil {
		return err
	}

	n.signature = &signature{
		r: r,
		s: s,
	}

	v.self.note = n
	if v.notes == nil {
		return ErrNotesNotInitialized
	}
	v.notes.AddItem(n, n.epoch)

	return nil
}

func validMask(mask, numRings, maxByz uint32) error {
	active := bits.OnesCount32(mask)
	disabled := int(numRings) - active

	if disabled > int(maxByz) {
		return errTooManyDeactivatedRings
	}

	return nil
}

func hashContent(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func setBit(n uint32, pos uint32) uint32 {
	n |= (1 << pos)
	return n
}

func clearBit(n uint32, pos uint32) uint32 {
	mask := uint32(^(1 << pos))
	n &= mask
	return n
}

func hasBit(n uint32, pos uint32) bool {
	val := n & (1 << pos)
	return (val > 0)
}

// AccusationStore returns the underlying ReverseIndexStore for accusations.
func (v *View) AccusationStore() revIdxStore.ReverseIndexStore[*Accusation, revIdxStore.DigestSymbol] {
	return v.accusationStore
}

// AccusationFingerprint returns the XOR fingerprint representing the entire accusation set.
func (v *View) AccusationFingerprint() revIdxStore.DigestSymbol {
	return v.accusationStore.Fingerprint()
}

// Accusations returns all accusations currently stored in the view.
func (v *View) Accusations() []*Accusation {
	return v.accusationStore.Elements()
}

// HasAccusation checks if an exact accusation exists matching (accused, accuser, ringNum, epoch).
func (v *View) HasAccusation(accused, accuser string, ringNum uint32, epoch uint64) bool {
	dummy := &Accusation{
		accused: accused,
		accuser: accuser,
		ringNum: ringNum,
		epoch:   epoch,
	}
	stored, ok := v.accusationStore.Contains(dummy)
	return ok && stored.Equal(accused, accuser, ringNum, epoch)
}

// Accusation returns the stored accusation matching (accused, accuser, ringNum, epoch), or nil if absent.
func (v *View) Accusation(accused, accuser string, ringNum uint32, epoch uint64) *Accusation {
	dummy := &Accusation{
		accused: accused,
		accuser: accuser,
		ringNum: ringNum,
		epoch:   epoch,
	}
	stored, ok := v.accusationStore.Contains(dummy)
	if ok && stored.Equal(accused, accuser, ringNum, epoch) {
		return stored
	}
	return nil
}

// AccusationsForPeer returns all accusations (historic and active) against the given accused peer ID.
func (v *View) AccusationsForPeer(accusedId string) []*Accusation {
	var accs []*Accusation
	for _, a := range v.accusationStore.Elements() {
		if a.accused == accusedId {
			accs = append(accs, a)
		}
	}
	return accs
}

// ActiveAccusationsForPeer returns accusations against peer p whose epoch is greater than or equal
// to the peer's current note epoch (i.e. not superseded by a rebuttal note).
func (v *View) ActiveAccusationsForPeer(p *Peer) []*Accusation {
	if p == nil {
		return nil
	}
	note := p.Note()
	var accs []*Accusation
	for _, a := range v.accusationStore.Elements() {
		if a.accused == p.Id {
			if note == nil || a.epoch >= note.epoch {
				accs = append(accs, a)
			}
		}
	}
	return accs
}

// IsAccused returns true if peer p has at least one active accusation whose epoch is >= current note epoch.
func (v *View) IsAccused(p *Peer) bool {
	if p == nil {
		return false
	}
	note := p.Note()
	for _, a := range v.accusationStore.Elements() {
		if a.accused == p.Id {
			if note == nil || a.epoch >= note.epoch {
				return true
			}
		}
	}
	return false
}

// RingAccusation returns the most recent active accusation against accusedId on ring ringNum.
func (v *View) RingAccusation(accusedId string, ringNum uint32) *Accusation {
	peer := v.Peer(accusedId)
	var note *Note
	if peer != nil {
		note = peer.Note()
	}
	var mostRecent *Accusation
	for _, a := range v.accusationStore.Elements() {
		if a.accused == accusedId && a.ringNum == ringNum {
			if note != nil && a.epoch < note.epoch {
				continue
			}
			if mostRecent == nil || a.epoch > mostRecent.epoch {
				mostRecent = a
			}
		}
	}
	return mostRecent
}

// CreateAccusation creates and signs a new accusation targeting an accused peer and note on ringNum,
// inserting it into the grow-only accusationStore.
func (v *View) CreateAccusation(accused *Peer, accusedNote *Note, ringNum uint32, sign signer) error {
	if accused == nil || accusedNote == nil {
		return errAccusedIsNil
	}
	if ringNum == 0 || ringNum > v.rings.numRings {
		return errInvalidRing
	}

	if v.HasAccusation(accused.Id, v.self.Id, ringNum, accusedNote.epoch) {
		return ErrAccAlreadyExists
	}

	acc := &Accusation{
		accused: accused.Id,
		accuser: v.self.Id,
		epoch:   accusedNote.epoch,
		ringNum: ringNum,
	}

	pbAcc := &pb.Accusation{
		Epoch:   acc.epoch,
		Accuser: []byte(acc.accuser),
		Accused: []byte(acc.accused),
		RingNum: acc.ringNum,
	}

	b, err := gpb.Marshal(pbAcc)
	if err != nil {
		return err
	}

	r, s, err := sign.Sign(b)
	if err != nil {
		return err
	}

	acc.signature = &signature{
		r: r,
		s: s,
	}

	v.accusationStore.AddElement(acc)
	log.Debug("Added accusation to view", "accused", accused.Addr, "ring", acc.ringNum, "epoch", acc.epoch)
	return nil
}

// AddAccusation validates and records an accusation received from the network into the grow-only accusationStore.
func (v *View) AddAccusation(accused, accuser string, epoch uint64, ringNum uint32, r, s []byte) error {
	if ringNum == 0 || ringNum > v.rings.numRings {
		return errInvalidRing
	}
	if r == nil || s == nil {
		return errAccuserSign
	}
	if accused == "" {
		return errAccusedId
	}
	if accuser == "" {
		return errAccuserId
	}

	a := &Accusation{
		accused: accused,
		accuser: accuser,
		epoch:   epoch,
		ringNum: ringNum,
		signature: &signature{
			r: r,
			s: s,
		},
	}

	v.accusationStore.AddElement(a)
	log.Debug("Added accusation to view", "accused", accused, "accuser", accuser, "ring", ringNum, "epoch", epoch)
	return nil
}

/*

########## METHODS ONLY USED FOR TESTING BELOW THIS LINE ##########

*/

// ONLY for testing
func (v *View) RemoveTestFull(id string) error {
	v.viewMutex.Lock()
	defer v.viewMutex.Unlock()

	if v.notes == nil {
		return ErrNotesNotInitialized
	}
	if p, ok := v.viewStore.Contains(&Peer{Id: id}); ok && p.Id == id {
		v.viewStore.Remove(p)
		v.notes.Remove(v.hashId(id))
	}
	return nil
}

// ONLY for testing
func (v *View) AddTestPeer(p *Peer) {
	v.viewStore.AddElement(p)
}

// ONLY for testing
func (v *View) AddTestLivePeer(p *Peer) {
	v.liveStore.AddElement(p)
}

// ONLY for testing
func (v *View) AddTestAccusation(a *pb.Accusation) {
	acc := &Accusation{
		epoch:   a.GetEpoch(),
		accuser: string(a.GetAccuser()),
		accused: string(a.GetAccused()),
		ringNum: a.GetRingNum(),
		signature: &signature{
			r: a.GetSignature().GetR(),
			s: a.GetSignature().GetS(),
		},
	}
	v.accusationStore.AddElement(acc)
}

// ONLY for testing
func (v *View) Compare(other *View) error {
	for _, p := range v.viewStore.Elements() {
		id := p.Id
		var p2 *Peer
		if id == other.self.Id {
			p2 = other.self
		} else {
			var ok bool
			p2, ok = other.viewStore.Contains(p)
			if !ok || p2.Id != id {
				return errors.New("Peer not present in both views.")
			}
		}

		if p.note == nil && p2.note == nil {
			continue
		}
		if p.note == nil || p2.note == nil {
			return errors.New("Did not have note for peer in both views.")
		}
		if !p.note.Equal(p2.note.epoch) {
			return errors.New("Did not have same note for peer in both views.")
		}
	}

	for _, p := range v.liveStore.Elements() {
		if p.Id == other.self.Id {
			continue
		}
		if !other.IsAlive(p) {
			return errors.New("Did not have peer in both live views.")
		}
	}

	if len(v.accusationStore.Elements()) != len(other.accusationStore.Elements()) {
		return errors.New("Accusation counts mismatch in views.")
	}

	for _, a := range v.accusationStore.Elements() {
		a2, ok := other.accusationStore.Contains(a)
		if !ok || !a.Equal(a2.accused, a2.accuser, a2.ringNum, a2.epoch) {
			return errors.New("Accusation not equal in both views.")
		}
	}

	return nil
}
