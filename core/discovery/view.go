package discovery

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/bits"
	"strings"
	"sync"
	"time"

	gpb "github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
	proto "github.com/joonnna/ifrit/protobuf"
	"github.com/spf13/viper"
)

var (
	errInvalidNeighbours  = errors.New("Neighbours are nil ?!")
	errPeerAlreadyExists  = errors.New("Peer id already exists in the full view")
	errAlreadyDeactivated = errors.New("Ring was already deactivated")
	errZeroDeactivate     = errors.New("No ring can be deactivated, maxbyz is 0")
	errNoNote             = errors.New("Note was nil.")
	errAccusedIsNil       = errors.New("Accused was nil.")
	errObsIsNil           = errors.New("Observer was nil")
	errWrongNote          = errors.New("Note does not belong to accused.")
)

type View struct {
	viewMap   map[string]*Peer
	viewMutex sync.RWMutex

	liveMap   map[string]*Peer
	liveMutex sync.RWMutex

	timeoutMap   map[string]*timeout
	timeoutMutex sync.RWMutex

	rings *rings

	currGossipRing  uint32
	currMonitorRing uint32

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
//   - Viper configuration must be loaded (keys: "dead_timeout", "view_update_interval").
func NewView(numRings uint32, cert *x509.Certificate, cm connectionManager, s signer) (*View, error) {
	var i, mask uint32

	maxByz := (float64(numRings) / 2.0) - 1
	if maxByz < 0 {
		maxByz = 0
	}

	self, err := newPeer(cert, numRings)
	if err != nil {
		return nil, err
	}

	rings, err := createRings(self, numRings)
	if err != nil {
		return nil, err
	}

	v := &View{
		rings:           rings,
		viewMap:         make(map[string]*Peer),
		liveMap:         make(map[string]*Peer),
		timeoutMap:      make(map[string]*timeout),
		maxByz:          uint32(maxByz),
		currGossipRing:  1,
		currMonitorRing: 1,
		self:            self,
		cm:              cm,
		exitChan:        make(chan bool, 1),
		s:               s,

		removalTimeout: viper.GetFloat64("dead_timeout"),
		updateTimeout: time.Second * time.Duration(viper.
			GetInt32("view_update_interval")),
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

// Peer returns the Peer with the given ID from the full view map, or nil if not present.
//
// Prerequisites / Expected Services:
//   - Peers must have been registered into the full view (e.g. via certificate validation in gossip handlers or CA contacts).
func (v *View) Peer(id string) *Peer {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	if p, ok := v.viewMap[id]; !ok {
		return nil
	} else {
		return p
	}
}

// Full returns a slice of all known peers in the full view map.
//
// Prerequisites / Expected Services:
//   - Used during gossip digest preparation, state responses, or bootstrapping to enumerate known hosts.
func (v *View) Full() []*Peer {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	ret := make([]*Peer, 0, len(v.viewMap))

	for _, p := range v.viewMap {
		ret = append(ret, p)
	}

	return ret
}

// Exists reports whether a peer with the specified ID exists in the full view map.
//
// Prerequisites / Expected Services:
//   - Used before processing peer notes or accusations to verify registration in full view.
func (v *View) Exists(id string) bool {
	v.viewMutex.RLock()
	defer v.viewMutex.RUnlock()

	_, ok := v.viewMap[id]

	return ok
}

// Live returns a slice of all currently active/live peers.
//
// Prerequisites / Expected Services:
//   - Peers must have been inserted into the live view (e.g. initial contacts or validated gossip notes).
//   - Used by application services, failure detectors, or visualizers to query active cluster membership.
func (v *View) Live() []*Peer {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	ret := make([]*Peer, 0, len(v.liveMap))

	for _, p := range v.liveMap {
		ret = append(ret, p)
	}

	return ret

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

	if _, ok := v.viewMap[id]; ok {
		log.Error("Tried to add peer twice to viewMap")
		return errPeerAlreadyExists
	}

	p, err := newPeer(cert, v.rings.numRings)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	v.viewMap[p.Id] = p

	return nil
}

// MyNeighbours returns all distinct neighbours (predecessors and successors) across all active rings.
//
// Prerequisites / Expected Services:
//   - Used by gossip protocols and failure detectors to discover which nodes to monitor/probe.
func (v *View) MyNeighbours() []*Peer {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	return v.rings.allMyNeighbours()
}

// GossipPartners returns the ring neighbours for the current gossip ring and
// advances the gossip ring index round-robin for the next call.
//
// Prerequisites / Expected Services:
//   - Expected to be called by the periodic gossip loop (Node.gossipLoop) on each gossip round.
func (v *View) GossipPartners() []*Peer {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	// Only one goroutine accesses gossip ring variable,
	// only take read lock for live view.
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
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	ringNum := v.currMonitorRing

	// Only one goroutine accesses monitor ring variable,
	// only take read lock for live view.
	defer v.incrementMonitorRing()

	return v.rings.myRingSuccessor(v.currMonitorRing), ringNum
}

// AddLive inserts a peer into the live map and places them into the ring structures,
// closing connections to any peers that are no longer direct ring neighbours.
//
// Prerequisites / Expected Services:
//   - Peer must have been validated (valid certificate and fresh signed Note) before adding to live view.
//   - connectionManager (commService) must be initialized to close connections to displaced ring neighbours.
func (v *View) AddLive(p *Peer) {
	v.liveMutex.Lock()
	defer v.liveMutex.Unlock()

	if _, ok := v.liveMap[p.Id]; ok {
		log.Error("Tried to add peer twice to liveMap", "addr", p.Addr)
		return
	}

	v.liveMap[p.Id] = p

	old := v.rings.add(p)
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
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	return v.rings.myRingSuccessor(ringNum), v.rings.myRingPredecessor(ringNum)
}

// LivePeer retrieves a peer from the live map by their ID, returning nil if not found.
//
// Prerequisites / Expected Services:
//   - Used when handling gossip and accusations to check if the target is currently considered active.
func (v *View) LivePeer(id string) *Peer {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	return v.liveMap[id]
}

// RemoveLive removes a peer from the live map and ring structures, closing any active connection to them.
//
// Prerequisites / Expected Services:
//   - connectionManager (commService) must be initialized to close the open transport connection to the removed peer.
//   - Called when a suspicion timeout expires (Start / checkTimeouts) or on explicit eviction.
func (v *View) RemoveLive(id string) {
	v.liveMutex.Lock()
	defer v.liveMutex.Unlock()

	if peer, ok := v.liveMap[id]; ok {
		v.rings.remove(peer)

		delete(v.liveMap, peer.Id)

		v.cm.CloseConn(peer.Addr)

		log.Debug("Removed livePeer", "addr", peer.Addr)
	} else {
		log.Debug("Tried to remove non-existing peer from live view.")
	}
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

// HasTimer checks whether an active suspicion timer exists for the given peer ID.
//
// Prerequisites / Expected Services:
//   - Used during gossip and note evaluation to check if an accused peer currently has a pending timeout.
func (v *View) HasTimer(id string) bool {
	v.timeoutMutex.RLock()
	defer v.timeoutMutex.RUnlock()

	_, ok := v.timeoutMap[id]

	return ok
}

// DeleteTimeout removes the active suspicion timer for the specified peer ID.
//
// Prerequisites / Expected Services:
//   - Called when a valid rebuttal Note is received or when a peer is evicted after timeout expiration.
func (v *View) DeleteTimeout(id string) {
	v.timeoutMutex.Lock()
	defer v.timeoutMutex.Unlock()

	delete(v.timeoutMap, id)
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
			v.RemoveLive(t.accused.Id)
			v.DeleteTimeout(t.accused.Id)
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
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	return v.rings.shouldBeMyNeighbour(id)
}

// FindNeighbours returns all neighbours of the given peer ID across all rings.
//
// Prerequisites / Expected Services:
//   - Used during peer placement checks and diagnostic/visualizer services.
func (v *View) FindNeighbours(id string) []*Peer {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	return v.rings.findNeighbours(id)
}

// ValidAccuser checks whether the accuser peer is the valid predecessor of the accused peer on the specified ring.
//
// Prerequisites / Expected Services:
//   - Used by accusation validation handlers (Node.evalAccusation) to verify accusation legitimacy before accepting.
func (v *View) ValidAccuser(accused, accuser *Peer, ringNum uint32) bool {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	return v.rings.isPredecessor(accused, accuser, ringNum)
}

// IsAlive checks whether a peer with the given ID currently exists in the live view map.
//
// Prerequisites / Expected Services:
//   - Used by failure detectors, visualizers, and message handlers before routing messages.
func (v *View) IsAlive(id string) bool {
	v.liveMutex.RLock()
	defer v.liveMutex.RUnlock()

	_, ok := v.liveMap[id]

	return ok
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

	for _, p := range v.viewMap {
		id := strings.ToValidUTF8(p.Id, "")
		if note := p.Note(); note != nil {
			ret.ExistingHosts[id] = note.epoch
		} else {
			ret.ExistingHosts[id] = 0
		}
	}

	return ret
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

	return err
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

/*

########## METHODS ONLY USED FOR TESTING BELOW THIS LINE ##########

*/

// ONLY for testing
func (v *View) RemoveTestFull(id string) {
	delete(v.viewMap, id)
}

// ONLY for testing
func (v *View) Compare(other *View) error {
	for id, p := range v.viewMap {
		if p2, ok := other.viewMap[id]; !ok {
			return errors.New("Peer not present in both views.")
		} else {
			for ringNum, a := range p.accusations {
				if a2, ok := p2.accusations[ringNum]; !ok {
					return errors.New("Accusation not present in both views.")
				} else {
					if !a.Equal(a2.accused, a2.accuser, a2.ringNum, a2.epoch) {
						return errors.New("Accusation were not equal in both views.")
					}
				}
			}
			if !p.note.Equal(p2.note.epoch) {
				return errors.New("Did not have same note for peer in both views.")
			}
		}
	}

	for id, _ := range v.liveMap {
		if _, ok := other.liveMap[id]; !ok {
			return errors.New("Did not have peer in both live views.")
		}
	}

	return nil
}
