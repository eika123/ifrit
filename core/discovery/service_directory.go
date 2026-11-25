package discovery

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/eika123/ifrit/digestmaps"
)

type serviceTimeout struct {
	accused        *Peer
	serviceID      string
	serviceVersion uint64
	timeStamp      time.Time
}

func serviceTimeoutKey(peerID, serviceID string) string {
	return peerID + ":" + serviceID
}

func serviceAccusationKey(accused, serviceID string, ringNum uint32) string {
	return fmt.Sprintf("%s:%s:%d", accused, serviceID, ringNum)
}

// ServiceDirectory manages the Service Discovery Plane (Tier 1 grow-only reconcilable
// stores + Tier 2 VersionVectorMutable indirection layers + incremental membership index
// + deterministic RingSuperOverlay instances + service suspicion timers).
type ServiceDirectory struct {
	mu       sync.RWMutex
	self     *Peer
	numRings uint32

	serviceStore    digestmaps.ReverseIndexStore[*ServiceNote, digestmaps.DigestSymbol]
	serviceAccStore digestmaps.ReverseIndexStore[*ServiceAccusation, digestmaps.DigestSymbol]

	activeServices    digestmaps.VersionVectorMutable[string, *ServiceNote, digestmaps.DigestSymbol]
	activeAccusations digestmaps.VersionVectorMutable[string, *ServiceAccusation, digestmaps.DigestSymbol]

	// membersByService maps serviceID -> {peerID -> *Peer} for live, non-evicted peers
	// (including self if locally registered). Maintained incrementally in O(delta).
	membersByService map[string]map[string]*Peer

	// evictedVersions records the highest evicted serviceVersion for (peerID, serviceID)
	// so evicted services stay excluded until the peer publishes a higher serviceVersion.
	evictedVersions map[string]uint64

	// serviceTimeouts tracks active suspicion timers for (peerID, serviceID).
	serviceTimeouts map[string]*serviceTimeout

	// overlays and healthChecks are maintained ONLY for services locally attached on this node.
	overlays     map[string]*RingSuperOverlay
	healthChecks map[string]func() bool
}

// NewServiceDirectory initializes a ServiceDirectory backed by optional pre-built Tier 1 stores.
func NewServiceDirectory(
	self *Peer,
	numRings uint32,
	serviceStore digestmaps.ReverseIndexStore[*ServiceNote, digestmaps.DigestSymbol],
	serviceAccStore digestmaps.ReverseIndexStore[*ServiceAccusation, digestmaps.DigestSymbol],
) (*ServiceDirectory, error) {
	if self == nil || self.Id == "" {
		return nil, errNoSelf
	}
	if numRings == 0 {
		return nil, errNoRings
	}

	var err error
	if serviceStore == nil {
		serviceStore, err = digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[*ServiceNote]())
		if err != nil {
			return nil, err
		}
	}
	if serviceAccStore == nil {
		serviceAccStore, err = digestmaps.NewDigestSet(digestmaps.MustDefaultHasher[*ServiceAccusation]())
		if err != nil {
			return nil, err
		}
	}

	noteHasher := digestmaps.MustDefaultHasher[*ServiceNote]()
	activeServices := digestmaps.NewVersionVectorMutable(
		func(a *ServiceNote) string { return a.Id() },
		func(vi digestmaps.VersionedItem[*ServiceNote]) digestmaps.DigestSymbol {
			return noteHasher(vi.Item)
		},
	)

	accHasher := digestmaps.MustDefaultHasher[*ServiceAccusation]()
	activeAccs := digestmaps.NewVersionVectorMutable(
		func(a *ServiceAccusation) string {
			return serviceAccusationKey(a.Accused(), a.ServiceID(), a.RingNum())
		},
		func(vi digestmaps.VersionedItem[*ServiceAccusation]) digestmaps.DigestSymbol {
			return accHasher(vi.Item)
		},
	)

	return &ServiceDirectory{
		self:              self,
		numRings:          numRings,
		serviceStore:      serviceStore,
		serviceAccStore:   serviceAccStore,
		activeServices:    activeServices,
		activeAccusations: activeAccs,
		membersByService:  make(map[string]map[string]*Peer),
		evictedVersions:   make(map[string]uint64),
		serviceTimeouts:   make(map[string]*serviceTimeout),
		overlays:          make(map[string]*RingSuperOverlay),
		healthChecks:      make(map[string]func() bool),
	}, nil
}

func (sd *ServiceDirectory) ServiceStore() digestmaps.ReverseIndexStore[*ServiceNote, digestmaps.DigestSymbol] {
	return sd.serviceStore
}

func (sd *ServiceDirectory) ServiceAccusationStore() digestmaps.ReverseIndexStore[*ServiceAccusation, digestmaps.DigestSymbol] {
	return sd.serviceAccStore
}

// Fingerprint returns the combined Tier 1 Service Discovery XOR fingerprint
// (serviceStore ^ serviceAccStore) carried in UDP Pong.FingerprintServices.
func (sd *ServiceDirectory) Fingerprint() digestmaps.DigestSymbol {
	return sd.serviceStore.Fingerprint().XOR(sd.serviceAccStore.Fingerprint())
}

// Epoch returns the monotonic whole-vector mutation counter of activeServices.
func (sd *ServiceDirectory) Epoch() uint64 {
	return sd.activeServices.Epoch()
}

func (sd *ServiceDirectory) SelfServiceNote() (*ServiceNote, bool) {
	return sd.ActiveServiceNote(sd.self.Id)
}

func (sd *ServiceDirectory) ActiveServiceNote(peerID string) (*ServiceNote, bool) {
	entry, ok := sd.activeServices.GetOne(peerID)
	if !ok {
		return nil, false
	}
	return entry.Item, true
}

func (sd *ServiceDirectory) ServiceVersion(peerID, serviceID string) (uint64, bool) {
	note, ok := sd.ActiveServiceNote(peerID)
	if !ok {
		return 0, false
	}
	return note.ServiceVersion(serviceID)
}

// RegisterLocalService attaches serviceID on this node, creates its deterministic
// RingSuperOverlay seeded with currently live members of S_svc, and publishes a new
// signed ServiceNote if serviceID was added or its version advanced.
func (sd *ServiceDirectory) RegisterLocalService(
	s signer,
	serviceID string,
	version uint64,
	healthCheck func() bool,
) (*ServiceNote, *RingSuperOverlay, error) {
	if err := ValidateServiceID(serviceID); err != nil {
		return nil, nil, err
	}
	if version == 0 {
		version = 1
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	if healthCheck != nil {
		sd.healthChecks[serviceID] = healthCheck
	}

	overlay, exists := sd.overlays[serviceID]
	if !exists {
		var err error
		overlay, err = NewRingSuperOverlay(PeerInfo{ID: sd.self.Id, Addr: sd.self.Addr}, sd.numRings)
		if err != nil {
			return nil, nil, err
		}
		for _, p := range sd.membersByService[serviceID] {
			if p.Id != sd.self.Id {
				overlay.OnJoin(PeerInfo{ID: p.Id, Addr: p.Addr})
			}
		}
		sd.overlays[serviceID] = overlay
	}

	currVV := NewServiceVector()
	currEntry, hasSelf := sd.activeServices.GetOne(sd.self.Id)
	if hasSelf && currEntry.Item != nil && currEntry.Item.Vector() != nil {
		currVV = currEntry.Item.Vector()
	}

	nextVV, changed := currVV.AddItem(digestmaps.VersionedItem[string]{
		Item:    serviceID,
		Version: version,
	})
	if !changed {
		return currEntry.Item, overlay, nil
	}

	note, err := NewSignedServiceNote(sd.self.Id, nextVV, s)
	if err != nil {
		return nil, nil, err
	}
	sd.serviceStore.Insert(note)
	sd.activeServices.AddItem(digestmaps.VersionedItem[*ServiceNote]{
		Item:    note,
		Version: note.Epoch(),
	})
	sd.addMemberLocked(serviceID, sd.self)
	delete(sd.evictedVersions, serviceTimeoutKey(sd.self.Id, serviceID))
	return note, overlay, nil
}

// UnregisterLocalService detaches serviceID from this node's local overlays and publishes
// a new signed ServiceNote with serviceID removed (bumping the vector epoch).
func (sd *ServiceDirectory) UnregisterLocalService(s signer, serviceID string) (*ServiceNote, error) {
	if err := ValidateServiceID(serviceID); err != nil {
		return nil, err
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	delete(sd.overlays, serviceID)
	delete(sd.healthChecks, serviceID)
	sd.removeMemberLocked(serviceID, sd.self.Id)

	entry, ok := sd.activeServices.GetOne(sd.self.Id)
	if !ok || entry.Item == nil || entry.Item.Vector() == nil {
		return nil, nil
	}

	nextVV, removed := entry.Item.Vector().Remove(serviceID)
	if !removed {
		return entry.Item, nil
	}

	note, err := NewSignedServiceNote(sd.self.Id, nextVV, s)
	if err != nil {
		return nil, err
	}
	sd.serviceStore.Insert(note)
	sd.activeServices.AddItem(digestmaps.VersionedItem[*ServiceNote]{
		Item:    note,
		Version: note.Epoch(),
	})
	return note, nil
}

// ShouldRebutService handles a verified self-accusation targeting serviceID at accusedVersion.
// If the local service is still registered and passes its HealthCheck, it bumps serviceID's
// version to accusedVersion+1 and publishes a signed rebuttal ServiceNote.
// If unhealthy, it unregisters serviceID locally so the dead service is cleanly removed.
func (sd *ServiceDirectory) ShouldRebutService(
	s signer,
	serviceID string,
	accusedVersion uint64,
) (*ServiceNote, bool, error) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	entry, ok := sd.activeServices.GetOne(sd.self.Id)
	if !ok || entry.Item == nil {
		return nil, false, nil
	}
	currVer, hosted := entry.Item.ServiceVersion(serviceID)
	if !hosted || accusedVersion < currVer {
		return nil, false, nil
	}

	if hc := sd.healthChecks[serviceID]; hc != nil && !hc() {
		// Local service failed health check: unregister instead of rebutting.
		delete(sd.overlays, serviceID)
		delete(sd.healthChecks, serviceID)
		sd.removeMemberLocked(serviceID, sd.self.Id)
		nextVV, removed := entry.Item.Vector().Remove(serviceID)
		if !removed {
			return nil, false, nil
		}
		note, err := NewSignedServiceNote(sd.self.Id, nextVV, s)
		if err != nil {
			return nil, false, err
		}
		sd.serviceStore.Insert(note)
		sd.activeServices.AddItem(digestmaps.VersionedItem[*ServiceNote]{
			Item:    note,
			Version: note.Epoch(),
		})
		return note, false, nil
	}

	nextVer := accusedVersion + 1
	nextVV, changed := entry.Item.Vector().AddItem(digestmaps.VersionedItem[string]{
		Item:    serviceID,
		Version: nextVer,
	})
	if !changed {
		return nil, false, nil
	}
	note, err := NewSignedServiceNote(sd.self.Id, nextVV, s)
	if err != nil {
		return nil, false, err
	}
	sd.serviceStore.Insert(note)
	sd.activeServices.AddItem(digestmaps.VersionedItem[*ServiceNote]{
		Item:    note,
		Version: note.Epoch(),
	})
	sd.pruneAccusationsLocked(sd.self.Id, serviceID, nextVer)
	return note, true, nil
}

// PromoteServiceNote advances activeServices if note.Epoch() is newer, prunes superseded
// per-service accusations/timers, and incrementally updates membersByService and attached overlays.
func (sd *ServiceDirectory) PromoteServiceNote(note *ServiceNote, isLive func(string) (*Peer, bool)) bool {
	if note == nil {
		return false
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	prevEntry, hadPrev := sd.activeServices.GetOne(note.Id())
	if _, advanced := sd.activeServices.AddItem(digestmaps.VersionedItem[*ServiceNote]{
		Item:    note,
		Version: note.Epoch(),
	}); !advanced {
		return false
	}

	var prevServices map[string]uint64
	if hadPrev && prevEntry.Item != nil {
		prevServices = prevEntry.Item.Services()
	}
	newServices := note.Services()

	var livePeer *Peer
	if note.Id() == sd.self.Id {
		livePeer = sd.self
	} else if isLive != nil {
		if p, ok := isLive(note.Id()); ok {
			livePeer = p
		}
	}

	// Handle removed services.
	for svcID := range prevServices {
		if _, stillPresent := newServices[svcID]; !stillPresent {
			sd.removeMemberLocked(svcID, note.Id())
			delete(sd.serviceTimeouts, serviceTimeoutKey(note.Id(), svcID))
		}
	}

	// Handle added or version-advanced services.
	for svcID, newVer := range newServices {
		oldVer := prevServices[svcID]
		if newVer > oldVer {
			sd.pruneAccusationsLocked(note.Id(), svcID, newVer)
			if t, ok := sd.serviceTimeouts[serviceTimeoutKey(note.Id(), svcID)]; ok && newVer > t.serviceVersion {
				delete(sd.serviceTimeouts, serviceTimeoutKey(note.Id(), svcID))
			}
		}
		if livePeer != nil && !sd.isEvictedLocked(note.Id(), svcID, newVer) {
			sd.addMemberLocked(svcID, livePeer)
		}
	}

	return true
}

// OnPeerLive adds p to membersByService and attached overlays for all non-evicted services
// in p's active ServiceNote.
func (sd *ServiceDirectory) OnPeerLive(p *Peer) {
	if p == nil || p.Id == "" {
		return
	}
	sd.mu.Lock()
	defer sd.mu.Unlock()

	entry, ok := sd.activeServices.GetOne(p.Id)
	if !ok || entry.Item == nil {
		return
	}
	for svcID, ver := range entry.Item.Services() {
		if !sd.isEvictedLocked(p.Id, svcID, ver) {
			sd.addMemberLocked(svcID, p)
		}
	}
}

// OnPeerDead removes p from all services and attached overlays when the host is evicted
// from Fireflies' live view.
func (sd *ServiceDirectory) OnPeerDead(p *Peer) {
	if p == nil || p.Id == "" {
		return
	}
	sd.mu.Lock()
	defer sd.mu.Unlock()

	entry, ok := sd.activeServices.GetOne(p.Id)
	if !ok || entry.Item == nil {
		return
	}
	for svcID := range entry.Item.Services() {
		sd.removeMemberLocked(svcID, p.Id)
		delete(sd.serviceTimeouts, serviceTimeoutKey(p.Id, svcID))
	}
}

// ValidateAndPromoteAccusation validates a signature-verified ServiceAccusation against
// the service's deterministic RingSuperOverlay (S_svc) and active per-service version.
// For remote peers, it promotes the accusation and starts a service suspicion timer.
// Returns (true, nil) if the accusation validly targets self so the caller can run ShouldRebutService.
func (sd *ServiceDirectory) ValidateAndPromoteAccusation(
	acc *ServiceAccusation,
	isLive func(string) (*Peer, bool),
) (bool, error) {
	if acc == nil {
		return false, ErrNilServiceAccusation
	}
	if acc.RingNum() == 0 || acc.RingNum() > sd.numRings {
		return false, errInvalidRing
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	accusedEntry, ok := sd.activeServices.GetOne(acc.Accused())
	if !ok || accusedEntry.Item == nil {
		return false, ErrServiceNotHosted
	}
	activeVer, hosted := accusedEntry.Item.ServiceVersion(acc.ServiceID())
	if !hosted {
		return false, ErrServiceNotHosted
	}
	if activeVer != acc.ServiceVersion() {
		return false, ErrInvalidServiceVersion
	}

	if !sd.isServicePredecessorLocked(acc.ServiceID(), acc.Accused(), acc.Accuser(), acc.RingNum()) {
		return false, ErrInvalidServiceAccuser
	}

	if acc.Accused() == sd.self.Id {
		return true, nil
	}

	key := serviceAccusationKey(acc.Accused(), acc.ServiceID(), acc.RingNum())
	if existing, exists := sd.activeAccusations.GetOne(key); exists && existing.Version >= acc.ServiceVersion() {
		return false, ErrServiceAccAlreadyExists
	}

	sd.activeAccusations.AddItem(digestmaps.VersionedItem[*ServiceAccusation]{
		Item:    acc,
		Version: acc.ServiceVersion(),
	})

	if isLive != nil {
		if accusedPeer, alive := isLive(acc.Accused()); alive {
			tKey := serviceTimeoutKey(acc.Accused(), acc.ServiceID())
			if existing, exists := sd.serviceTimeouts[tKey]; !exists || existing.serviceVersion < acc.ServiceVersion() {
				ts := time.Now()
				if exists {
					ts = existing.timeStamp
				}
				sd.serviceTimeouts[tKey] = &serviceTimeout{
					accused:        accusedPeer,
					serviceID:      acc.ServiceID(),
					serviceVersion: acc.ServiceVersion(),
					timeStamp:      ts,
				}
			}
		}
	}

	return false, nil
}

// CheckTimeouts evicts any (peer, serviceID) whose service suspicion timer has exceeded
// removalTimeout without a per-service version rebuttal, leaving the host in View.Live().
func (sd *ServiceDirectory) CheckTimeouts(now time.Time, removalTimeout float64) {
	if removalTimeout <= 0 {
		return
	}
	sd.mu.Lock()
	defer sd.mu.Unlock()

	for key, t := range sd.serviceTimeouts {
		if now.Sub(t.timeStamp).Seconds() > removalTimeout {
			sd.evictedVersions[key] = t.serviceVersion
			sd.removeMemberLocked(t.serviceID, t.accused.Id)
			delete(sd.serviceTimeouts, key)
		}
	}
}

// IsServicePredecessor checks whether accuserID is the immediate predecessor of accusedID
// on ringNum within serviceID's deterministic RingSuperOverlay (S_svc).
func (sd *ServiceDirectory) IsServicePredecessor(serviceID, accusedID, accuserID string, ringNum uint32) bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.isServicePredecessorLocked(serviceID, accusedID, accuserID, ringNum)
}

func (sd *ServiceDirectory) isServicePredecessorLocked(serviceID, accusedID, accuserID string, ringNum uint32) bool {
	if overlay, ok := sd.overlays[serviceID]; ok {
		return overlay.IsPredecessor(accusedID, accuserID, ringNum)
	}
	return IsPredecessorInMemberSet(sd.membersByService[serviceID], accusedID, accuserID, ringNum)
}

// Members returns all live, non-evicted peers currently hosting serviceID (excluding self),
// sorted deterministically by PeerInfo.ID. Complexity: O(|S_svc| log |S_svc|), independent of N.
func (sd *ServiceDirectory) Members(serviceID string) []PeerInfo {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	members := sd.membersByService[serviceID]
	out := make([]PeerInfo, 0, len(members))
	for id, p := range members {
		if id == sd.self.Id {
			continue
		}
		out = append(out, PeerInfo{ID: p.Id, Addr: p.Addr})
	}
	slices.SortFunc(out, func(a, b PeerInfo) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return out
}

// Overlay returns the locally attached RingSuperOverlay for serviceID, or nil if not attached.
func (sd *ServiceDirectory) Overlay(serviceID string) *RingSuperOverlay {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.overlays[serviceID]
}

// HasServiceTimeout reports whether an active suspicion timer exists for (peerID, serviceID).
func (sd *ServiceDirectory) HasServiceTimeout(peerID, serviceID string) bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	_, ok := sd.serviceTimeouts[serviceTimeoutKey(peerID, serviceID)]
	return ok
}

// CreateServiceAccusation signs a ServiceAccusation against accusedID for serviceID on ringNum,
// inserts it into Tier 1 serviceAccStore, and starts a local suspicion timer if valid.
func (sd *ServiceDirectory) CreateServiceAccusation(
	s signer,
	accused *Peer,
	serviceID string,
	ringNum uint32,
	isLive func(string) (*Peer, bool),
) (*ServiceAccusation, error) {
	if accused == nil || accused.Id == "" {
		return nil, errAccusedIsNil
	}
	if accused.Id == sd.self.Id {
		return nil, errors.New("cannot accuse self service")
	}
	ver, ok := sd.ServiceVersion(accused.Id, serviceID)
	if !ok {
		return nil, ErrServiceNotHosted
	}
	if !sd.IsServicePredecessor(serviceID, accused.Id, sd.self.Id, ringNum) {
		return nil, ErrInvalidServiceAccuser
	}
	acc, err := NewSignedServiceAccusation(accused.Id, sd.self.Id, serviceID, ver, ringNum, s)
	if err != nil {
		return nil, err
	}
	sd.serviceAccStore.Insert(acc)
	_, err = sd.ValidateAndPromoteAccusation(acc, isLive)
	if err != nil && !errors.Is(err, ErrServiceAccAlreadyExists) {
		return nil, err
	}
	return acc, nil
}

func (sd *ServiceDirectory) addMemberLocked(serviceID string, p *Peer) {
	if p == nil || p.Id == "" {
		return
	}
	set, ok := sd.membersByService[serviceID]
	if !ok {
		set = make(map[string]*Peer)
		sd.membersByService[serviceID] = set
	}
	if _, already := set[p.Id]; already {
		return
	}
	set[p.Id] = p
	if overlay, attached := sd.overlays[serviceID]; attached && p.Id != sd.self.Id {
		overlay.OnJoin(PeerInfo{ID: p.Id, Addr: p.Addr})
	}
}

func (sd *ServiceDirectory) removeMemberLocked(serviceID, peerID string) {
	set, ok := sd.membersByService[serviceID]
	if !ok {
		return
	}
	if _, exists := set[peerID]; !exists {
		return
	}
	delete(set, peerID)
	if len(set) == 0 {
		delete(sd.membersByService, serviceID)
	}
	if overlay, attached := sd.overlays[serviceID]; attached && peerID != sd.self.Id {
		overlay.OnLeave(peerID)
	}
}

// NB! Naming
func (sd *ServiceDirectory) isEvictedLocked(peerID, serviceID string, ver uint64) bool {
	evictedVer, evicted := sd.evictedVersions[serviceTimeoutKey(peerID, serviceID)]
	return evicted && ver <= evictedVer
}

// NB! Naming
func (sd *ServiceDirectory) pruneAccusationsLocked(accusedID, serviceID string, newVersion uint64) {
	for ringNum := uint32(1); ringNum <= sd.numRings; ringNum++ {
		key := serviceAccusationKey(accusedID, serviceID, ringNum)
		if entry, ok := sd.activeAccusations.GetOne(key); ok && entry.Version < newVersion {
			sd.activeAccusations.Remove(key)
		}
	}
}
