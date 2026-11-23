package discovery

import "sync"

// PeerInfo is an immutable snapshot of a live peer's identity and RPC endpoint.
type PeerInfo struct {
	ID   string
	Addr string
}

// SuperOverlay maintains a deterministic service-level neighbor topology over a
// dynamic live member subset S_svc sitting above the base Fireflies overlay.
type SuperOverlay interface {
	OnJoin(peer PeerInfo)
	OnLeave(peerID string)
	Neighbours() []PeerInfo
	GossipPartners() []PeerInfo
}

// RingSuperOverlay implements SuperOverlay using Fireflies' deterministic k-ring
// topology (SHA-256(peer.ID || ringNum)) over ONLY the live members hosting a service.
// Neighbor lookups are O(k) and gossip partner lookups are O(1), independent of total
// base-overlay cluster size N.
type RingSuperOverlay struct {
	mu             sync.RWMutex
	rings          *rings
	selfID         string
	currGossipRing uint32
	present        map[string]struct{}
}

// NewRingSuperOverlay constructs a deterministic k-ring super-overlay rooted at self.
func NewRingSuperOverlay(self PeerInfo, numRings uint32) (*RingSuperOverlay, error) {
	selfPeer := &Peer{
		Id:   self.ID,
		Addr: self.Addr,
	}
	rs, err := createRings(selfPeer, numRings)
	if err != nil {
		return nil, err
	}
	return &RingSuperOverlay{
		rings:          rs,
		selfID:         self.ID,
		currGossipRing: 1,
		present:        map[string]struct{}{self.ID: {}},
	}, nil
}

// OnJoin inserts peer into the k-ring super-overlay if not already present.
func (ro *RingSuperOverlay) OnJoin(peer PeerInfo) {
	if peer.ID == "" || peer.ID == ro.selfID {
		return
	}
	ro.mu.Lock()
	defer ro.mu.Unlock()
	if _, exists := ro.present[peer.ID]; exists {
		return
	}
	ro.rings.add(&Peer{Id: peer.ID, Addr: peer.Addr})
	ro.present[peer.ID] = struct{}{}
}

// OnLeave removes peerID from the k-ring super-overlay if present.
func (ro *RingSuperOverlay) OnLeave(peerID string) {
	if peerID == "" || peerID == ro.selfID {
		return
	}
	ro.mu.Lock()
	defer ro.mu.Unlock()
	if _, exists := ro.present[peerID]; !exists {
		return
	}
	ro.rings.remove(&Peer{Id: peerID})
	delete(ro.present, peerID)
}

// Neighbours returns all distinct predecessors and successors across all k rings in O(k).
func (ro *RingSuperOverlay) Neighbours() []PeerInfo {
	ro.mu.RLock()
	defer ro.mu.RUnlock()
	peers := ro.rings.allMyNeighbours()
	out := make([]PeerInfo, 0, len(peers))
	for _, p := range peers {
		out = append(out, PeerInfo{ID: p.Id, Addr: p.Addr})
	}
	return out
}

// GossipPartners returns the predecessor and successor on the current gossip ring in O(1)
// and advances the gossip ring index round-robin.
func (ro *RingSuperOverlay) GossipPartners() []PeerInfo {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	peers := ro.rings.myRingNeighbours(ro.currGossipRing)
	ro.currGossipRing = (ro.currGossipRing % ro.rings.numRings) + 1
	out := make([]PeerInfo, 0, len(peers))
	for _, p := range peers {
		out = append(out, PeerInfo{ID: p.Id, Addr: p.Addr})
	}
	return out
}

// IsPredecessor reports whether accuserID is the immediate predecessor of accusedID
// on ringNum within this super-overlay.
func (ro *RingSuperOverlay) IsPredecessor(accusedID, accuserID string, ringNum uint32) bool {
	if accusedID == "" || accuserID == "" || accusedID == accuserID {
		return false
	}
	ro.mu.RLock()
	defer ro.mu.RUnlock()
	if _, ok := ro.present[accusedID]; !ok {
		return false
	}
	if _, ok := ro.present[accuserID]; !ok {
		return false
	}
	return ro.rings.isPredecessor(&Peer{Id: accusedID}, &Peer{Id: accuserID}, ringNum)
}

// IsPredecessorInMemberSet deterministically verifies whether accuserID is the immediate
// predecessor of accusedID on ringNum among the live member set members (S_svc), without
// requiring a materialized RingSuperOverlay on nodes that do not host the service.
func IsPredecessorInMemberSet(members map[string]*Peer, accusedID, accuserID string, ringNum uint32) bool {
	if ringNum == 0 || accusedID == "" || accuserID == "" || accusedID == accuserID {
		return false
	}
	if _, ok := members[accusedID]; !ok {
		return false
	}
	if _, ok := members[accuserID]; !ok {
		return false
	}

	accuserRingID := &ringId{hash: hashId(ringNum, []byte(accuserID))}
	accusedRingID := &ringId{hash: hashId(ringNum, []byte(accusedID))}

	for id := range members {
		if id == accusedID || id == accuserID {
			continue
		}
		candidate := &ringId{hash: hashId(ringNum, []byte(id))}
		if isBetween(accuserRingID, accusedRingID, candidate) {
			return false
		}
	}
	return true
}
