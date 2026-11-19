package core

import (
	"errors"
	"sync"
)

// ErrSessionBusy indicates an inbound reconciliation request was rejected because the
// local peer holds tie-breaker priority on an active outbound session with the caller.
var ErrSessionBusy = errors.New("reconcile: session is busy")

type peerGateEntry struct {
	outbound bool
	inbound  int
}

// PeerGate guards per-peer outbound and inbound reconciliation concurrency using a
// deterministic lower-ID crossed-wires tie-breaker and automatically prunes idle entries.
type PeerGate struct {
	mu    sync.Mutex
	peers map[string]*peerGateEntry
}

// NewPeerGate constructs an empty PeerGate.
func NewPeerGate() *PeerGate {
	return &PeerGate{
		peers: make(map[string]*peerGateEntry),
	}
}

// Responsibility of caller to lock before calling
func (g *PeerGate) getOrCreateLocked(peerID string) *peerGateEntry {
	e, ok := g.peers[peerID]
	if !ok {
		e = &peerGateEntry{}
		g.peers[peerID] = e
	}
	return e
}

// Responsibility of caller to lock before calling
func (g *PeerGate) pruneIfIdleLocked(peerID string, e *peerGateEntry) {
	if !e.outbound && e.inbound == 0 {
		delete(g.peers, peerID)
	}
}

// TryStartOutbound acquires the outbound slot for peerID if no outbound or inbound
// reconciliation is currently active for that peer.
func (g *PeerGate) TryStartOutbound(peerID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if e, ok := g.peers[peerID]; ok && (e.outbound || e.inbound > 0) {
		return false
	}
	e := g.getOrCreateLocked(peerID)
	e.outbound = true
	return true
}

// ReleaseOutbound releases the outbound slot for peerID and prunes the entry if idle.
func (g *PeerGate) ReleaseOutbound(peerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.peers[peerID]
	if !ok {
		return
	}
	e.outbound = false
	g.pruneIfIdleLocked(peerID, e)
}

// TryStartInbound admits an inbound reconciliation stream from remoteID using the
// deterministic crossed-wires tie-breaker:
//   - If inbound streams from remoteID are already active, increments the refcount.
//   - If an outbound session to remoteID is active and remoteID >= selfID, self holds
//     priority and returns ErrSessionBusy.
//   - If an outbound session to remoteID is active and remoteID < selfID, remote wins
//     and inbound is admitted while outbound remains marked until its goroutine exits.
func (g *PeerGate) TryStartInbound(selfID, remoteID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	e := g.getOrCreateLocked(remoteID)
	if e.inbound > 0 {
		e.inbound++
		return nil
	}
	if e.outbound && remoteID >= selfID {
		return ErrSessionBusy
	}
	e.inbound++
	return nil
}

// ReleaseInbound decrements the active inbound stream count for peerID and prunes if idle.
func (g *PeerGate) ReleaseInbound(peerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.peers[peerID]
	if !ok {
		return
	}
	if e.inbound > 0 {
		e.inbound--
	}
	g.pruneIfIdleLocked(peerID, e)
}

// IsIdle reports whether peerID currently has no active outbound or inbound reconciliation.
func (g *PeerGate) IsIdle(peerID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.peers[peerID]
	return !ok || (!e.outbound && e.inbound == 0)
}

// Len returns the number of peers with active reconciliation entries.
func (g *PeerGate) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.peers)
}
