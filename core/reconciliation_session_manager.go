package core

import (
	"errors"
	"sync"
	"time"
)

// ErrSessionBusy indicates an inbound reconciliation request was rejected because the
// local peer holds tie-breaker priority on an active session with the caller.
var ErrSessionBusy = errors.New("reconcile: session is busy")

// SessionState represents the concurrency-gating state of a per-peer reconciliation session.
type SessionState int

const (
	// SessionIdle indicates no active reconciliation session with the peer.
	SessionIdle SessionState = iota
	// SessionOutboundReconciling indicates an outbound reconciliation round is in flight for the peer.
	SessionOutboundReconciling
	// SessionInboundReconciling indicates one or more inbound reconciliation streams from the peer are active.
	SessionInboundReconciling
)

// String returns a human-readable label for SessionState.
func (s SessionState) String() string {
	switch s {
	case SessionIdle:
		return "Idle"
	case SessionOutboundReconciling:
		return "OutboundReconciling"
	case SessionInboundReconciling:
		return "InboundReconciling"
	default:
		return "Unknown"
	}
}

// PeerReconcileSession guards outbound and inbound reconciliation concurrency per peer using
// a monotonic generation counter so stale goroutines never reset newer sessions.
type PeerReconcileSession struct {
	mu            sync.Mutex
	peerID        string
	state         SessionState
	seq           uint64
	inboundActive int
	lastActivity  time.Time
}

// NewPeerReconcileSession constructs a new session in SessionIdle state for peerID.
func NewPeerReconcileSession(peerID string) *PeerReconcileSession {
	return &PeerReconcileSession{
		peerID:       peerID,
		state:        SessionIdle,
		lastActivity: time.Now(),
	}
}

// PeerID returns the peer identity for this session.
func (s *PeerReconcileSession) PeerID() string {
	return s.peerID
}

// State returns the current session state.
func (s *PeerReconcileSession) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Seq returns the current generation sequence number of this session.
func (s *PeerReconcileSession) Seq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// TryStartOutboundReconciling attempts to transition from SessionIdle to SessionOutboundReconciling.
// Returns the new generation sequence number and true if acquired, or (0, false) if busy.
func (s *PeerReconcileSession) TryStartOutboundReconciling() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionIdle {
		return 0, false
	}
	s.seq++
	s.state = SessionOutboundReconciling
	s.inboundActive = 0
	s.lastActivity = time.Now()
	return s.seq, true
}

// TryStartInboundReconciling admits an inbound reconciliation stream from remoteID using a
// deterministic crossed-wires tie-breaker:
//   - If already SessionInboundReconciling: increments the active sub-store stream refcount
//     and returns the current generation sequence number.
//   - If SessionOutboundReconciling and remoteID < selfID: higher peer yields priority,
//     increments seq, transitions to SessionInboundReconciling (inboundActive = 1), and accepts.
//   - If SessionOutboundReconciling and selfID <= remoteID: local peer holds priority and returns
//     (0, false, ErrSessionBusy).
//   - If SessionIdle: increments seq, transitions to SessionInboundReconciling (inboundActive = 1).
func (s *PeerReconcileSession) TryStartInboundReconciling(selfID, remoteID string) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case SessionInboundReconciling:
		s.inboundActive++
		s.lastActivity = time.Now()
		return s.seq, true, nil
	case SessionOutboundReconciling:
		if remoteID >= selfID {
			return 0, false, ErrSessionBusy
		}
		s.seq++
		s.state = SessionInboundReconciling
		s.inboundActive = 1
		s.lastActivity = time.Now()
		return s.seq, true, nil
	default:
		s.seq++
		s.state = SessionInboundReconciling
		s.inboundActive = 1
		s.lastActivity = time.Now()
		return s.seq, true, nil
	}
}

// ReleaseInbound decrements the active inbound stream count for generation seq and
// returns to SessionIdle once all concurrent inbound sub-store streams complete.
// Returns false if seq is stale or the session is not in SessionInboundReconciling.
func (s *PeerReconcileSession) ReleaseInbound(seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seq != seq || s.state != SessionInboundReconciling {
		return false
	}
	if s.inboundActive > 0 {
		s.inboundActive--
	}
	if s.inboundActive == 0 {
		s.state = SessionIdle
	}
	s.lastActivity = time.Now()
	return true
}

// ResetIfSeq resets the session to SessionIdle if seq matches the current generation.
// Returns true if reset, false if seq is stale (superseded).
func (s *PeerReconcileSession) ResetIfSeq(seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seq != seq {
		return false
	}
	s.state = SessionIdle
	s.inboundActive = 0
	s.lastActivity = time.Now()
	return true
}

// ResetToIdle forcefully resets the session to SessionIdle.
func (s *PeerReconcileSession) ResetToIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	s.state = SessionIdle
	s.inboundActive = 0
	s.lastActivity = time.Now()
}

// SweepIfStale resets the session to SessionIdle if it has remained in a non-Idle state
// for longer than timeout. Returns true if the session was reset.
func (s *PeerReconcileSession) SweepIfStale(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionIdle && time.Since(s.lastActivity) > timeout {
		s.seq++
		s.state = SessionIdle
		s.inboundActive = 0
		s.lastActivity = time.Now()
		return true
	}
	return false
}

// PeerSessionManager manages PeerReconcileSession instances across ring neighbours.
type PeerSessionManager struct {
	mu           sync.RWMutex
	sessions     map[string]*PeerReconcileSession
	staleTimeout time.Duration
}

// NewPeerSessionManager constructs a session manager with the given stale session timeout.
// If staleTimeout <= 0, a default of 30 seconds is used.
func NewPeerSessionManager(staleTimeout time.Duration) *PeerSessionManager {
	if staleTimeout <= 0 {
		staleTimeout = 30 * time.Second
	}
	return &PeerSessionManager{
		sessions:     make(map[string]*PeerReconcileSession),
		staleTimeout: staleTimeout,
	}
}

// GetOrCreate returns the session for peerID, creating it in SessionIdle state if absent.
func (m *PeerSessionManager) GetOrCreate(peerID string) *PeerReconcileSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, exists := m.sessions[peerID]; exists {
		return s
	}
	s := NewPeerReconcileSession(peerID)
	m.sessions[peerID] = s
	return s
}

// Get returns the session for peerID if present, or nil.
func (m *PeerSessionManager) Get(peerID string) *PeerReconcileSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[peerID]
}

// SweepStaleSessions iterates over all sessions and resets any that have exceeded staleTimeout.
func (m *PeerSessionManager) SweepStaleSessions() int {
	m.mu.RLock()
	sessions := make([]*PeerReconcileSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()

	swept := 0
	for _, s := range sessions {
		if s.SweepIfStale(m.staleTimeout) {
			swept++
		}
	}
	return swept
}
