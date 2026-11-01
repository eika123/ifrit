package core

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/joonnna/ifrit/core/discovery"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/spf13/viper"
)

// ErrNilStore indicates that a nil store was provided where an active store is required.
var ErrNilStore = errors.New("store cannot be nil")

// Symbol is aliased from revIdxStore.Symbol.
type Symbol[S any] = revIdxStore.Symbol[S]

// ReverseIndexStore is aliased from revIdxStore.ReverseIndexStore.
type ReverseIndexStore[T any, S Symbol[S]] = revIdxStore.ReverseIndexStore[T, S]

// ReconcilerSession represents an active set reconciliation session between two peers.
type ReconcilerSession[T, S any] interface {
	ProcessIncomingMessage(msg []byte) error
	ProcessIncomingDigests(incoming []S)
	SetResolvedDiffs(localDiff, remoteDiff []S)
	GenerateNextMessage() ([]byte, error)

	Done() bool
	RemoteDigests() []S // Elements the peer has that we need to fetch
	LocalDigests() []S  // Elements we have that the peer is missing
	LocalElements() []T // Elements we have that the peer is missing (resolved from local store)
	DiffDigests() []S   // Union of RemoteDigests() and LocalDigests() (the symmetric difference)
}

// SessionConstructor creates an active reconciliation session backed by a store snapshot/view.
type SessionConstructor[T any, S Symbol[S]] func(store ReverseIndexStore[T, S]) (ReconcilerSession[T, S], error)

// ProtocolDefinition defines a pluggable set reconciliation protocol and provides
// typed session constructors for each control store type.
type ProtocolDefinition struct {
	Name           string
	Description    string
	NewCertSession SessionConstructor[*discovery.Certificate, revIdxStore.DigestSymbol]
	NewNoteSession SessionConstructor[*discovery.Note, revIdxStore.DigestSymbol]
	NewAccSession  SessionConstructor[*discovery.Accusation, revIdxStore.DigestSymbol]
}

var (
	protocolRegistryMu sync.RWMutex
	protocolRegistry   = make(map[string]ProtocolDefinition)
	defaultProtocolMu  sync.RWMutex
	defaultProtocol    = "naive"
)

// RegisterProtocol registers a reconciliation protocol in the global registry.
func RegisterProtocol(def ProtocolDefinition) {
	protocolRegistryMu.Lock()
	defer protocolRegistryMu.Unlock()
	protocolRegistry[strings.ToLower(strings.TrimSpace(def.Name))] = def
}

// GetProtocol retrieves a protocol definition by name.
func GetProtocol(name string) (ProtocolDefinition, bool) {
	protocolRegistryMu.RLock()
	defer protocolRegistryMu.RUnlock()
	p, ok := protocolRegistry[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// AvailableProtocols returns a slice of all registered protocol names.
func AvailableProtocols() []string {
	protocolRegistryMu.RLock()
	defer protocolRegistryMu.RUnlock()
	res := make([]string, 0, len(protocolRegistry))
	for k := range protocolRegistry {
		res = append(res, k)
	}
	return res
}

// DefaultProtocolName returns the default protocol name configured via viper ("reconciliation_strategy")
// or falling back to the package-level default.
func DefaultProtocolName() string {
	if v := viper.GetString("reconciliation_strategy"); strings.TrimSpace(v) != "" {
		return strings.ToLower(strings.TrimSpace(v))
	}
	defaultProtocolMu.RLock()
	defer defaultProtocolMu.RUnlock()
	return defaultProtocol
}

// SetDefaultProtocolName sets the default protocol name.
func SetDefaultProtocolName(name string) {
	defaultProtocolMu.Lock()
	defer defaultProtocolMu.Unlock()
	defaultProtocol = strings.ToLower(strings.TrimSpace(name))
}

// ResolveProtocol resolves a ProtocolDefinition for the given name or falls back to the default protocol.
func ResolveProtocol(name string) ProtocolDefinition {
	if def, ok := GetProtocol(name); ok {
		return def
	}
	defName := DefaultProtocolName()
	if def, ok := GetProtocol(defName); ok {
		return def
	}
	// Fallback in case init() hasn't executed or registry was empty
	return ProtocolDefinition{
		Name:           "naive",
		Description:    "Naive full set exchange",
		NewCertSession: NaiveSessionConstructor[*discovery.Certificate, revIdxStore.DigestSymbol](),
		NewNoteSession: NaiveSessionConstructor[*discovery.Note, revIdxStore.DigestSymbol](),
		NewAccSession:  NaiveSessionConstructor[*discovery.Accusation, revIdxStore.DigestSymbol](),
	}
}

// DefaultSessionConstructor returns the default session constructor for arbitrary store of T and DigestSymbol.
// It resolves the constructor from the configured default protocol (e.g. from viper or package default).
func DefaultSessionConstructor[T any]() SessionConstructor[T, revIdxStore.DigestSymbol] {
	protoName := DefaultProtocolName()
	switch protoName {
	case "riblt", "rateless_iblt":
		return RIBLTSessionConstructor[T]()
	case "naive", "":
		fallthrough
	default:
		return NaiveSessionConstructor[T, revIdxStore.DigestSymbol]()
	}
}

// DiffDigests returns the union of local and remote digests (the symmetric difference).
func DiffDigests[S any](local, remote []S) []S {
	diff := make([]S, 0, len(local)+len(remote))
	diff = append(diff, local...)
	diff = append(diff, remote...)
	return diff
}

// SessionLocalElements resolves elements from the store corresponding to localDiff digests.
func SessionLocalElements[T any, S Symbol[S]](store ReverseIndexStore[T, S], localDiff []S) []T {
	if store == nil || len(localDiff) == 0 {
		return nil
	}
	elems, _ := store.GetByDigests(localDiff)
	return elems
}

// ReconcileStoreWithSession executes a reconciliation round using an existing session.
func ReconcileStoreWithSession[T any, S Symbol[S]](
	session ReconcilerSession[T, S],
	incomingDigests []S,
) (localElements []T, localDigests, remoteDigests []S) {
	if session == nil {
		return nil, nil, nil
	}
	session.ProcessIncomingDigests(incomingDigests)
	return session.LocalElements(), session.LocalDigests(), session.RemoteDigests()
}

// ReconcileStore executes a protocol-agnostic reconciliation round against the given store using
// a session produced by constructor. If constructor is nil, it defaults to DefaultSessionConstructor.
func ReconcileStore[T any, S Symbol[S]](
	constructor SessionConstructor[T, S],
	store ReverseIndexStore[T, S],
	incomingDigests []S,
) (localElements []T, localDigests, remoteDigests []S, err error) {
	if store == nil {
		return nil, nil, nil, ErrNilStore
	}
	if constructor == nil {
		constructor = NaiveSessionConstructor[T, S]()
	}
	session, err := constructor(store)
	if err != nil {
		return nil, nil, nil, err
	}
	localElements, localDigests, remoteDigests = ReconcileStoreWithSession(session, incomingDigests)
	return localElements, localDigests, remoteDigests, nil
}

// SessionState models the lifecycle of a set reconciliation session with a peer.
type SessionState int

const (
	// SessionIdle indicates no active reconciliation or transfer is occurring with the peer.
	SessionIdle SessionState = iota
	// SessionReconciling indicates an inbound or outbound Spread is resolving set diffs.
	SessionReconciling
	// SessionAwaitingStream indicates diffs have been resolved on the responder, awaiting inbound stream.
	SessionAwaitingStream
	// SessionTransferring indicates active bulk data or control item streaming is in flight.
	SessionTransferring
)

func (s SessionState) String() string {
	switch s {
	case SessionIdle:
		return "Idle"
	case SessionReconciling:
		return "Reconciling"
	case SessionAwaitingStream:
		return "AwaitingStream"
	case SessionTransferring:
		return "Transferring"
	default:
		return "Unknown"
	}
}

var (
	ErrSessionBusy       = errors.New("reconciliation session is busy")
	ErrInvalidTransition = errors.New("invalid session state transition")
)

// PeerReconcileSession tracks per-peer reconciliation state across certificates, notes, accusations, and data.
// It is protected by a mutex ensuring only one active reconciliation session per peer pair is in flight.
type PeerReconcileSession struct {
	mu           sync.Mutex
	peerID       string
	state        SessionState
	lastActivity time.Time
	hasDeltas    bool
}

// NewPeerReconcileSession constructs a new session in SessionIdle state for peerID.
func NewPeerReconcileSession(peerID string) *PeerReconcileSession {
	return &PeerReconcileSession{
		peerID:       peerID,
		state:        SessionIdle,
		lastActivity: time.Now(),
	}
}

// PeerID returns the authenticated peer identity for this session.
func (s *PeerReconcileSession) PeerID() string {
	return s.peerID
}

// State returns the current session state.
func (s *PeerReconcileSession) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// TryStartReconciling attempts to atomically transition from SessionIdle to SessionReconciling.
// Returns true if acquired, false if the session is already active.
func (s *PeerReconcileSession) TryStartReconciling() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionIdle {
		return false
	}
	s.state = SessionReconciling
	s.hasDeltas = false
	s.lastActivity = time.Now()
	return true
}

// TryStartInboundReconciling attempts to transition the responder session to SessionReconciling
// upon receiving an inbound Spread RPC. It transitions if the session is SessionIdle or
// SessionAwaitingStream (superseded by a fresh reconciliation round), but returns false if
// actively transferring (SessionTransferring).
func (s *PeerReconcileSession) TryStartInboundReconciling() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == SessionTransferring {
		return false
	}
	s.state = SessionReconciling
	s.hasDeltas = false
	s.lastActivity = time.Now()
	return true
}

// SetHasDeltas manually marks whether the session has pending deltas.
func (s *PeerReconcileSession) SetHasDeltas(hasDeltas bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hasDeltas = hasDeltas
}

// HasDeltas returns true if the session holds non-empty pending deltas.
func (s *PeerReconcileSession) HasDeltas() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasDeltas
}

// TransitionAfterReconcile transitions the session after diff resolution.
// If isCaller is true:
//   - If has deltas -> SessionTransferring (ready to open stream/dispatch egress)
//   - If no deltas  -> SessionIdle
//
// If isCaller is false (Responder):
//   - If has deltas -> SessionAwaitingStream (waiting for caller to open stream)
//   - If no deltas  -> SessionIdle
func (s *PeerReconcileSession) TransitionAfterReconcile(isCaller bool) SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionReconciling {
		return s.state
	}

	if !s.hasDeltas {
		s.state = SessionIdle
	} else if isCaller {
		s.state = SessionTransferring
	} else {
		s.state = SessionAwaitingStream
	}

	s.lastActivity = time.Now()
	return s.state
}

// StartTransfer attempts to transition from SessionAwaitingStream to SessionTransferring
// when the remote peer initiates the authenticated stream.
func (s *PeerReconcileSession) StartTransfer() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionAwaitingStream {
		return ErrInvalidTransition
	}
	s.state = SessionTransferring
	s.lastActivity = time.Now()
	return nil
}

// FinishTransfer resets the session back to SessionIdle upon successful stream completion.
func (s *PeerReconcileSession) FinishTransfer() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = SessionIdle
	s.hasDeltas = false
	s.lastActivity = time.Now()
}

// ResetToIdle forcefully resets the session to SessionIdle (e.g. on RPC error or stale sweep).
func (s *PeerReconcileSession) ResetToIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = SessionIdle
	s.hasDeltas = false
	s.lastActivity = time.Now()
}

// SweepIfStale resets the session to SessionIdle if it has remained in a non-Idle state
// for longer than timeout. Returns true if the session was reset.
func (s *PeerReconcileSession) SweepIfStale(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionIdle && time.Since(s.lastActivity) > timeout {
		s.state = SessionIdle
		s.hasDeltas = false
		s.lastActivity = time.Now()
		return true
	}
	return false
}

// PeerSessionManager manages bounded PeerReconcileSession instances across ring neighbours.
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
