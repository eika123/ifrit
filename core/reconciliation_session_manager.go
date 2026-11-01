package core

import (
	"errors"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/core/discovery"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
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

// SessionFactory creates a new reconciliation session backed by a store snapshot/view.
type SessionFactory[T any, S Symbol[S]] interface {
	NewSession(store ReverseIndexStore[T, S]) (ReconcilerSession[T, S], error)
}

// SessionFactoryProvider provides SessionFactory instances for core control stores
// (Certificates, Notes, Accusations).
type SessionFactoryProvider interface {
	CertSessionFactory() SessionFactory[*discovery.Certificate, revIdxStore.DigestSymbol]
	NoteSessionFactory() SessionFactory[*discovery.Note, revIdxStore.DigestSymbol]
	AccusationSessionFactory() SessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol]
}

// NaiveSessionFactoryProvider constructs naive exchange session factories for all control stores.
type NaiveSessionFactoryProvider struct{}

func (NaiveSessionFactoryProvider) CertSessionFactory() SessionFactory[*discovery.Certificate, revIdxStore.DigestSymbol] {
	return NewNaiveSessionFactory[*discovery.Certificate, revIdxStore.DigestSymbol]()
}

func (NaiveSessionFactoryProvider) NoteSessionFactory() SessionFactory[*discovery.Note, revIdxStore.DigestSymbol] {
	return NewNaiveSessionFactory[*discovery.Note, revIdxStore.DigestSymbol]()
}

func (NaiveSessionFactoryProvider) AccusationSessionFactory() SessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol] {
	return NewNaiveSessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol]()
}

// RIBLTSessionFactoryProvider constructs rateless IBLT session factories for all control stores.
type RIBLTSessionFactoryProvider struct{}

func (RIBLTSessionFactoryProvider) CertSessionFactory() SessionFactory[*discovery.Certificate, revIdxStore.DigestSymbol] {
	return NewRIBLTSessionFactory[*discovery.Certificate]()
}

func (RIBLTSessionFactoryProvider) NoteSessionFactory() SessionFactory[*discovery.Note, revIdxStore.DigestSymbol] {
	return NewRIBLTSessionFactory[*discovery.Note]()
}

func (RIBLTSessionFactoryProvider) AccusationSessionFactory() SessionFactory[*discovery.Accusation, revIdxStore.DigestSymbol] {
	return NewRIBLTSessionFactory[*discovery.Accusation]()
}

var (
	defaultSessionFactoryProviderMu sync.RWMutex
	defaultSessionFactoryProvider   SessionFactoryProvider = NaiveSessionFactoryProvider{}
)

// DefaultSessionFactoryProvider returns the current package-level / compile-time default session factory provider.
func DefaultSessionFactoryProvider() SessionFactoryProvider {
	defaultSessionFactoryProviderMu.RLock()
	defer defaultSessionFactoryProviderMu.RUnlock()
	return defaultSessionFactoryProvider
}

// SetDefaultSessionFactoryProvider updates the package-level default session factory provider.
func SetDefaultSessionFactoryProvider(p SessionFactoryProvider) {
	if p == nil {
		return
	}
	defaultSessionFactoryProviderMu.Lock()
	defer defaultSessionFactoryProviderMu.Unlock()
	defaultSessionFactoryProvider = p
}

// DefaultSessionFactory returns a default session factory for generic type T and symbol S.
// By default, it returns a NaiveSessionFactory.
func DefaultSessionFactory[T any, S Symbol[S]]() SessionFactory[T, S] {
	return NewNaiveSessionFactory[T, S]()
}

// SessionFactoryProviderForStrategy resolves a SessionFactoryProvider from a strategy name string
// (e.g. "naive", "riblt", "rateless_iblt"). If unknown or empty, falls back to DefaultSessionFactoryProvider().
func SessionFactoryProviderForStrategy(strategy string) SessionFactoryProvider {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "riblt", "rateless_iblt":
		return RIBLTSessionFactoryProvider{}
	case "naive", "":
		return NaiveSessionFactoryProvider{}
	default:
		log.Warn("Unknown reconciliation strategy, falling back to default provider", "strategy", strategy)
		return DefaultSessionFactoryProvider()
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

// ReconcileStoreWithSession executes a reconciliation round using an existing session produced by factory.
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
// a session produced by factory. If factory is nil, it defaults to NaiveSessionFactory.
func ReconcileStore[T any, S Symbol[S]](
	factory SessionFactory[T, S],
	store ReverseIndexStore[T, S],
	incomingDigests []S,
) (localElements []T, localDigests, remoteDigests []S, err error) {
	if store == nil {
		return nil, nil, nil, ErrNilStore
	}
	if factory == nil {
		factory = DefaultSessionFactory[T, S]()
	}
	session, err := factory.NewSession(store)
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

	certSession ReconcilerSession[*discovery.Certificate, revIdxStore.DigestSymbol]
	noteSession ReconcilerSession[*discovery.Note, revIdxStore.DigestSymbol]
	accSession  ReconcilerSession[*discovery.Accusation, revIdxStore.DigestSymbol]
	dataSession ReconcilerSession[any, revIdxStore.DigestSymbol]
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
	s.lastActivity = time.Now()
	return true
}

// HasDeltas returns true if any initialized set session holds non-empty local or remote deltas.
func (s *PeerReconcileSession) HasDeltas() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.certSession != nil && (len(s.certSession.LocalDigests()) > 0 || len(s.certSession.RemoteDigests()) > 0) {
		return true
	}
	if s.noteSession != nil && (len(s.noteSession.LocalDigests()) > 0 || len(s.noteSession.RemoteDigests()) > 0) {
		return true
	}
	if s.accSession != nil && (len(s.accSession.LocalDigests()) > 0 || len(s.accSession.RemoteDigests()) > 0) {
		return true
	}
	if s.dataSession != nil && (len(s.dataSession.LocalDigests()) > 0 || len(s.dataSession.RemoteDigests()) > 0) {
		return true
	}
	return false
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

	hasDeltas := false
	if s.certSession != nil && (len(s.certSession.LocalDigests()) > 0 || len(s.certSession.RemoteDigests()) > 0) {
		hasDeltas = true
	} else if s.noteSession != nil && (len(s.noteSession.LocalDigests()) > 0 || len(s.noteSession.RemoteDigests()) > 0) {
		hasDeltas = true
	} else if s.accSession != nil && (len(s.accSession.LocalDigests()) > 0 || len(s.accSession.RemoteDigests()) > 0) {
		hasDeltas = true
	} else if s.dataSession != nil && (len(s.dataSession.LocalDigests()) > 0 || len(s.dataSession.RemoteDigests()) > 0) {
		hasDeltas = true
	}

	if !hasDeltas {
		s.state = SessionIdle
		s.resetSessions()
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
	s.resetSessions()
	s.lastActivity = time.Now()
}

// ResetToIdle forcefully resets the session to SessionIdle (e.g. on RPC error or stale sweep).
func (s *PeerReconcileSession) ResetToIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = SessionIdle
	s.resetSessions()
	s.lastActivity = time.Now()
}

// SetCertSession sets the certificate reconciliation session.
func (s *PeerReconcileSession) SetCertSession(sess ReconcilerSession[*discovery.Certificate, revIdxStore.DigestSymbol]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certSession = sess
}

// CertSession returns the active certificate reconciliation session.
func (s *PeerReconcileSession) CertSession() ReconcilerSession[*discovery.Certificate, revIdxStore.DigestSymbol] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.certSession
}

// SetNoteSession sets the note reconciliation session.
func (s *PeerReconcileSession) SetNoteSession(sess ReconcilerSession[*discovery.Note, revIdxStore.DigestSymbol]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noteSession = sess
}

// NoteSession returns the active note reconciliation session.
func (s *PeerReconcileSession) NoteSession() ReconcilerSession[*discovery.Note, revIdxStore.DigestSymbol] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.noteSession
}

// SetAccSession sets the accusation reconciliation session.
func (s *PeerReconcileSession) SetAccSession(sess ReconcilerSession[*discovery.Accusation, revIdxStore.DigestSymbol]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accSession = sess
}

// AccSession returns the active accusation reconciliation session.
func (s *PeerReconcileSession) AccSession() ReconcilerSession[*discovery.Accusation, revIdxStore.DigestSymbol] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accSession
}

// SetDataSession sets the data reconciliation session.
func (s *PeerReconcileSession) SetDataSession(sess ReconcilerSession[any, revIdxStore.DigestSymbol]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataSession = sess
}

// DataSession returns the active data reconciliation session.
func (s *PeerReconcileSession) DataSession() ReconcilerSession[any, revIdxStore.DigestSymbol] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataSession
}

func (s *PeerReconcileSession) resetSessions() {
	s.certSession = nil
	s.noteSession = nil
	s.accSession = nil
	s.dataSession = nil
}

// SweepIfStale resets the session to SessionIdle if it has remained in a non-Idle state
// for longer than timeout. Returns true if the session was reset.
func (s *PeerReconcileSession) SweepIfStale(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionIdle && time.Since(s.lastActivity) > timeout {
		s.state = SessionIdle
		s.resetSessions()
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
