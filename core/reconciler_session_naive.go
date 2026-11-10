package core

import (
	"encoding/json"

	"github.com/joonnna/ifrit/core/discovery"
	"github.com/joonnna/ifrit/crypto/pki"
	"github.com/joonnna/ifrit/digestmaps"
)

type NaiveSessionFactory[T any, S Symbol[S]] struct{}

func NewNaiveSessionFactory[T any, S Symbol[S]]() *NaiveSessionFactory[T, S] {
	return &NaiveSessionFactory[T, S]{}
}

// NaiveSessionConstructor returns a higher-order SessionConstructor closure for NaiveSession.
func NaiveSessionConstructor[T any, S Symbol[S]]() SessionConstructor[T, S] {
	return func(store ReverseIndexStore[T, S]) (ReconcilerSession[T, S], error) {
		return NewNaiveSession(store)
	}
}

func init() {
	RegisterProtocol(ProtocolDefinition{
		Name:           "naive",
		Description:    "Naive full set digest exchange",
		NewCertSession: NaiveSessionConstructor[*pki.Certificate, digestmaps.DigestSymbol](),
		NewNoteSession: NaiveSessionConstructor[*discovery.Note, digestmaps.DigestSymbol](),
		NewAccSession:  NaiveSessionConstructor[*discovery.Accusation, digestmaps.DigestSymbol](),
	})
}

// NewSession implements SessionFactory[T, S]
func (f *NaiveSessionFactory[T, S]) NewSession(store ReverseIndexStore[T, S]) (ReconcilerSession[T, S], error) {
	return NewNaiveSession(store)
}

// NaiveSession implements the ReconcilerSession interface, performing a naive set reconciliation
// protocol by exchanging full digest sets to resolve differences.
type NaiveSession[T any, S Symbol[S]] struct {
	store        ReverseIndexStore[T, S]
	storeDigests []S
	done         bool
	remoteDiff   []S
	localDiff    []S
}

var _ ReconcilerSession[string, DigestSymbol] = (*NaiveSession[string, DigestSymbol])(nil)

// NewNaiveSession creates a new NaiveSession backed by a ReverseIndexStore.
// Returns ErrNilStore if store is nil.
func NewNaiveSession[T any, S Symbol[S]](store ReverseIndexStore[T, S]) (*NaiveSession[T, S], error) {
	if store == nil {
		return nil, ErrNilStore
	}
	return &NaiveSession[T, S]{
		store:        store,
		storeDigests: store.DigestsCopy(),
	}, nil
}

func (session *NaiveSession[T, S]) GenerateNextMessage() ([]byte, error) {
	return json.Marshal(session.storeDigests)
}

func (session *NaiveSession[T, S]) ProcessIncomingDigests(incoming []S) {
	if len(incoming) == 0 && len(session.storeDigests) == 0 {
		session.done = true
		return
	}

	// Single map: tracks which of our local digests were seen in the remote message.
	localSeen := make(map[S]bool, len(session.storeDigests))
	for _, item := range session.storeDigests {
		localSeen[item] = false
	}

	// Items remote has that we lack --> remoteDiff
	// Single pass over incoming:
	// - If we have it: mark as seen
	// - If we don't: remote has it, we lack it -> remoteDiff
	for _, item := range incoming {
		if _, exists := localSeen[item]; exists {
			localSeen[item] = true
		} else {
			session.remoteDiff = append(session.remoteDiff, item)
		}
	}

	// Items we have that were never seen in incoming -> localDiff
	for _, item := range session.storeDigests {
		if !localSeen[item] {
			session.localDiff = append(session.localDiff, item)
		}
	}

	session.done = true
}

// SetResolvedDiffs directly sets the resolved local and remote diffs (e.g. on the caller side
// when receiving differential digests in StateResponse) and marks the session as done.
func (session *NaiveSession[T, S]) SetResolvedDiffs(localDiff, remoteDiff []S) {
	session.localDiff = localDiff
	session.remoteDiff = remoteDiff
	session.done = true
}

func (session *NaiveSession[T, S]) ProcessIncomingMessage(msg []byte) error {
	var incoming []S
	if err := json.Unmarshal(msg, &incoming); err != nil {
		return err
	}

	session.ProcessIncomingDigests(incoming)
	return nil
}

func (session *NaiveSession[T, S]) Done() bool         { return session.done }
func (session *NaiveSession[T, S]) RemoteDigests() []S { return session.remoteDiff }
func (session *NaiveSession[T, S]) LocalDigests() []S  { return session.localDiff }

// DiffDigests returns the union of RemoteDigests and LocalDigests (the symmetric difference).
func (session *NaiveSession[T, S]) DiffDigests() []S {
	return DiffDigests(session.localDiff, session.remoteDiff)
}

// LocalElements returns the local elements from the underlying store corresponding to LocalDigests.
func (session *NaiveSession[T, S]) LocalElements() []T {
	return SessionLocalElements(session.store, session.localDiff)
}
