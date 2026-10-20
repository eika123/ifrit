package core

import "encoding/json"

type NaiveSessionFactory[T comparable, S Symbol[S]] struct{}

func NewNaiveSessionFactory[T comparable, S Symbol[S]]() *NaiveSessionFactory[T, S] {
	return &NaiveSessionFactory[T, S]{}
}

// NewSession implements SessionFactory[T]
func (f *NaiveSessionFactory[T, S]) NewSession(store ReverseIndexStore[T, S]) ReconcilerSession[T, S] {
	return &NaiveExchangeSession[T, S]{store: store}
}

// Implements the Reconciler interface, @see Reconciler in protocol.go
// performs a naive set reconciliation protocol by sending the entire set
// to resolve differences.
type NaiveExchangeSession[T comparable, S Symbol[S]] struct {
	store  ReverseIndexStore[T, S]
	done   bool
	remote []S
	local  []S
}

func (session *NaiveExchangeSession[T, S]) GenerateNextMessage() ([]byte, error) {
	return json.Marshal(session.store.Digests())
}

func (session *NaiveExchangeSession[T, S]) ProcessIncomingMessage(msg []byte) error {
	var incoming []S
	if err := json.Unmarshal(msg, &incoming); err != nil {
		return err
	}

	// append everythign we don't have locally into the "incomingSet"
	incomingSet := make(map[S]struct{}, len(incoming))
	for _, item := range incoming {
		incomingSet[item] = struct{}{}
		if !session.store.ContainsDigest(item) {
			session.remote = append(session.remote, item)
		}
	}

	// What we have that the peer lacks:
	for _, item := range session.store.Digests() {
		if _, exists := incomingSet[item]; !exists {
			session.local = append(session.local, item)
		}
	}
	session.done = true
	return nil
}

func (session *NaiveExchangeSession[T, S]) Done() bool         { return session.done }
func (session *NaiveExchangeSession[T, S]) RemoteDigests() []S { return session.remote }
func (session *NaiveExchangeSession[T, S]) LocalDigests() []S  { return session.local }
