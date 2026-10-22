package core

import "encoding/json"

type NaiveSessionFactory[T any, S Symbol[S]] struct{}

func NewNaiveSessionFactory[T any, S Symbol[S]]() *NaiveSessionFactory[T, S] {
	return &NaiveSessionFactory[T, S]{}
}

// NewSession implements SessionFactory[T]
func (f *NaiveSessionFactory[T, S]) NewSession(store ReverseIndexStore[T, S]) ReconcilerSession[T, S] {
	return &NaiveExchangeSession[T, S]{storeDigests: store.Digests()}
}

// Implements the Reconciler interface, @see Reconciler in protocol.go
// performs a naive set reconciliation protocol by sending the entire set
// to resolve differences.
type NaiveExchangeSession[T any, S Symbol[S]] struct {
	storeDigests []S
	done         bool
	remoteDiff   []S
	localDiff    []S
}

func (session *NaiveExchangeSession[T, S]) GenerateNextMessage() ([]byte, error) {
	return json.Marshal(session.storeDigests)
}

func (session *NaiveExchangeSession[T, S]) ProcessIncomingMessage(msg []byte) error {
	var incoming []S
	if err := json.Unmarshal(msg, &incoming); err != nil {
		return err
	}

	if len(incoming) == 0 && len(session.storeDigests) == 0 {
		session.done = true
		return nil
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
	return nil
}

func (session *NaiveExchangeSession[T, S]) Done() bool         { return session.done }
func (session *NaiveExchangeSession[T, S]) RemoteDigests() []S { return session.remoteDiff }
func (session *NaiveExchangeSession[T, S]) LocalDigests() []S  { return session.localDiff }
