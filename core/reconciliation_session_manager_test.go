package core

import (
	"sync"
	"testing"
	"time"

	"github.com/joonnna/ifrit/core/discovery"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerReconcileSession_LifecycleAndConcurrency(t *testing.T) {
	s := NewPeerReconcileSession("peer-1")
	assert.Equal(t, "peer-1", s.PeerID())
	assert.Equal(t, SessionIdle, s.State())

	// Cannot transition directly to transferring from idle
	err := s.StartTransfer()
	assert.ErrorIs(t, err, ErrInvalidTransition)

	// TryStartReconciling
	assert.True(t, s.TryStartReconciling())
	assert.Equal(t, SessionReconciling, s.State())

	// Mutual exclusion: simultaneous initiation attempt returns false
	assert.False(t, s.TryStartReconciling())

	// Transition without deltas -> returns to Idle
	nextState := s.TransitionAfterReconcile(true)
	assert.Equal(t, SessionIdle, nextState)
	assert.Equal(t, SessionIdle, s.State())

	// Reconcile with deltas as Caller
	assert.True(t, s.TryStartReconciling())
	noteStore, err := revIdxStore.NewDigestSet[*discovery.Note, revIdxStore.DigestSymbol](revIdxStore.DefaultHasher[*discovery.Note]())
	require.NoError(t, err)
	noteSess, err := NewNaiveSession(noteStore)
	require.NoError(t, err)
	noteSess.SetResolvedDiffs([]revIdxStore.DigestSymbol{100}, []revIdxStore.DigestSymbol{200})
	s.SetNoteSession(noteSess)

	assert.True(t, s.HasDeltas())
	nextState = s.TransitionAfterReconcile(true) // caller
	assert.Equal(t, SessionTransferring, nextState)
	assert.Equal(t, SessionTransferring, s.State())

	// FinishTransfer returns to Idle
	s.FinishTransfer()
	assert.Equal(t, SessionIdle, s.State())
	assert.Nil(t, s.NoteSession())

	// Reconcile with deltas as Responder
	assert.True(t, s.TryStartReconciling())
	s.SetNoteSession(noteSess)
	nextState = s.TransitionAfterReconcile(false) // responder
	assert.Equal(t, SessionAwaitingStream, nextState)
	assert.Equal(t, SessionAwaitingStream, s.State())

	// Remote peer opens stream -> transitions to Transferring
	err = s.StartTransfer()
	require.NoError(t, err)
	assert.Equal(t, SessionTransferring, s.State())

	s.FinishTransfer()
	assert.Equal(t, SessionIdle, s.State())
}

func TestPeerReconcileSession_ConcurrentAcquisitionRace(t *testing.T) {
	s := NewPeerReconcileSession("peer-2")

	const numGoroutines = 50
	var wg sync.WaitGroup
	acquiredCount := 0
	var mu sync.Mutex

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if s.TryStartReconciling() {
				mu.Lock()
				acquiredCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly one goroutine should win the race
	assert.Equal(t, 1, acquiredCount)
	assert.Equal(t, SessionReconciling, s.State())
}

func TestPeerSessionManager_StaleSweep(t *testing.T) {
	mgr := NewPeerSessionManager(50 * time.Millisecond)

	s1 := mgr.GetOrCreate("peer-a")
	s2 := mgr.GetOrCreate("peer-b")

	assert.True(t, s1.TryStartReconciling())
	assert.True(t, s2.TryStartReconciling())

	// S1 finishes normally
	s1.TransitionAfterReconcile(true)
	assert.Equal(t, SessionIdle, s1.State())

	// S2 gets stuck in Reconciling
	time.Sleep(70 * time.Millisecond)

	swept := mgr.SweepStaleSessions()
	assert.Equal(t, 1, swept)
	assert.Equal(t, SessionIdle, s2.State())
}

func TestSessionFactoryProvider_DefaultsAndStrategies(t *testing.T) {
	// Verify compile-time default is NaiveSessionFactoryProvider
	defaultProv := DefaultSessionFactoryProvider()
	require.NotNil(t, defaultProv)
	_, isNaive := defaultProv.(NaiveSessionFactoryProvider)
	assert.True(t, isNaive, "DefaultSessionFactoryProvider must default to NaiveSessionFactoryProvider")

	assert.NotNil(t, defaultProv.CertSessionFactory())
	assert.NotNil(t, defaultProv.NoteSessionFactory())
	assert.NotNil(t, defaultProv.AccusationSessionFactory())

	// Strategy lookup
	naiveProv := SessionFactoryProviderForStrategy("naive")
	_, isNaive = naiveProv.(NaiveSessionFactoryProvider)
	assert.True(t, isNaive)

	ribltProv := SessionFactoryProviderForStrategy("riblt")
	_, isRIBLT := ribltProv.(RIBLTSessionFactoryProvider)
	assert.True(t, isRIBLT)

	assert.NotNil(t, ribltProv.CertSessionFactory())
	assert.NotNil(t, ribltProv.NoteSessionFactory())
	assert.NotNil(t, ribltProv.AccusationSessionFactory())

	// Default factory for generic T
	genericFactory := DefaultSessionFactory[string, revIdxStore.DigestSymbol]()
	require.NotNil(t, genericFactory)

	// SetDefaultSessionFactoryProvider
	orig := DefaultSessionFactoryProvider()
	defer SetDefaultSessionFactoryProvider(orig)

	SetDefaultSessionFactoryProvider(RIBLTSessionFactoryProvider{})
	_, isRIBLT = DefaultSessionFactoryProvider().(RIBLTSessionFactoryProvider)
	assert.True(t, isRIBLT)
}

func TestNode_StartupReconciliationConfiguration(t *testing.T) {
	priv, err := genKeys()
	require.NoError(t, err)
	cert := genCert(priv, 1)

	// Default node uses factories initialized at startup from config/default
	n, err := NewNode(&commStub{}, &pingStub{}, &cmStub{cert: cert}, &cryptoStub{priv: priv})
	require.NoError(t, err)
	defer n.Stop()

	require.NotNil(t, n.getCertSessionFactory())
	require.NotNil(t, n.getNoteSessionFactory())
	require.NotNil(t, n.getAccusationSessionFactory())
	require.NotNil(t, n.SessionManager())
}
