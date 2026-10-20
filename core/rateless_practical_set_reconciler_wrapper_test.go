package core

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigestSymbol_Reconciliation(t *testing.T) {
	hasher := DefaultHasher[DigestSymbol]()
	aliceStore := NewDigestSet[DigestSymbol, DigestSymbol](hasher)
	bobStore := NewDigestSet[DigestSymbol, DigestSymbol](hasher)

	// Alice has elements 1, 2, 3, 4
	for _, e := range []DigestSymbol{1, 2, 3, 4} {
		aliceStore.AddElement(e)
	}

	// Bob has elements 2, 3, 4, 5 (missing 1, has extra 5)
	for _, e := range []DigestSymbol{2, 3, 4, 5} {
		bobStore.AddElement(e)
	}

	encodeDigest := func(d DigestSymbol) []byte {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(d))
		return buf
	}

	decodeDigest := func(buf []byte) DigestSymbol {
		return DigestSymbol(binary.LittleEndian.Uint64(buf))
	}
	symbolSize := uint32(8)
	sessionFactory := RIBLTSessionFactoryConstructor[DigestSymbol, DigestSymbol](symbolSize, encodeDigest, decodeDigest)
	aliceSession := sessionFactory.NewSession(aliceStore)
	bobSession := sessionFactory.NewSession(bobStore)

	cost := 0
	for !bobSession.Done() {
		msg, err := aliceSession.GenerateNextMessage()
		assert.NoError(t, err)
		cost++

		err = bobSession.ProcessIncomingMessage(msg)
		assert.NoError(t, err)

		if cost > 50 {
			t.Fatalf("Failed to decode within reasonable number of symbols: cost=%d", cost)
		}
	}

	assert.True(t, bobSession.Done())
	assert.ElementsMatch(t, []DigestSymbol{1}, bobSession.RemoteDigests(), "Alice should have 1 exclusive symbol (1)")
	assert.ElementsMatch(t, []DigestSymbol{5}, bobSession.LocalDigests(), "Bob should have 1 exclusive symbol (5)")
}

func TestRIBLTSession_SequentialMutationSnapshotIsolation(t *testing.T) {
	hasher := DefaultHasher[DigestSymbol]()
	aliceStore := NewDigestSet[DigestSymbol, DigestSymbol](hasher)
	bobStore := NewDigestSet[DigestSymbol, DigestSymbol](hasher)

	for _, e := range []DigestSymbol{10, 20, 30} {
		aliceStore.AddElement(e)
		bobStore.AddElement(e)
	}
	aliceStore.AddElement(DigestSymbol(999)) // difference

	encodeDigest := func(d DigestSymbol) []byte {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(d))
		return buf
	}
	decodeDigest := func(buf []byte) DigestSymbol {
		return DigestSymbol(binary.LittleEndian.Uint64(buf))
	}
	sessionFactory := RIBLTSessionFactoryConstructor[DigestSymbol, DigestSymbol](8, encodeDigest, decodeDigest)

	// Create sessions (snapshots taken)
	aliceSession := sessionFactory.NewSession(aliceStore)
	bobSession := sessionFactory.NewSession(bobStore)

	// Mutate the stores AFTER session creation (should not affect active sessions)
	aliceStore.AddElement(DigestSymbol(1001))
	aliceStore.AddElement(DigestSymbol(1002))
	bobStore.AddElement(DigestSymbol(2001))

	// Reconcile
	for !bobSession.Done() {
		msg, err := aliceSession.GenerateNextMessage()
		assert.NoError(t, err)
		err = bobSession.ProcessIncomingMessage(msg)
		assert.NoError(t, err)
	}

	// Should only reflect the snapshot differences (999), not the subsequent additions
	assert.ElementsMatch(t, []DigestSymbol{999}, bobSession.RemoteDigests())
	assert.Empty(t, bobSession.LocalDigests())
}

func TestRIBLTSession_ConcurrentMutationSnapshotIsolation(t *testing.T) {
	hasher := DefaultHasher[DigestSymbol]()
	aliceStore := NewDigestSet[DigestSymbol, DigestSymbol](hasher)
	bobStore := NewDigestSet[DigestSymbol, DigestSymbol](hasher)

	for _, e := range []DigestSymbol{10, 20, 30, 40, 50} {
		aliceStore.AddElement(e)
		bobStore.AddElement(e)
	}
	aliceStore.AddElement(DigestSymbol(999)) // known difference

	encodeDigest := func(d DigestSymbol) []byte {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(d))
		return buf
	}
	decodeDigest := func(buf []byte) DigestSymbol {
		return DigestSymbol(binary.LittleEndian.Uint64(buf))
	}
	sessionFactory := RIBLTSessionFactoryConstructor[DigestSymbol, DigestSymbol](8, encodeDigest, decodeDigest)

	stopWriters := make(chan struct{})
	var wg sync.WaitGroup

	// Concurrently hammer aliceStore with continuous writes while sessions are created and running
	wg.Add(1)
	go func() {
		defer wg.Done()
		val := DigestSymbol(1000)
		for {
			select {
			case <-stopWriters:
				return
			default:
				aliceStore.AddElement(val)
				val++
			}
		}
	}()

	// Concurrently hammer bobStore with continuous writes while sessions are created and running
	wg.Add(1)
	go func() {
		defer wg.Done()
		val := DigestSymbol(2000)
		for {
			select {
			case <-stopWriters:
				return
			default:
				bobStore.AddElement(val)
				val++
			}
		}
	}()

	// While writers are actively writing to both stores, create sessions here to test proper isolation
	// for the sessions
	aliceSession := sessionFactory.NewSession(aliceStore)
	bobSession := sessionFactory.NewSession(bobStore)

	// Perform reconciliation while writes continue in background
	cost := 0
	for !bobSession.Done() {
		msg, err := aliceSession.GenerateNextMessage()
		assert.NoError(t, err)
		cost++

		err = bobSession.ProcessIncomingMessage(msg)
		assert.NoError(t, err)

		if cost > 100 {
			t.Fatalf("Failed to decode within reasonable number of symbols: cost=%d", cost)
		}
	}

	// Stop concurrent writers
	close(stopWriters)
	wg.Wait()

	assert.True(t, bobSession.Done())
	// Alice definitely had 999 in her snapshot which was never added to Bob's store
	assert.Contains(t, bobSession.RemoteDigests(), DigestSymbol(999))
}
