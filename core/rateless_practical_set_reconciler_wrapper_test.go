package core

import (
	"encoding/binary"
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
