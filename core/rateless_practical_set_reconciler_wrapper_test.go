package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigestSymbol_Reconciliation(t *testing.T) {
	aliceStore := NewRIBLTReconciler[DigestSymbol]()
	bobStore := NewRIBLTReconciler[DigestSymbol]()

	// Alice has elements 1, 2, 3, 4
	aliceElements := []DigestSymbol{1, 2, 3, 4}
	for _, e := range aliceElements {
		aliceStore.AddElement(e)
	}

	// Bob has elements 2, 3, 4, 5 (missing 1, has extra 5)
	bobElements := []DigestSymbol{2, 3, 4, 5}
	for _, e := range bobElements {
		bobStore.AddElement(e)
	}

	enc := aliceStore.NewEncoder()
	dec := bobStore.NewDecoder()

	cost := 0
	for {
		sym := enc.ProduceNextCodedSymbol()
		cost++

		dec.AddCodedSymbol(sym)
		dec.TryDecode()
		if dec.Decoded() {
			break
		}
		if cost > 50 {
			t.Fatalf("Failed to decode within reasonable number of symbols: cost=%d", cost)
		}
	}

	assert.True(t, dec.Decoded())
	assert.Equal(t, 1, len(dec.Remote()), "Alice should have 1 exclusive symbol")
	assert.Equal(t, DigestSymbol(1), dec.Remote()[0].Symbol)

	assert.Equal(t, 1, len(dec.Local()), "Bob should have 1 exclusive symbol")
	assert.Equal(t, DigestSymbol(5), dec.Local()[0].Symbol)
}
