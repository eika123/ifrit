package dht

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	"github.com/eika123/ifrit/services"
)

// Item is a replicated key-value entry stored in the DHT.
type Item = digestmaps.Item[string, []byte]

func hashItem(item Item) digestmaps.DigestSymbol {
	h := sha256.New()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(item.Key)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(item.Key))
	_, _ = h.Write(item.Value)
	sum := h.Sum(nil)
	return digestmaps.DigestSymbol(binary.BigEndian.Uint64(sum[:8]))
}

// Service is a replicated DHT service running on top of an Ifrit services.Endpoint,
// owning its replicated store(s) directly.
type Service struct {
	*services.Endpoint
	items *ratelessIBLT.KeyedReconcilableStore[string, []byte]
}
