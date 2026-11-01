package ifrit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_ItemCodecExport(t *testing.T) {
	codec := DefaultItemCodec[string]()
	require.NotNil(t, codec)

	var buf bytes.Buffer
	err := codec.Encode("test-payload", &buf)
	require.NoError(t, err)

	decoded, err := codec.Decode(&buf)
	require.NoError(t, err)
	assert.Equal(t, "test-payload", decoded)
}

func TestClient_RegisterDataStoreNilClient(t *testing.T) {
	hasher := MustDefaultHasher[string]()
	store, err := NewDigestSet(hasher)
	require.NoError(t, err)

	// Guard against nil client or nil node
	assert.NotPanics(t, func() {
		RegisterDataStore(nil, store)
	})

	assert.NotPanics(t, func() {
		RegisterDataStoreWithCodec(nil, store, DefaultItemCodec[string]())
	})
}

