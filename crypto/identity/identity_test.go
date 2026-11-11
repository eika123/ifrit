package identity

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentity_SelfSignedAndPersistence(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "ifrit-identity-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		Identity: pkix.Name{
			Locality: []string{"127.0.0.1:9000", "127.0.0.1:9001"},
		},
		Path: tmpDir,
	}

	id, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, id)

	assert.Equal(t, uint32(32), id.NumRings())
	assert.NotNil(t, id.Certificate())
	assert.NotNil(t, id.Priv())

	// Test signing and verifying
	data := []byte("hello-ifrit-signature")
	r, s, err := id.Sign(data)
	require.NoError(t, err)
	require.NotEmpty(t, r)
	require.NotEmpty(t, s)

	valid := id.Verify(data, r, s, &id.Priv().PublicKey)
	assert.True(t, valid)

	invalid := id.Verify([]byte("corrupt-data"), r, s, &id.Priv().PublicKey)
	assert.False(t, invalid)

	// Test Save
	require.NoError(t, id.SavePrivateKey())
	require.NoError(t, id.SaveCertificate())

	// Verify files exist on disk
	assert.FileExists(t, filepath.Join(tmpDir, "key.pem"))

	// Test Load
	loaded, err := Load(tmpDir, cfg.Identity, "")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, id.NumRings(), loaded.NumRings())
	assert.Equal(t, id.Certificate().Raw, loaded.Certificate().Raw)

	// Verify loaded key signs and validates
	r2, s2, err := loaded.Sign(data)
	require.NoError(t, err)
	assert.True(t, loaded.Verify(data, r2, s2, &loaded.Priv().PublicKey))
}
