package ifrit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
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

func TestConfigSearchPaths(t *testing.T) {
	assert.Equal(t, []string{"/var/tmp", "./config", "."}, configSearchPaths(""))
	assert.Equal(t, []string{"/var/tmp", "./config", "."}, configSearchPaths("   "))

	sep := string(filepath.ListSeparator)
	assert.Equal(t, []string{"./config", ".", "/var/tmp"}, configSearchPaths("./config"+sep+"."+sep+"/var/tmp"))
	assert.Equal(t, []string{"./custom", "/opt/ifrit"}, configSearchPaths(" ./custom "+sep+sep+" /opt/ifrit "))
	assert.Equal(t, []string{"/var/tmp", "./config", "."}, configSearchPaths(sep+sep))
}

func TestReadConfig_SearchOrderAndOverride(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dirA, "ifrit_config.yaml"), []byte("ca_addr: \"node-a:8321\"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dirB, "ifrit_config.yaml"), []byte("ca_addr: \"node-b:8321\"\n"), 0644))

	t.Cleanup(viper.Reset)

	viper.Reset()
	t.Setenv("IFRIT_CONFIG", "")
	t.Setenv("IFRIT_CONFIG_PATHS", dirA+string(filepath.ListSeparator)+dirB)
	require.NoError(t, readConfig())
	assert.Equal(t, "node-a:8321", viper.GetString("ca_addr"))

	viper.Reset()
	t.Setenv("IFRIT_CONFIG_PATHS", dirB+string(filepath.ListSeparator)+dirA)
	require.NoError(t, readConfig())
	assert.Equal(t, "node-b:8321", viper.GetString("ca_addr"))

	explicitCfg := filepath.Join(t.TempDir(), "custom.yaml")
	require.NoError(t, os.WriteFile(explicitCfg, []byte("ca_addr: \"explicit:8321\"\n"), 0644))
	viper.Reset()
	t.Setenv("IFRIT_CONFIG", explicitCfg)
	require.NoError(t, readConfig())
	assert.Equal(t, "explicit:8321", viper.GetString("ca_addr"))
}
