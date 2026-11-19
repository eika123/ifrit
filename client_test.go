package ifrit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_ItemCodecExport(t *testing.T) {
	codec := DefaultItemCodec[string]()
	require.NotNil(t, codec)

	encoded, err := codec.Encode("test-payload")
	require.NoError(t, err)

	decoded, err := codec.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, "test-payload", decoded)
}

func TestClient_RegisterDataStoreNilClient(t *testing.T) {
	hasher := MustDefaultHasher[string]()
	store, err := NewReconcilableStore(hasher)
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

func TestResolveConfig_SearchOrderAndOverride(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dirA, "ifrit_config.yaml"), []byte("ca_addr: \"node-a:8321\"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dirB, "ifrit_config.yaml"), []byte("ca_addr: \"node-b:8321\"\n"), 0644))

	t.Setenv("IFRIT_CONFIG", "")
	t.Setenv("IFRIT_CONFIG_PATHS", dirA+string(filepath.ListSeparator)+dirB)
	res, err := resolveConfig(&Config{})
	require.NoError(t, err)
	assert.Equal(t, "node-a:8321", res.caAddr)

	t.Setenv("IFRIT_CONFIG_PATHS", dirB+string(filepath.ListSeparator)+dirA)
	res, err = resolveConfig(&Config{})
	require.NoError(t, err)
	assert.Equal(t, "node-b:8321", res.caAddr)

	explicitCfg := filepath.Join(t.TempDir(), "custom.yaml")
	require.NoError(t, os.WriteFile(explicitCfg, []byte("ca_addr: \"explicit:8321\"\n"), 0644))
	t.Setenv("IFRIT_CONFIG", explicitCfg)
	res, err = resolveConfig(&Config{})
	require.NoError(t, err)
	assert.Equal(t, "explicit:8321", res.caAddr)

	// Explicit Config.CAAddr overrides YAML file.
	res, err = resolveConfig(&Config{CAAddr: "programmatic:9999"})
	require.NoError(t, err)
	assert.Equal(t, "programmatic:9999", res.caAddr)
}

func TestResolveConfig_PureGoWithoutYAML(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("IFRIT_CONFIG", "")
	t.Setenv("IFRIT_CONFIG_PATHS", emptyDir)

	// Without YAML and without CAAddr, resolveConfig returns an error.
	_, err := resolveConfig(&Config{})
	require.Error(t, err)

	// With CAAddr set directly on Config, no YAML file is required.
	noComp := false
	res, err := resolveConfig(&Config{
		CAAddr:                 "127.0.0.1:8321",
		GossipInterval:         3 * time.Second,
		ReconciliationStrategy: "naive",
		UseCompression:         &noComp,
	})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8321", res.caAddr)
	assert.Equal(t, 3*time.Second, res.nodeOpts.GossipInterval)
	assert.Equal(t, "naive", res.nodeOpts.ReconciliationStrategy)
	assert.False(t, res.useCompression)
}
