package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joonnna/ifrit/crypto/cauth"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestCA(t *testing.T) (string, func()) {
	t.Helper()

	caDir, err := os.MkdirTemp("", "ifrit-http-ca-test-*")
	require.NoError(t, err)

	ca, err := cauth.NewCa(caDir)
	require.NoError(t, err)

	err = ca.NewGroup(3, 5)
	require.NoError(t, err)

	require.NoError(t, ca.SavePrivateKey())
	require.NoError(t, ca.SaveCertificate())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	caPort := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	go ca.Start("127.0.0.1", strconv.Itoa(caPort))

	caAddr := fmt.Sprintf("127.0.0.1:%d", caPort)

	// Wait for CA HTTP listener to become ready
	caReady := false
	for i := 0; i < 50; i++ {
		conn, dialErr := net.DialTimeout("tcp", caAddr, 100*time.Millisecond)
		if dialErr == nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("failed to close test conn: %v", closeErr)
			}
			caReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.True(t, caReady, "test CA failed to start")

	cleanup := func() {
		ca.Shutdown()
		if rmErr := os.RemoveAll(caDir); rmErr != nil {
			t.Logf("cleanup error: %v", rmErr)
		}
	}

	return caAddr, cleanup
}

func waitForNodeHealth(t *testing.T, nodeAddr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	url := nodeAddr
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	url = fmt.Sprintf("%s/health", strings.TrimRight(url, "/"))

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Logf("close resp body: %v", closeErr)
			}
			return
		}
		if resp != nil && resp.Body != nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Logf("close resp body: %v", closeErr)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("node %s did not become healthy within %v", nodeAddr, timeout)
}

func TestHTTPDissemination_PythonDriver(t *testing.T) {
	pythonBin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available on PATH; skipping python driver test")
	}

	caAddr, caCleanup := setupTestCA(t)
	defer caCleanup()

	// Global config setup for ifrit clients in this process
	testCfgDir, err := os.MkdirTemp("", "ifrit-test-cfg-*")
	require.NoError(t, err)
	defer func() {
		if rmErr := os.RemoveAll(testCfgDir); rmErr != nil {
			t.Logf("cleanup cfg dir: %v", rmErr)
		}
	}()

	cfgFile := filepath.Join(testCfgDir, "ifrit_config.yaml")
	cfgContent := fmt.Sprintf("ca_addr: %q\ngossip_interval: 1\n", caAddr)
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfgContent), 0644))
	t.Setenv("IFRIT_CONFIG", cfgFile)
	viper.Set("ca_addr", caAddr)
	viper.Set("gossip_interval", 1)

	// Spin up 3 HTTP nodes
	numNodes := 3
	apps := make([]*App, numNodes)
	nodeURLs := make([]string, numNodes)

	for i := 0; i < numNodes; i++ {
		cryptoDir, mkErr := os.MkdirTemp("", fmt.Sprintf("ifrit-node-%d-crypto-*", i))
		require.NoError(t, mkErr)

		app, appErr := NewApp(&AppConfig{
			HTTPPort:       0,
			TCPPort:        0,
			UDPPort:        0,
			Hostname:       "localhost",
			CaAddr:         caAddr,
			CertPath:       cryptoDir,
			GossipInterval: 1,
			NewCrypto:      true,
		})
		require.NoError(t, appErr)
		app.Start()

		apps[i] = app
		nodeURLs[i] = app.HTTPAddr()
	}

	defer func() {
		for _, a := range apps {
			a.Stop()
		}
	}()

	// Wait for all nodes to be healthy
	for _, u := range nodeURLs {
		waitForNodeHealth(t, u, 5*time.Second)
	}

	// Execute python test driver
	scriptPath := filepath.Join(".", "test_dissemination.py")
	cmd := exec.Command(
		pythonBin,
		scriptPath,
		"--nodes", strings.Join(nodeURLs, ","),
		"--items", "2",
		"--timeout", "20",
	)

	out, err := cmd.CombinedOutput()
	t.Logf("Python Driver Output:\n%s", string(out))
	require.NoError(t, err, "Python dissemination test must pass")
}

func TestHTTPDissemination_GoClient(t *testing.T) {
	caAddr, caCleanup := setupTestCA(t)
	defer caCleanup()

	testCfgDir, err := os.MkdirTemp("", "ifrit-test-cfg-go-*")
	require.NoError(t, err)
	defer func() {
		if rmErr := os.RemoveAll(testCfgDir); rmErr != nil {
			t.Logf("cleanup cfg dir: %v", rmErr)
		}
	}()

	cfgFile := filepath.Join(testCfgDir, "ifrit_config.yaml")
	cfgContent := fmt.Sprintf("ca_addr: %q\ngossip_interval: 1\n", caAddr)
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfgContent), 0644))
	t.Setenv("IFRIT_CONFIG", cfgFile)
	viper.Set("ca_addr", caAddr)
	viper.Set("gossip_interval", 1)

	// Launch 2 nodes
	apps := make([]*App, 2)
	nodeURLs := make([]string, 2)
	for i := 0; i < 2; i++ {
		cryptoDir, mkErr := os.MkdirTemp("", fmt.Sprintf("ifrit-go-node-%d-crypto-*", i))
		require.NoError(t, mkErr)

		app, appErr := NewApp(&AppConfig{
			HTTPPort:       0,
			TCPPort:        0,
			UDPPort:        0,
			Hostname:       "localhost",
			CaAddr:         caAddr,
			CertPath:       cryptoDir,
			GossipInterval: 1,
			NewCrypto:      true,
		})
		require.NoError(t, appErr)
		app.Start()

		apps[i] = app
		nodeURLs[i] = app.HTTPAddr()
	}
	defer func() {
		for _, a := range apps {
			a.Stop()
		}
	}()

	for _, u := range nodeURLs {
		waitForNodeHealth(t, u, 5*time.Second)
	}

	httpClient := &http.Client{Timeout: 3 * time.Second}

	// 1. POST item1 to Node 0
	item1 := "uuid-from-node-0"
	body1, err := json.Marshal(map[string]string{"item": item1})
	require.NoError(t, err)
	resp1, err := httpClient.Post(fmt.Sprintf("http://%s/items", nodeURLs[0]), "application/json", bytes.NewReader(body1))
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	require.NoError(t, resp1.Body.Close())

	// 2. POST item2 to Node 1
	item2 := "uuid-from-node-1"
	body2, err := json.Marshal(map[string]string{"item": item2})
	require.NoError(t, err)
	resp2, err := httpClient.Post(fmt.Sprintf("http://%s/items", nodeURLs[1]), "application/json", bytes.NewReader(body2))
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	require.NoError(t, resp2.Body.Close())

	// 3. Wait for both nodes to contain both items
	require.Eventually(t, func() bool {
		for _, u := range nodeURLs {
			r, getErr := httpClient.Get(fmt.Sprintf("http://%s/items", u))
			if getErr != nil {
				return false
			}
			var itemsResp ItemsResponse
			decodeErr := json.NewDecoder(r.Body).Decode(&itemsResp)
			if closeErr := r.Body.Close(); closeErr != nil {
				return false
			}
			if decodeErr != nil {
				return false
			}
			if itemsResp.Count < 2 {
				return false
			}
			hasItem1 := false
			hasItem2 := false
			for _, it := range itemsResp.Items {
				if it == item1 {
					hasItem1 = true
				}
				if it == item2 {
					hasItem2 = true
				}
			}
			if !hasItem1 || !hasItem2 {
				return false
			}
		}
		return true
	}, 15*time.Second, 200*time.Millisecond, "both nodes must converge on both items")
}
