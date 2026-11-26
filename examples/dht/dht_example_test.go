package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/eika123/ifrit"
	"github.com/eika123/ifrit/crypto/cauth"
	"github.com/eika123/ifrit/services/dht"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTestCA(t *testing.T) string {
	t.Helper()
	caDir := t.TempDir()
	ca, err := cauth.NewCa(caDir)
	require.NoError(t, err)
	require.NoError(t, ca.NewGroup(3, 5))
	require.NoError(t, ca.SavePrivateKey())
	require.NoError(t, ca.SaveCertificate())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	go ca.Start("127.0.0.1", strconv.Itoa(port))
	t.Cleanup(ca.Shutdown)

	caAddr := fmt.Sprintf("127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		conn, dialErr := net.DialTimeout("tcp", caAddr, 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 3*time.Second, 25*time.Millisecond)
	return caAddr
}

func newTestNode(t *testing.T, caAddr string) (*ifrit.Client, *dht.Service, *httptest.Server) {
	t.Helper()
	c, err := ifrit.NewClient(&ifrit.Config{
		New:                true,
		Hostname:           "127.0.0.1",
		CertPath:           t.TempDir(),
		CAAddr:             caAddr,
		GossipInterval:     150 * time.Millisecond,
		MonitorInterval:    300 * time.Millisecond,
		ViewUpdateInterval: 200 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(c.Stop)

	svc, err := dht.Open(c, "dht")
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	go c.Start()
	require.Eventually(t, func() bool {
		conn, dialErr := net.DialTimeout("tcp", c.Addr(), 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 3*time.Second, 15*time.Millisecond)

	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)
	return c, svc, srv
}

func putItem(t *testing.T, baseURL string, item dht.Item) int {
	t.Helper()
	body, err := json.Marshal(item)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, baseURL+"/dht/items", bytes.NewReader(body))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func getItems(t *testing.T, baseURL, key string) ([]dht.Item, int) {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/dht/items?q=%s", baseURL, key))
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var items []dht.Item
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&items))
	return items, resp.StatusCode
}

func TestDHTExample_HTTPPutGetAndSiblingReplication(t *testing.T) {
	caAddr := startTestCA(t)

	_, _, srvA := newTestNode(t, caAddr)
	_, _, srvB := newTestNode(t, caAddr)

	// Missing key returns 404.
	_, status := getItems(t, srvA.URL, "missing")
	assert.Equal(t, http.StatusNotFound, status)

	// PUT on node A -> replicates via ratelessIBLT -> GET on node B returns it.
	item1 := dht.Item{Key: "greeting", Value: []byte("hello-from-A")}
	assert.Equal(t, http.StatusCreated, putItem(t, srvA.URL, item1))

	require.Eventually(t, func() bool {
		got, code := getItems(t, srvB.URL, "greeting")
		return code == http.StatusOK && len(got) == 1 && string(got[0].Value) == "hello-from-A"
	}, 8*time.Second, 100*time.Millisecond, "node B must receive item1 via service store reconciliation")

	// Conflicting write on node B for the same key -> both nodes converge to both siblings as a JSON array.
	item2 := dht.Item{Key: "greeting", Value: []byte("hello-from-B")}
	assert.Equal(t, http.StatusCreated, putItem(t, srvB.URL, item2))

	require.Eventually(t, func() bool {
		gotA, codeA := getItems(t, srvA.URL, "greeting")
		gotB, codeB := getItems(t, srvB.URL, "greeting")
		return codeA == http.StatusOK && codeB == http.StatusOK && len(gotA) == 2 && len(gotB) == 2
	}, 8*time.Second, 100*time.Millisecond, "both nodes must converge to both sibling items")

	gotA, _ := getItems(t, srvA.URL, "greeting")
	gotB, _ := getItems(t, srvB.URL, "greeting")
	assert.ElementsMatch(t, []dht.Item{item1, item2}, gotA)
	assert.ElementsMatch(t, []dht.Item{item1, item2}, gotB)
}
