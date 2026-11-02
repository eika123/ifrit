package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit"
	"github.com/spf13/viper"
)

// AppConfig contains configuration parameters for the HTTP dissemination node.
type AppConfig struct {
	HTTPPort       int
	TCPPort        int
	UDPPort        int
	Hostname       string
	CaAddr         string
	CryptoUnitPath string
	GossipInterval int
	NewCrypto      bool
}

// HealthResponse represents the response structure for /health.
type HealthResponse struct {
	Status      string `json:"status"`
	StoreSize   int    `json:"store_size"`
	Fingerprint string `json:"fingerprint"`
}

// ItemsResponse represents the response structure for GET /items.
type ItemsResponse struct {
	Items       []string `json:"items"`
	Count       int      `json:"count"`
	Fingerprint string   `json:"fingerprint"`
}

// PostItemResponse represents the response structure for POST /items.
type PostItemResponse struct {
	Status      string `json:"status"`
	Item        string `json:"item"`
	IsNew       bool   `json:"is_new"`
	StoreSize   int    `json:"store_size"`
	Fingerprint string `json:"fingerprint"`
}

// App represents an HTTP dissemination node sitting on top of an Ifrit client
// and a convergent ReverseIndexStore.
type App struct {
	config       *AppConfig
	ifritClient  *ifrit.Client
	store        ifrit.ReverseIndexStore[string]
	httpListener net.Listener
	httpServer   *http.Server
	httpAddr     string
	stopOnce     sync.Once
	cleanupDirs  []string
}

// NewApp initializes an App instance, creates the backing ReverseIndexStore,
// and binds the HTTP listener.
func NewApp(cfg *AppConfig) (*App, error) {
	if cfg == nil {
		return nil, errors.New("app config cannot be nil")
	}

	var cleanupDirs []string

	if cfg.CaAddr != "" {
		viper.Set("ca_addr", cfg.CaAddr)
	}
	if cfg.GossipInterval > 0 {
		viper.Set("gossip_interval", cfg.GossipInterval)
	}

	cfgPath := os.Getenv("IFRIT_CONFIG")
	if cfgPath == "" {
		cfgDir, err := os.MkdirTemp("", "ifrit-http-cfg-*")
		if err != nil {
			return nil, fmt.Errorf("create temp cfg dir: %w", err)
		}
		cleanupDirs = append(cleanupDirs, cfgDir)
		cfgPath = filepath.Join(cfgDir, "ifrit_config.yaml")
	}

	gInterval := cfg.GossipInterval
	if gInterval <= 0 {
		gInterval = 1
	}
	caAddr := cfg.CaAddr
	if caAddr == "" {
		caAddr = "127.0.0.1:8321"
	}
	cfgContent := fmt.Sprintf("ca_addr: %q\ngossip_interval: %d\n", caAddr, gInterval)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		return nil, fmt.Errorf("write ifrit config: %w", err)
	}
	if err := os.Setenv("IFRIT_CONFIG", cfgPath); err != nil {
		return nil, fmt.Errorf("set IFRIT_CONFIG: %w", err)
	}

	if cfg.CryptoUnitPath == "" {
		cryptoDir, err := os.MkdirTemp("", "ifrit-http-crypto-*")
		if err != nil {
			return nil, fmt.Errorf("create temp crypto dir: %w", err)
		}
		cfg.CryptoUnitPath = cryptoDir
		cleanupDirs = append(cleanupDirs, cryptoDir)
	}

	httpHost := cfg.Hostname
	if httpHost == "" || httpHost == "localhost" {
		httpHost = "127.0.0.1"
	}
	httpListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", httpHost, cfg.HTTPPort))
	if err != nil {
		return nil, fmt.Errorf("listen http: %w", err)
	}
	actualHTTPAddr := httpListener.Addr().String()

	hostname := cfg.Hostname
	if hostname == "" {
		hostname = "localhost"
	}

	client, err := ifrit.NewClient(&ifrit.Config{
		New:            cfg.NewCrypto,
		Hostname:       hostname,
		TCPPort:        cfg.TCPPort,
		UDPPort:        cfg.UDPPort,
		CryptoUnitPath: cfg.CryptoUnitPath,
	})
	if err != nil {
		if closeErr := httpListener.Close(); closeErr != nil {
			log.Error("failed to close http listener", "err", closeErr)
		}
		return nil, fmt.Errorf("new ifrit client: %w", err)
	}

	hasher, err := ifrit.DefaultHasher[string]()
	if err != nil {
		client.Stop()
		if closeErr := httpListener.Close(); closeErr != nil {
			log.Error("failed to close http listener", "err", closeErr)
		}
		return nil, fmt.Errorf("create default hasher: %w", err)
	}

	store, err := ifrit.NewDigestSet[string](hasher)
	if err != nil {
		client.Stop()
		if closeErr := httpListener.Close(); closeErr != nil {
			log.Error("failed to close http listener", "err", closeErr)
		}
		return nil, fmt.Errorf("create digest set: %w", err)
	}

	ifrit.RegisterDataStore(client, store)

	app := &App{
		config:       cfg,
		ifritClient:  client,
		store:        store,
		httpListener: httpListener,
		httpAddr:     actualHTTPAddr,
		cleanupDirs:  cleanupDirs,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/status", app.handleHealth)
	mux.HandleFunc("/items", app.handleItems)

	app.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return app, nil
}

// Start begins operating the Ifrit gossip client and the HTTP server.
func (a *App) Start() {
	go a.ifritClient.Start()
	go func() {
		if err := a.httpServer.Serve(a.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server failed", "err", err)
		}
	}()
}

// Stop terminates the HTTP server and the Ifrit client cleanly.
func (a *App) Stop() {
	a.stopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if err := a.httpServer.Shutdown(ctx); err != nil {
			log.Error("error shutting down http server", "err", err)
		}

		a.ifritClient.Stop()

		if err := a.store.Close(); err != nil {
			log.Error("error closing store", "err", err)
		}

		for _, dir := range a.cleanupDirs {
			if err := os.RemoveAll(dir); err != nil {
				log.Error("error removing temp dir", "dir", dir, "err", err)
			}
		}
	})
}

// HTTPAddr returns the bound HTTP address of the node.
func (a *App) HTTPAddr() string {
	return a.httpAddr
}

// Store returns the backing ReverseIndexStore.
func (a *App) Store() ifrit.ReverseIndexStore[string] {
	return a.store
}

// Client returns the underlying Ifrit client.
func (a *App) Client() *ifrit.Client {
	return a.ifritClient
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	resp := HealthResponse{
		Status:      "ok",
		StoreSize:   a.store.Size(),
		Fingerprint: fmt.Sprintf("%016x", uint64(a.store.Fingerprint())),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error("failed to encode health response", "err", err)
	}
}

func (a *App) handleItems(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		elems := a.store.Elements()
		sort.Strings(elems)

		resp := ItemsResponse{
			Items:       elems,
			Count:       len(elems),
			Fingerprint: fmt.Sprintf("%016x", uint64(a.store.Fingerprint())),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Error("failed to encode items response", "err", err)
		}

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"read body failed: %v"}`, err), http.StatusBadRequest)
			return
		}

		var item string
		var jsonReq struct {
			Item string `json:"item"`
		}
		if err := json.Unmarshal(body, &jsonReq); err == nil && jsonReq.Item != "" {
			item = jsonReq.Item
		} else {
			item = strings.TrimSpace(string(body))
		}

		if item == "" {
			http.Error(w, `{"error":"empty item"}`, http.StatusBadRequest)
			return
		}

		isNew := a.store.AddElement(item)

		resp := PostItemResponse{
			Status:      "added",
			Item:        item,
			IsNew:       isNew,
			StoreSize:   a.store.Size(),
			Fingerprint: fmt.Sprintf("%016x", uint64(a.store.Fingerprint())),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Error("failed to encode post item response", "err", err)
		}

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
