package ifrit

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eika123/ifrit/comm"
	"github.com/eika123/ifrit/core"
	"github.com/eika123/ifrit/core/discovery"
	"github.com/eika123/ifrit/crypto/identity"
	"github.com/eika123/ifrit/digestmaps"
	"github.com/eika123/ifrit/reconcile"
	"github.com/eika123/ifrit/reconcile/naive"
	"github.com/eika123/ifrit/reconcile/ratelessIBLT"
	log "github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

type Client struct {
	node     *core.Node
	identity *identity.Identity
	strategy string
}

type Config struct {
	// If set to true, the client will create new cryptographic resources and store it in
	// CertPath. Otherwise, it will use the existing resources.
	New bool

	// TCP port of the Ifrit client.
	TCPPort int

	// UDP port of the Ifrit client.
	UDPPort int

	// Hostname used in the X.509 certificate.
	Hostname string

	// The directory of the cryptographic resources.
	CertPath string

	// Optional transport options (e.g. gRPC interceptors or close hooks) passed to comm.NewComm.
	CommOptions []comm.Option

	// Optional programmatic configuration overrides (eliminates need for ifrit_config.yaml).
	CAAddr                 string
	GossipInterval         time.Duration
	MonitorInterval        time.Duration
	ViewUpdateInterval     time.Duration
	PingTimeout            time.Duration
	PingLimit              uint32
	PingsPerInterval       int
	RemovalTimeout         time.Duration
	UseCompression         *bool
	ReconciliationStrategy string
	SyncConfig             *SyncConfig
	EntryAddrs             []string
	UseViz                 *bool
	VizAddr                string
	VizUpdateInterval      time.Duration
}

var (
	errNoCaAddress = errors.New("Config does not contain address of CA")
	errNoConfig    = errors.New("Ifrit client's config is nil")
	errNoHostname  = errors.New("Config does not contain hostname")
)

// Creates and returns a new ifrit client instance.
func NewClient(config *Config) (*Client, error) {
	var id *identity.Identity

	if config == nil {
		return nil, errNoConfig
	}

	resolved, err := resolveConfig(config)
	if err != nil {
		return nil, err
	}

	var (
		udpConn *net.UDPConn
		udpAddr string
		l       net.Listener
		tcpAddr string
	)

	for {
		var err error
		udpConn, udpAddr, err = comm.ListenUdp(config.Hostname, config.UDPPort)
		if err != nil {
			return nil, err
		}

		l, tcpAddr, err = comm.GetListener(config.Hostname, config.TCPPort)
		if err != nil {
			if closeErr := udpConn.Close(); closeErr != nil {
				log.Error("failed to close udpConn on listener error", "err", closeErr)
			}
			return nil, err
		}

		// In X.509 DER encoding, elements within Subject.Locality are canonicalized
		// in lexicographical order. Therefore, tcpAddr must be lexicographically smaller
		// than udpAddr so that peer deserialization (peer.Addr = Locality[0], peer.PingAddr = Locality[1])
		// preserves the mapping correctly. When ephemeral ports are requested (port 0),
		// retry until tcpAddr < udpAddr.
		if tcpAddr < udpAddr {
			break
		}

		if config.TCPPort != 0 && config.UDPPort != 0 {
			if closeErr := udpConn.Close(); closeErr != nil {
				log.Error("failed to close udpConn", "err", closeErr)
			}
			if closeErr := l.Close(); closeErr != nil {
				log.Error("failed to close tcpListener", "err", closeErr)
			}
			return nil, fmt.Errorf("invalid port configuration: tcpAddr %q must be lexicographically smaller than udpAddr %q for X.509 certificate ordering", tcpAddr, udpAddr)
		}

		if closeErr := udpConn.Close(); closeErr != nil {
			log.Error("failed to close udpConn during port ordering retry", "err", closeErr)
		}
		if closeErr := l.Close(); closeErr != nil {
			log.Error("failed to close tcpListener during port ordering retry", "err", closeErr)
		}
	}

	log.Debug("addrs", "rpc", tcpAddr, "udp", udpAddr)

	pk := pkix.Name{
		Locality: []string{tcpAddr, udpAddr},
	}

	caAddr := resolved.caAddr

	if config.New {
		id, err = identity.New(&identity.Config{
			Identity: pk,
			CaAddr:   caAddr,
			DNSNames: []string{config.Hostname},
			Path:     config.CertPath,
		})
		if err != nil {
			return nil, err
		}
	} else {
		id, err = identity.Load(config.CertPath, pk, caAddr)
		if err != nil {
			return nil, err
		}
	}

	commOpts := append([]comm.Option{
		comm.WithAdvertisedAddr(tcpAddr),
		comm.WithCompression(resolved.useCompression),
	}, config.CommOptions...)
	commService, err := comm.NewComm(id.Certificate(), id.CaCertificate(), id.Priv(), l, commOpts...)
	if err != nil {
		return nil, err
	}

	udpServer, err := comm.NewUdpServer(id, udpConn, resolved.pingTimeout)
	if err != nil {
		return nil, err
	}

	n, err := core.NewNode(commService, udpServer, id, id, resolved.nodeOpts)
	if err != nil {
		return nil, err
	}

	return &Client{
		node:     n,
		identity: id,
		strategy: resolved.nodeOpts.ReconciliationStrategy,
	}, nil
}

// Client starts operating.
func (c *Client) Start() {
	c.node.Start()
}

// Stops client operations.
// The client cannot be used after callling Close.
func (c *Client) Stop() {
	c.node.Stop()
}

// Returns the address (ip:port, rpc endpoint) of all other ifrit clients in the network which is currently believed to be alive.
func (c *Client) Members() []string {
	return c.node.LiveMembers()
}

// Returns ifrit's internal ID generated by the trusted CA
func (c *Client) Id() string {
	return c.node.Id()
}

// Returns the address(ip:port) of the ifrit client.
// Can be directly used as entry addresses in the config.
func (c *Client) Addr() string {
	return c.node.Addr()
}

// Strategy returns the configured reconciliation strategy name for this client.
func (c *Client) Strategy() string {
	return c.strategy
}

// Signs the provided content with the internal private key of ifrit.
func (c *Client) Sign(content []byte) ([]byte, []byte, error) {
	return c.node.Sign(content)
}

// Checks if the given content is correctly signed by the public key
// belonging to the given node id.
// The id represents another node in the Fireflies network, if the id
// is not recongnized false is returned.
func (c *Client) VerifySignature(r, s, content []byte, id string) bool {
	return c.node.Verify(r, s, content, id)
}

// PeerInfo represents an immutable snapshot of a live cluster member's identity and RPC address.
type PeerInfo = discovery.PeerInfo

// Self returns the local node's identity and RPC endpoint.
func (c *Client) Self() PeerInfo {
	return c.node.Self()
}

// LivePeers returns all live cluster members in the base Fireflies view.
func (c *Client) LivePeers() []PeerInfo {
	return c.node.LivePeers()
}

// Neighbours returns the RPC addresses of direct ring neighbors in the base Fireflies overlay.
func (c *Client) Neighbours() []string {
	return c.node.Neighbours()
}

// ConnProvider returns a reconcile.ConnProvider borrowing pooled mTLS connections from this client.
func (c *Client) ConnProvider() reconcile.ConnProvider {
	return c.node.ConnProvider()
}

// PeerAuthenticator returns a reconcile.PeerAuthenticator enforcing mTLS + live-view membership.
func (c *Client) PeerAuthenticator() reconcile.PeerAuthenticator {
	return c.node.PeerAuthenticator()
}

// ServiceMembers returns all live, non-evicted peers currently hosting serviceID.
func (c *Client) ServiceMembers(serviceID string) []PeerInfo {
	return c.node.ServiceMembers(serviceID)
}

// RegisterGRPCService mounts a custom gRPC service on the client's shared mTLS
// gRPC server. Must be called before Start() (returns core.ErrAlreadyStarted after,
// or core.ErrGRPCServiceAlreadyRegistered on duplicate registration).
func (c *Client) RegisterGRPCService(desc *grpc.ServiceDesc, impl any) error {
	return c.node.RegisterGRPCService(desc, impl)
}

// EnsureGRPCService returns the already-registered implementation for
// desc.ServiceName if present; otherwise it invokes factory() and mounts it on
// the client's shared mTLS gRPC server before Start().
func (c *Client) EnsureGRPCService(desc *grpc.ServiceDesc, factory func() (any, error)) (any, error) {
	return c.node.EnsureGRPCService(desc, factory)
}

// ValidatePeerCtx extracts and verifies the mTLS client certificate from an
// incoming gRPC context against this client's CA or self-signed trust settings.
func (c *Client) ValidatePeerCtx(ctx context.Context) (*x509.Certificate, error) {
	return c.node.ValidatePeerCtx(ctx)
}

type serviceConfig struct {
	version     uint64
	healthCheck func() bool
}

// ServiceOption configures how a third-party service attaches to an Ifrit client.
type ServiceOption func(*serviceConfig)

// WithServiceVersion sets the initial service version published in this node's ServiceNote.
func WithServiceVersion(version uint64) ServiceOption {
	return func(cfg *serviceConfig) {
		if version > 0 {
			cfg.version = version
		}
	}
}

// WithHealthCheck registers a local health callback invoked before rebutting a ServiceAccusation
// targeting this service. Returning false unregisters the service instead of rebutting.
func WithHealthCheck(fn func() bool) ServiceOption {
	return func(cfg *serviceConfig) {
		cfg.healthCheck = fn
	}
}

// ServiceEndpoint is a scoped handle for a third-party service running atop Ifrit,
// providing super-overlay discovery, service-level accusations, and transparent
// reconcilable store attachment.
type ServiceEndpoint struct {
	client    *Client
	serviceID string
}

// Service attaches a third-party service identified by serviceID to this client,
// initializing its deterministic RingSuperOverlay over S_svc and publishing a signed
// ServiceNote across the cluster.
func (c *Client) Service(serviceID string, opts ...ServiceOption) (*ServiceEndpoint, error) {
	if c == nil || c.node == nil {
		return nil, errors.New("ifrit client is nil")
	}
	cfg := serviceConfig{version: 1}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if _, err := c.node.RegisterService(serviceID, cfg.version, cfg.healthCheck); err != nil {
		return nil, err
	}
	return &ServiceEndpoint{
		client:    c,
		serviceID: serviceID,
	}, nil
}

// ID returns the validated service identifier for this endpoint.
func (s *ServiceEndpoint) ID() string {
	return s.serviceID
}

// Members returns all live, non-evicted peers currently hosting this service (sorted by ID).
func (s *ServiceEndpoint) Members() []PeerInfo {
	return s.client.node.ServiceMembers(s.serviceID)
}

// MemberAddrs returns the RPC addresses of all live, non-evicted peers hosting this service.
func (s *ServiceEndpoint) MemberAddrs() []string {
	members := s.Members()
	addrs := make([]string, 0, len(members))
	for _, p := range members {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// Neighbours returns the deterministic k-ring neighbors from this service's RingSuperOverlay.
func (s *ServiceEndpoint) Neighbours() []PeerInfo {
	return s.client.node.ServiceNeighbours(s.serviceID)
}

// NeighbourAddrs returns the RPC addresses of this service's deterministic k-ring neighbors.
func (s *ServiceEndpoint) NeighbourAddrs() []string {
	neighbours := s.Neighbours()
	addrs := make([]string, 0, len(neighbours))
	for _, p := range neighbours {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// AccusePeer signs and publishes a ServiceAccusation against peerID on ringNum of this
// service's RingSuperOverlay when peerID's service instance crashes or behaves malignantly.
func (s *ServiceEndpoint) AccusePeer(peerID string, ringNum uint32) error {
	return s.client.node.AccuseServicePeer(s.serviceID, peerID, ringNum)
}

// RegisterStoreReconciler mounts a custom reconcile.StoreReconciler for this service under
// "service/<serviceID>" and enables automatic background anti-entropy across Neighbours().
func (s *ServiceEndpoint) RegisterStoreReconciler(rec reconcile.StoreReconciler, fpFn func() []byte) error {
	return s.client.node.RegisterServiceStoreReconciler(s.serviceID, rec, fpFn)
}

// Close detaches this service's store reconciler and super-overlay, and publishes
// an updated ServiceNote epoch without this service.
func (s *ServiceEndpoint) Close() error {
	return s.client.node.UnregisterService(s.serviceID)
}

// RegisterServiceStore attaches a typed ReverseIndexStore[T] to svc under "service/<serviceID>",
// providing transparent eventual-consistency replication via store.Insert() across svc's RingSuperOverlay.
func RegisterServiceStore[T any](svc *ServiceEndpoint, store ReverseIndexStore[T], codec ...ItemCodec[T]) error {
	if svc == nil || svc.client == nil || svc.client.node == nil {
		return errors.New("service endpoint is nil")
	}
	var c ItemCodec[T]
	if len(codec) > 0 {
		c = codec[0]
	}
	return core.RegisterServiceStore(svc.client.node, svc.serviceID, store, c)
}

// ReverseIndexStore defines the standard contract that all data stores must comply to.
type ReverseIndexStore[T any] = digestmaps.ReverseIndexStore[T, digestmaps.DigestSymbol]

// ReconcilableStore is a reconcilable data store whose Insert operations
// automatically maintain underlying set-reconciliation state.
type ReconcilableStore[T any] = reconcile.Store[T]

var (
	ErrNilHasher      = digestmaps.ErrNilHasher
	ErrUnhashableType = digestmaps.ErrUnhashableType
)

// DefaultHasher returns a deterministic 64-bit hasher for type T after validating at factory time
// that T is deterministically hashable, or returns an error wrapping ErrUnhashableType.
func DefaultHasher[T any]() (digestmaps.Hasher[T, digestmaps.DigestSymbol], error) {
	return digestmaps.DefaultHasher[T]()
}

// MustDefaultHasher returns DefaultHasher[T]() or panics if T is not deterministically hashable.
func MustDefaultHasher[T any]() digestmaps.Hasher[T, digestmaps.DigestSymbol] {
	return digestmaps.MustDefaultHasher[T]()
}

// NewCustomDigestSet creates a new empty ReverseIndexStore backed by an in-memory digest set.
// Returns (nil, ErrNilHasher) if hasher is nil.
func NewCustomDigestSet[T any, S digestmaps.Symbol[S]](hasher digestmaps.Hasher[T, S]) (digestmaps.ReverseIndexStore[T, S], error) {
	return digestmaps.NewDigestSet(hasher)
}

// NewDigestSet creates a new empty ReverseIndexStore backed by an in-memory digest set.
// Returns (nil, ErrNilHasher) if hasher is nil.
func NewDigestSet[T any](hasher digestmaps.Hasher[T, digestmaps.DigestSymbol]) (ReverseIndexStore[T], error) {
	return digestmaps.NewDigestSet(hasher)
}

// NewReconcilableStore creates a new in-memory reconcilable store backed by
// ratelessIBLT (default). sketchSize is optional (when omitted or <= 0, DefaultSketchSize is used).
func NewReconcilableStore[T any](hasher digestmaps.Hasher[T, digestmaps.DigestSymbol], sketchSize ...int) (ReconcilableStore[T], error) {
	return ratelessIBLT.NewReconcilableStore(hasher, sketchSize...)
}

// NewReconcilableStoreWithStrategy creates a reconcilable store for the given strategy
// ("naive"/"naive/1" or default "riblt"/"riblt/1").
func NewReconcilableStoreWithStrategy[T any](strategy string, hasher digestmaps.Hasher[T, digestmaps.DigestSymbol], sketchSize ...int) (ReconcilableStore[T], error) {
	s := strings.ToLower(strings.TrimSpace(strategy))
	if s == "naive" || s == naive.ProtocolName {
		return naive.NewReconcilableStore(hasher)
	}
	return ratelessIBLT.NewReconcilableStore(hasher, sketchSize...)
}

// NewNaiveStore creates a new in-memory reconcilable store backed by full digest exchange.
func NewNaiveStore[T any](hasher digestmaps.Hasher[T, digestmaps.DigestSymbol]) (ReconcilableStore[T], error) {
	return naive.NewReconcilableStore(hasher)
}

// ItemCodec defines the serialization and deserialization contract for data items.
type ItemCodec[T any] = reconcile.ItemCodec[T]

// DefaultItemCodec returns the default ItemCodec implementation for type T.
func DefaultItemCodec[T any]() ItemCodec[T] {
	return reconcile.DefaultItemCodec[T]()
}

// SyncConfig defines streaming transfer limits and timeouts.
type SyncConfig = core.SyncConfig

// DefaultSyncConfig returns standard reconciliation parameters.
func DefaultSyncConfig() SyncConfig {
	return core.DefaultSyncConfig()
}

// RegisterDataStore registers an application's typed data store with the Ifrit client.
func RegisterDataStore[T any](c *Client, store ReverseIndexStore[T]) {
	if c == nil || c.node == nil {
		return
	}
	core.RegisterDataStore(c.node, store)
}

// RegisterDataStoreWithCodec registers an application's typed data store with a custom ItemCodec.
func RegisterDataStoreWithCodec[T any](c *Client, store ReverseIndexStore[T], codec ItemCodec[T]) {
	if c == nil || c.node == nil {
		return
	}
	core.RegisterDataStoreWithCodec(c.node, store, codec)
}

func (c *Client) SavePrivateKey() error {
	if c.identity != nil {
		return c.identity.SavePrivateKey()
	}
	return nil
}

func (c *Client) SaveCertificate() error {
	if c.identity != nil {
		return c.identity.SaveCertificate()
	}
	return nil
}

var defaultConfigPaths = []string{"/var/tmp", "./config", "."}

func configSearchPaths(envPaths string) []string {
	if strings.TrimSpace(envPaths) == "" {
		return append([]string(nil), defaultConfigPaths...)
	}

	var paths []string
	for _, p := range filepath.SplitList(envPaths) {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			paths = append(paths, trimmed)
		}
	}
	if len(paths) == 0 {
		return append([]string(nil), defaultConfigPaths...)
	}
	return paths
}

type resolvedClientConfig struct {
	caAddr         string
	pingTimeout    time.Duration
	useCompression bool
	nodeOpts       core.Options
}

func resolveConfig(cfg *Config) (resolvedClientConfig, error) {
	v := viper.New()
	if envCfg := os.Getenv("IFRIT_CONFIG"); envCfg != "" {
		v.SetConfigFile(envCfg)
		if err := v.ReadInConfig(); err != nil {
			return resolvedClientConfig{}, err
		}
	} else {
		v.SetConfigName("ifrit_config")
		for _, p := range configSearchPaths(os.Getenv("IFRIT_CONFIG_PATHS")) {
			v.AddConfigPath(p)
		}
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) || cfg.CAAddr == "" {
				return resolvedClientConfig{}, err
			}
		}
	}

	// Behavior defaults
	v.SetDefault("gossip_interval", 10)
	v.SetDefault("monitor_interval", 10)
	v.SetDefault("view_update_interval", 10)
	v.SetDefault("ping_timeout", 5)
	v.SetDefault("ping_limit", 3)
	v.SetDefault("pings_per_interval", 3)
	v.SetDefault("removal_timeout", 60)
	v.SetDefault("max_concurrent_messages", 5)
	v.SetDefault("use_compression", true)
	v.SetDefault("reconciliation_strategy", "riblt")
	v.SetDefault("viz_update_interval", 10)

	out := resolvedClientConfig{
		caAddr:         v.GetString("ca_addr"),
		pingTimeout:    time.Second * time.Duration(v.GetInt32("ping_timeout")),
		useCompression: v.GetBool("use_compression"),
		nodeOpts: core.Options{
			GossipInterval:         time.Second * time.Duration(v.GetInt32("gossip_interval")),
			MonitorInterval:        time.Second * time.Duration(v.GetInt32("monitor_interval")),
			ViewUpdateInterval:     time.Second * time.Duration(v.GetInt32("view_update_interval")),
			RemovalTimeout:         time.Second * time.Duration(v.GetFloat64("removal_timeout")),
			PingLimit:              uint32(v.GetInt32("ping_limit")),
			PingsPerInterval:       v.GetInt("pings_per_interval"),
			ReconciliationStrategy: v.GetString("reconciliation_strategy"),
			EntryAddrs:             v.GetStringSlice("entry_addrs"),
			SyncConfig:             core.DefaultSyncConfig(),
			UseViz:                 v.GetBool("use_viz"),
			VizAddr:                v.GetString("viz_addr"),
			VizUpdateInterval:      time.Second * time.Duration(v.GetInt32("viz_update_interval")),
		},
	}

	if cfg.CAAddr != "" {
		out.caAddr = cfg.CAAddr
	}
	if cfg.PingTimeout > 0 {
		out.pingTimeout = cfg.PingTimeout
	}
	if cfg.UseCompression != nil {
		out.useCompression = *cfg.UseCompression
	}
	if cfg.GossipInterval > 0 {
		out.nodeOpts.GossipInterval = cfg.GossipInterval
	}
	if cfg.MonitorInterval > 0 {
		out.nodeOpts.MonitorInterval = cfg.MonitorInterval
	}
	if cfg.ViewUpdateInterval > 0 {
		out.nodeOpts.ViewUpdateInterval = cfg.ViewUpdateInterval
	}
	if cfg.RemovalTimeout > 0 {
		out.nodeOpts.RemovalTimeout = cfg.RemovalTimeout
	}
	if cfg.PingLimit > 0 {
		out.nodeOpts.PingLimit = cfg.PingLimit
	}
	if cfg.PingsPerInterval > 0 {
		out.nodeOpts.PingsPerInterval = cfg.PingsPerInterval
	}
	if cfg.ReconciliationStrategy != "" {
		out.nodeOpts.ReconciliationStrategy = cfg.ReconciliationStrategy
	}
	if cfg.SyncConfig != nil {
		out.nodeOpts.SyncConfig = *cfg.SyncConfig
	}
	if len(cfg.EntryAddrs) > 0 {
		out.nodeOpts.EntryAddrs = cfg.EntryAddrs
	}
	if cfg.UseViz != nil {
		out.nodeOpts.UseViz = *cfg.UseViz
	}
	if cfg.VizAddr != "" {
		out.nodeOpts.VizAddr = cfg.VizAddr
	}
	if cfg.VizUpdateInterval > 0 {
		out.nodeOpts.VizUpdateInterval = cfg.VizUpdateInterval
	}

	return out, nil
}
