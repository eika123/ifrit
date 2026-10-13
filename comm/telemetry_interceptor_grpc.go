package comm

/*
	Provides functionality to log RPC messages while unencrypted. Use the factory NewRPCInterfaceLogger to create a logger.
	The logger must be passed to the NewClient and NewServer functions, this is done in the comm/comm.go NewComm factory method.
	If no logger is passed (a nil), no interceptor is attached and logging of gRPCs is effectively disabled.

	The TelemetryLogger's OnGossipExchange method is called by the interceptors before and after the RPC call.
	In principle, the TelemetryLogger's OnGossipExchange method can do what it wants with the event data.
	Our implementation of the TelemetryLogger interface below writes it to a local SQLite3 database.
*/

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit/netutil"
	pb "github.com/joonnna/ifrit/protobuf"
	_ "github.com/mattn/go-sqlite3" // needed for sqlite3 driver
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// TelemetryListener receives unencrypted semantic gossip events.
type TelemetryLogger interface {
	OnGossipExchange(event GossipEvent)
	Close() error
}

type GossipEvent struct {
	Timestamp       time.Time
	Direction       string // "INCOMING" or "OUTGOING"
	Host            string
	HostPort        string
	RemoteHost      string
	RemotePort      string
	HasNote         bool
	DataBytes       int
	AccusationCount int
	NoteCount       int
	AccusedNodes    []string
	Rings           []uint32
}

func getLocalHostIdentifier() string {
	if ip := netutil.GetLocalIP(); ip != "" {
		return ip
	}
	if h := os.Getenv("HOSTNAME"); h != "" {
		return h
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}

func splitHostAndPort(addr string) (string, string) {
	if addr == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx], addr[idx+1:]
	}
	return addr, ""
}

func extractAccusations(accs []*pb.Accusation) []string {
	accIds := []string{}
	for _, acc := range accs {
		accIds = append(accIds, acc.String())
	}
	return accIds
}

func extractRings(accs []*pb.Accusation) []uint32 {
	rings := []uint32{}
	for _, acc := range accs {
		rings = append(rings, acc.GetRingNum())
	}
	return rings
}

// Client Interceptor factory: returns a unary client interceptor.
// This interceptor is called before client TLS encryption.
//
// In OUTGOING events:
//   - Request fields (stateReq): Represent this local node's own outgoing state/payload:
//   - HasNote: whether this node attached its own pb.Note.
//   - DataBytes: byte size of this node's own ExternalGossip payload.
//   - Reply fields (stateResp): Represent information received back from the remote peer:
//   - AccusationCount, AccusedNodes, Rings: accusations returned by the remote peer.
//   - NoteCount: membership notes returned by the remote peer.
func gossipClientInterceptorFactory(telemetryLogger TelemetryLogger) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var pr peer.Peer
		callOpts := append(opts, grpc.Peer(&pr))
		err := invoker(ctx, method, req, reply, cc, callOpts...)

		if method == "/proto.gossip/Spread" && err == nil {
			stateReq, okReq := req.(*pb.State)
			stateResp, okResp := reply.(*pb.StateResponse)
			if okReq && okResp {
				remoteAddr := cc.Target()
				if pr.Addr != nil {
					remoteAddr = pr.Addr.String()
				}
				remoteHost, remotePort := splitHostAndPort(remoteAddr)
				telemetryLogger.OnGossipExchange(GossipEvent{
					Timestamp:       time.Now(),
					Direction:       "OUTGOING",
					Host:            getLocalHostIdentifier(),
					HostPort:        "",
					RemoteHost:      remoteHost,
					RemotePort:      remotePort,
					HasNote:         stateReq.GetOwnNote() != nil,
					DataBytes:       len(stateReq.GetExternalGossip()),
					AccusationCount: len(stateResp.GetAccusations()),
					NoteCount:       len(stateResp.GetNotes()),
					AccusedNodes:    extractAccusations(stateResp.GetAccusations()),
					Rings:           extractRings(stateResp.GetAccusations()),
				})
			}
		}
		return err
	}
}

// Server Interceptor factory: returns a unary server interceptor.
// This interceptor is called after server TLS decryption and before reply encryption.
func gossipServerInterceptorFactory(telemetryLogger TelemetryLogger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		reply, err := handler(ctx, req)
		if info.FullMethod == "/proto.gossip/Spread" && err == nil {
			stateReq, okReq := req.(*pb.State)
			stateResp, okResp := reply.(*pb.StateResponse)
			remoteAddr := "unknown"
			if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
				remoteAddr = p.Addr.String()
			}
			remoteHost, remotePort := splitHostAndPort(remoteAddr)
			if okReq && okResp {
				telemetryLogger.OnGossipExchange(GossipEvent{
					Timestamp:       time.Now(),
					Direction:       "INCOMING",
					Host:            getLocalHostIdentifier(),
					HostPort:        "",
					RemoteHost:      remoteHost,
					RemotePort:      remotePort,
					HasNote:         stateReq.GetOwnNote() != nil,
					DataBytes:       len(stateReq.GetExternalGossip()),
					AccusationCount: len(stateResp.GetAccusations()),
					NoteCount:       len(stateResp.GetNotes()),
					AccusedNodes:    extractAccusations(stateResp.GetAccusations()),
					Rings:           extractRings(stateResp.GetAccusations()),
				})
			}
		}
		return reply, err
	}
}

func getTelemetryDBPath() string {
	customPath := os.Getenv("IFRIT_TELEMETRY_DB")
	// If explicitly set to empty or "disabled", disable logging
	if customPath == "disabled" || customPath == "off" {
		return ""
	}
	hostname := getLocalHostIdentifier()
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "node"
		}
	}
	// If explicit path was provided:
	if customPath != "" {
		fi, err := os.Stat(customPath)
		if err == nil && fi.IsDir() {
			return filepath.Join(customPath, fmt.Sprintf("telemetry_%s.db", hostname))
		}
		return customPath
	}
	// Default fallback: /tmp/<username>/ifrit-experiments/telemetry_<hostname>.db
	username := os.Getenv("USER")
	if username == "" {
		username = "ifrit"
	}
	dir := filepath.Join(os.TempDir(), username, "ifrit-experiments")
	return filepath.Join(dir, fmt.Sprintf("telemetry_%s.db", hostname))
}

// implements the TelemtryLogger interface
type rpcInterfaceLogger struct {
	dbConn *sql.DB
	dbLock sync.Mutex
	stopCh chan struct{}
}

func NewRPCInterfaceLogger(dbPath string) (*rpcInterfaceLogger, error) {

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Error("Failed to create telemetry directory: " + err.Error())
		return nil, err
	}

	// open db connection with write-ahead-logging
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_sync=NORMAL")
	if err != nil {
		log.Error("Failed to open database: " + err.Error())
		return nil, err
	}

	// Create table gossip_exchange
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS gossip_exchange (
		timestamp INTEGER,
		direction TEXT, -- "OUTGOING" or "INCOMING"
		host TEXT,
		host_port TEXT,
		remote_host TEXT,
		remote_port TEXT,
		has_note BOOLEAN,
		data_bytes INTEGER,
		accusation_count INTEGER,
		note_count INTEGER,
		accused_nodes TEXT,
		rings TEXT
	)`)
	if err != nil {
		log.Error("Failed to create database table: " + err.Error())
		db.Close()
		return nil, err
	}

	rpcil := &rpcInterfaceLogger{
		dbConn: db,
		stopCh: make(chan struct{}),
	}

	go rpcil.periodicCheckpoint()
	return rpcil, nil
}

func (rpcil *rpcInterfaceLogger) Close() error {

	select {
	case <-rpcil.stopCh:
		// already closed
	default:
		close(rpcil.stopCh)
	}

	rpcil.dbLock.Lock()
	defer rpcil.dbLock.Unlock()
	if rpcil.dbConn != nil {
		_, _ = rpcil.dbConn.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		return rpcil.dbConn.Close()
	}
	return nil
}

func (rpcil *rpcInterfaceLogger) OnGossipExchange(event GossipEvent) {
	// send the event to our sqlite3 database
	rpcil.dbLock.Lock()
	defer rpcil.dbLock.Unlock()

	accusedStr := strings.Join(event.AccusedNodes, ",")
	ringsBytes, err := json.Marshal(event.Rings)
	if err != nil {
		log.Error("Failed to marshal rings: " + err.Error())
		ringsBytes = []byte("[]")
	}

	_, err = rpcil.dbConn.Exec(
		`INSERT INTO gossip_exchange (
			timestamp, direction, host, host_port, remote_host, remote_port, 
			has_note, data_bytes, accusation_count, note_count, accused_nodes, rings
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
		event.Direction,
		event.Host,
		event.HostPort,
		event.RemoteHost,
		event.RemotePort,
		event.HasNote,
		event.DataBytes,
		event.AccusationCount,
		event.NoteCount,
		accusedStr,
		ringsBytes,
	)
	if err != nil {
		log.Error(err.Error())
	}
}

func (rpcil *rpcInterfaceLogger) periodicCheckpoint() {
	interval := getCheckpointInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rpcil.stopCh:
			return
		case <-ticker.C:
			rpcil.dbLock.Lock()
			// PASSIVE checkpoint moves committed frames without blocking active gossip RPCs
			_, _ = rpcil.dbConn.Exec("PRAGMA wal_checkpoint(PASSIVE);")
			rpcil.dbLock.Unlock()
		}
	}
}

func getCheckpointInterval() time.Duration {
	val := os.Getenv("IFRIT_TELEMETRY_CHECKPOINT_INTERVAL")
	if val == "" {
		return 10 * time.Second // Default fallback
	}
	dur, err := time.ParseDuration(val)
	if err != nil {
		log.Warn("Invalid IFRIT_TELEMETRY_CHECKPOINT_INTERVAL, using default 10s", "val", val, "err", err)
		return 10 * time.Second
	}
	return dur
}
