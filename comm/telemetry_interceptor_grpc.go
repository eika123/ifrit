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
	"encoding/hex"
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

// TelemetryLogger receives unencrypted semantic protocol events: application gossip,
// failure-recovery rebuttals, accusations, and membership notes.
type TelemetryLogger interface {
	OnGossipExchange(event GossipEvent)
	OnRebuttal(event RebuttalEvent)
	OnAccusation(event AccusationEvent)
	OnNote(event NoteEvent)
	Close() error
}

// GossipEvent represents an application data exchange between peers.
type GossipEvent struct {
	Timestamp       time.Time
	Direction       string // "INCOMING" or "OUTGOING"
	Host            string
	HostPort        string
	RemoteHost      string
	RemotePort      string
	PayloadDataSize int
}

// RebuttalEvent captures when an accused node broadcasts or receives an urgent rebuttal Note.
type RebuttalEvent struct {
	Timestamp  time.Time
	Direction  string // "OUTGOING" (issued by this node) or "INCOMING" (received by this node)
	Host       string
	HostPort   string
	RemoteHost string
	RemotePort string
	NodeID     string // hex encoded ID of the accused node
	Epoch      uint64 // incremented epoch
	Mask       uint32 // active/deactivated ring mask
}

// AccusationEvent represents an accusation against a suspected node on a specific ring.
type AccusationEvent struct {
	Timestamp  time.Time
	Direction  string // "OUTGOING" (served to peer) or "INCOMING" (received from peer)
	Host       string
	RemoteHost string
	Accuser    string // hex encoded ID
	Accused    string // hex encoded ID
	RingNum    uint32 // ring number on which accusation was made
	Epoch      uint64 // epoch being accused
}

// NoteEvent represents a membership Note exchanged between peers.
type NoteEvent struct {
	Timestamp  time.Time
	Direction  string // "OUTGOING" (served to peer) or "INCOMING" (received from peer)
	Host       string
	RemoteHost string
	NodeID     string // hex encoded ID
	Epoch      uint64
	Mask       uint32
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

// Client Interceptor factory: returns a unary client interceptor.
// This interceptor is called before client TLS encryption.
func gossipClientInterceptorFactory(telemetryLogger TelemetryLogger) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var pr peer.Peer
		callOpts := append(opts, grpc.Peer(&pr))
		err := invoker(ctx, method, req, reply, cc, callOpts...)

		if method == "/proto.gossip/Spread" && err == nil {
			stateReq, okReq := req.(*pb.State)
			stateResp, okResp := reply.(*pb.StateResponse)
			if okReq && okResp {
				remoteAddr := ""
				if cc != nil {
					remoteAddr = cc.Target()
				}
				if pr.Addr != nil {
					remoteAddr = pr.Addr.String()
				}
				remoteHost, remotePort := splitHostAndPort(remoteAddr)
				host := getLocalHostIdentifier()
				now := time.Now()

				// Distinguish between a Rebuttal and regular Gossip
				isRebuttal := len(stateReq.GetExistingHosts()) == 0 && stateReq.GetOwnNote() != nil

				if isRebuttal {
					ownNote := stateReq.GetOwnNote()
					telemetryLogger.OnRebuttal(RebuttalEvent{
						Timestamp:  now,
						Direction:  "OUTGOING",
						Host:       host,
						HostPort:   "",
						RemoteHost: remoteHost,
						RemotePort: remotePort,
						NodeID:     hex.EncodeToString(ownNote.GetId()),
						Epoch:      ownNote.GetEpoch(),
						Mask:       ownNote.GetMask(),
					})
				} else {
					payloadSize := len(stateReq.GetExternalGossip())
					telemetryLogger.OnGossipExchange(GossipEvent{
						Timestamp:       now,
						Direction:       "OUTGOING",
						Host:            host,
						HostPort:        "",
						RemoteHost:      remoteHost,
						RemotePort:      remotePort,
						PayloadDataSize: payloadSize,
					})
				}

				// Log accusations received from remote peer in reply
				for _, acc := range stateResp.GetAccusations() {
					telemetryLogger.OnAccusation(AccusationEvent{
						Timestamp:  now,
						Direction:  "INCOMING",
						Host:       host,
						RemoteHost: remoteHost,
						Accuser:    hex.EncodeToString(acc.GetAccuser()),
						Accused:    hex.EncodeToString(acc.GetAccused()),
						RingNum:    acc.GetRingNum(),
						Epoch:      acc.GetEpoch(),
					})
				}

				// Log membership notes received from remote peer in reply
				for _, note := range stateResp.GetNotes() {
					telemetryLogger.OnNote(NoteEvent{
						Timestamp:  now,
						Direction:  "INCOMING",
						Host:       host,
						RemoteHost: remoteHost,
						NodeID:     hex.EncodeToString(note.GetId()),
						Epoch:      note.GetEpoch(),
						Mask:       note.GetMask(),
					})
				}
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
			host := getLocalHostIdentifier()
			now := time.Now()

			if okReq && okResp {
				// Distinguish between a Rebuttal and regular Gossip
				isRebuttal := len(stateReq.GetExistingHosts()) == 0 && stateReq.GetOwnNote() != nil

				if isRebuttal {
					ownNote := stateReq.GetOwnNote()
					telemetryLogger.OnRebuttal(RebuttalEvent{
						Timestamp:  now,
						Direction:  "INCOMING",
						Host:       host,
						HostPort:   "",
						RemoteHost: remoteHost,
						RemotePort: remotePort,
						NodeID:     hex.EncodeToString(ownNote.GetId()),
						Epoch:      ownNote.GetEpoch(),
						Mask:       ownNote.GetMask(),
					})
				} else {
					payloadSize := len(stateReq.GetExternalGossip())
					telemetryLogger.OnGossipExchange(GossipEvent{
						Timestamp:       now,
						Direction:       "INCOMING",
						Host:            host,
						HostPort:        "",
						RemoteHost:      remoteHost,
						RemotePort:      remotePort,
						PayloadDataSize: payloadSize,
					})
				}

				// Log accusations sent back to remote peer in reply
				for _, acc := range stateResp.GetAccusations() {
					telemetryLogger.OnAccusation(AccusationEvent{
						Timestamp:  now,
						Direction:  "OUTGOING",
						Host:       host,
						RemoteHost: remoteHost,
						Accuser:    hex.EncodeToString(acc.GetAccuser()),
						Accused:    hex.EncodeToString(acc.GetAccused()),
						RingNum:    acc.GetRingNum(),
						Epoch:      acc.GetEpoch(),
					})
				}

				// Log membership notes sent back to remote peer in reply
				for _, note := range stateResp.GetNotes() {
					telemetryLogger.OnNote(NoteEvent{
						Timestamp:  now,
						Direction:  "OUTGOING",
						Host:       host,
						RemoteHost: remoteHost,
						NodeID:     hex.EncodeToString(note.GetId()),
						Epoch:      note.GetEpoch(),
						Mask:       note.GetMask(),
					})
				}
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

	// 1. Create table gossip_exchange (application gossip only)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS gossip_exchange (
		timestamp INTEGER,
		direction TEXT, -- "OUTGOING" or "INCOMING"
		host TEXT,
		host_port TEXT,
		remote_host TEXT,
		remote_port TEXT,
		payload_data_size INTEGER,
		data_bytes INTEGER -- alias for backwards compatibility
	)`)
	if err != nil {
		log.Error("Failed to create gossip_exchange table: " + err.Error())
		db.Close()
		return nil, err
	}

	// 2. Create table rebuttal_events
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rebuttal_events (
		timestamp INTEGER,
		direction TEXT, -- "OUTGOING" or "INCOMING"
		host TEXT,
		host_port TEXT,
		remote_host TEXT,
		remote_port TEXT,
		node_id TEXT,
		epoch INTEGER,
		mask INTEGER
	)`)
	if err != nil {
		log.Error("Failed to create rebuttal_events table: " + err.Error())
		db.Close()
		return nil, err
	}

	// 3. Create table accusation_events
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS accusation_events (
		timestamp INTEGER,
		direction TEXT, -- "OUTGOING" or "INCOMING"
		host TEXT,
		remote_host TEXT,
		accuser TEXT,
		accused TEXT,
		ring_num INTEGER,
		epoch INTEGER
	)`)
	if err != nil {
		log.Error("Failed to create accusation_events table: " + err.Error())
		db.Close()
		return nil, err
	}

	// 4. Create table note_events
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS note_events (
		timestamp INTEGER,
		direction TEXT, -- "OUTGOING" or "INCOMING"
		host TEXT,
		remote_host TEXT,
		node_id TEXT,
		epoch INTEGER,
		mask INTEGER
	)`)
	if err != nil {
		log.Error("Failed to create note_events table: " + err.Error())
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
	rpcil.dbLock.Lock()
	defer rpcil.dbLock.Unlock()

	_, err := rpcil.dbConn.Exec(
		`INSERT INTO gossip_exchange (
			timestamp, direction, host, host_port, remote_host, remote_port, 
			payload_data_size, data_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
		event.Direction,
		event.Host,
		event.HostPort,
		event.RemoteHost,
		event.RemotePort,
		event.PayloadDataSize,
		event.PayloadDataSize,
	)
	if err != nil {
		log.Error(err.Error())
	}
}

func (rpcil *rpcInterfaceLogger) OnRebuttal(event RebuttalEvent) {
	rpcil.dbLock.Lock()
	defer rpcil.dbLock.Unlock()

	_, err := rpcil.dbConn.Exec(
		`INSERT INTO rebuttal_events (
			timestamp, direction, host, host_port, remote_host, remote_port, 
			node_id, epoch, mask
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
		event.Direction,
		event.Host,
		event.HostPort,
		event.RemoteHost,
		event.RemotePort,
		event.NodeID,
		event.Epoch,
		event.Mask,
	)
	if err != nil {
		log.Error(err.Error())
	}
}

func (rpcil *rpcInterfaceLogger) OnAccusation(event AccusationEvent) {
	rpcil.dbLock.Lock()
	defer rpcil.dbLock.Unlock()

	_, err := rpcil.dbConn.Exec(
		`INSERT INTO accusation_events (
			timestamp, direction, host, remote_host, 
			accuser, accused, ring_num, epoch
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
		event.Direction,
		event.Host,
		event.RemoteHost,
		event.Accuser,
		event.Accused,
		event.RingNum,
		event.Epoch,
	)
	if err != nil {
		log.Error(err.Error())
	}
}

func (rpcil *rpcInterfaceLogger) OnNote(event NoteEvent) {
	rpcil.dbLock.Lock()
	defer rpcil.dbLock.Unlock()

	_, err := rpcil.dbConn.Exec(
		`INSERT INTO note_events (
			timestamp, direction, host, remote_host, 
			node_id, epoch, mask
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
		event.Direction,
		event.Host,
		event.RemoteHost,
		event.NodeID,
		event.Epoch,
		event.Mask,
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
