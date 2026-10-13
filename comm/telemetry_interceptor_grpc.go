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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
	_ "github.com/mattn/go-sqlite3" // needed for sqlite3 driver
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// TelemetryListener receives unencrypted semantic gossip events.
type TelemetryLogger interface {
	OnGossipExchange(event GossipEvent)
}

type GossipEvent struct {
	Timestamp       time.Time
	Direction       string // "INCOMING" or "OUTGOING"
	HostAddr        string
	RemoteAddr      string
	HasNote         bool
	DataBytes       int
	AccusationCount int
	NoteCount       int
	AccusedNodes    []string
	Rings           []uint32
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
func gossipClientInterceptorFactory(telemetryLogger TelemetryLogger) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)

		if method == "/proto.gossip/Spread" && err == nil {
			stateReq, okReq := req.(*pb.State)
			stateResp, okResp := reply.(*pb.StateResponse)
			if okReq && okResp {
				telemetryLogger.OnGossipExchange(GossipEvent{
					Timestamp: time.Now(),
					Direction: "OUTGOING",
					//HostAddr:        netutil.GetLocalIP(),
					HostAddr:        os.Getenv("HOSTNAME"),
					RemoteAddr:      cc.Target(),
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
			if okReq && okResp {
				telemetryLogger.OnGossipExchange(GossipEvent{
					Timestamp:       time.Now(),
					Direction:       "INCOMING",
					HostAddr:        os.Getenv("HOSTNAME"),
					RemoteAddr:      remoteAddr,
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
	hostname := os.Getenv("HOSTNAME")
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
		remote TEXT,
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

	return &rpcInterfaceLogger{
		dbConn: db,
	}, nil
}

func (crpcl *rpcInterfaceLogger) OnGossipExchange(event GossipEvent) {
	// send the event to our sqlite3 database
	crpcl.dbLock.Lock()
	defer crpcl.dbLock.Unlock()

	accusedStr := strings.Join(event.AccusedNodes, ",")
	ringsBytes, err := json.Marshal(event.Rings)
	if err != nil {
		log.Error("Failed to marshal rings: " + err.Error())
		ringsBytes = []byte("[]")
	}

	_, err = crpcl.dbConn.Exec(
		`INSERT INTO gossip_exchange (timestamp, direction, host, remote, has_note, data_bytes, accusation_count, note_count, accused_nodes, rings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
		event.Direction,
		event.HostAddr,
		event.RemoteAddr,
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
