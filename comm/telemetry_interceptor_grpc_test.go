package comm

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type mockInvoker struct {
	req   any
	reply any
	err   error
}

func (m *mockInvoker) invoke(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	m.req = req
	m.reply = reply
	return m.err
}

func TestTelemetryLoggerTablesAndInserts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "telemetry-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_telemetry.db")
	logger, err := NewRPCInterfaceLogger(dbPath)
	require.NoError(t, err)
	defer logger.Close()

	now := time.Now()

	// 1. Test OnGossipExchange
	logger.OnGossipExchange(GossipEvent{
		Timestamp:       now,
		Direction:       "OUTGOING",
		Host:            "127.0.0.1",
		HostPort:        "9000",
		RemoteHost:      "127.0.0.2",
		RemotePort:      "9000",
		PayloadDataSize: 1024,
	})

	// 2. Test OnRebuttal
	logger.OnRebuttal(RebuttalEvent{
		Timestamp:  now,
		Direction:  "OUTGOING",
		Host:       "127.0.0.1",
		HostPort:   "9000",
		RemoteHost: "127.0.0.2",
		RemotePort: "9000",
		NodeID:     "aabbcc112233",
		Epoch:      5,
		Mask:       7,
	})

	// 3. Test OnAccusation
	logger.OnAccusation(AccusationEvent{
		Timestamp:  now,
		Direction:  "INCOMING",
		Host:       "127.0.0.1",
		RemoteHost: "127.0.0.2",
		Accuser:    "accuser1",
		Accused:    "accused1",
		RingNum:    2,
		Epoch:      4,
	})

	// 4. Test OnNote
	logger.OnNote(NoteEvent{
		Timestamp:  now,
		Direction:  "INCOMING",
		Host:       "127.0.0.1",
		RemoteHost: "127.0.0.2",
		NodeID:     "node1",
		Epoch:      3,
		Mask:       15,
	})

	// Verify database contents
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Verify gossip_exchange
	var gCount, gPayload, gDataBytes int
	var gDir, gHost, gRemote string
	err = db.QueryRow("SELECT COUNT(*), direction, host, remote_host, payload_data_size, data_bytes FROM gossip_exchange").Scan(
		&gCount, &gDir, &gHost, &gRemote, &gPayload, &gDataBytes,
	)
	require.NoError(t, err)
	assert.Equal(t, 1, gCount)
	assert.Equal(t, "OUTGOING", gDir)
	assert.Equal(t, "127.0.0.1", gHost)
	assert.Equal(t, "127.0.0.2", gRemote)
	assert.Equal(t, 1024, gPayload)
	assert.Equal(t, 1024, gDataBytes)

	// Verify rebuttal_events
	var rCount int
	var rNodeID string
	var rEpoch, rMask uint64
	err = db.QueryRow("SELECT COUNT(*), node_id, epoch, mask FROM rebuttal_events").Scan(&rCount, &rNodeID, &rEpoch, &rMask)
	require.NoError(t, err)
	assert.Equal(t, 1, rCount)
	assert.Equal(t, "aabbcc112233", rNodeID)
	assert.Equal(t, uint64(5), rEpoch)
	assert.Equal(t, uint64(7), rMask)

	// Verify accusation_events
	var aCount int
	var aAccuser, aAccused string
	var aRing uint32
	var aEpoch uint64
	err = db.QueryRow("SELECT COUNT(*), accuser, accused, ring_num, epoch FROM accusation_events").Scan(&aCount, &aAccuser, &aAccused, &aRing, &aEpoch)
	require.NoError(t, err)
	assert.Equal(t, 1, aCount)
	assert.Equal(t, "accuser1", aAccuser)
	assert.Equal(t, "accused1", aAccused)
	assert.Equal(t, uint32(2), aRing)
	assert.Equal(t, uint64(4), aEpoch)

	// Verify note_events
	var nCount int
	var nNodeID string
	var nEpoch, nMask uint64
	err = db.QueryRow("SELECT COUNT(*), node_id, epoch, mask FROM note_events").Scan(&nCount, &nNodeID, &nEpoch, &nMask)
	require.NoError(t, err)
	assert.Equal(t, 1, nCount)
	assert.Equal(t, "node1", nNodeID)
	assert.Equal(t, uint64(3), nEpoch)
	assert.Equal(t, uint64(15), nMask)
}

type recordingLogger struct {
	gossipEvents    []GossipEvent
	rebuttalEvents  []RebuttalEvent
	accusationEvents []AccusationEvent
	noteEvents      []NoteEvent
}

func (r *recordingLogger) OnGossipExchange(event GossipEvent) {
	r.gossipEvents = append(r.gossipEvents, event)
}

func (r *recordingLogger) OnRebuttal(event RebuttalEvent) {
	r.rebuttalEvents = append(r.rebuttalEvents, event)
}

func (r *recordingLogger) OnAccusation(event AccusationEvent) {
	r.accusationEvents = append(r.accusationEvents, event)
}

func (r *recordingLogger) OnNote(event NoteEvent) {
	r.noteEvents = append(r.noteEvents, event)
}

func (r *recordingLogger) Close() error {
	return nil
}

func TestGossipClientInterceptorRebuttalVsGossip(t *testing.T) {
	rec := &recordingLogger{}
	interceptor := gossipClientInterceptorFactory(rec)

	// 1. Rebuttal message (ExistingHosts is empty/nil, OwnNote != nil)
	rebuttalReq := &pb.State{
		ExistingHosts: nil,
		OwnNote: &pb.Note{
			Id:    []byte("my-node-id"),
			Epoch: 10,
			Mask:  3,
		},
		ExternalGossip: nil,
	}
	resp := &pb.StateResponse{}

	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		return nil
	}

	err := interceptor(context.Background(), "/proto.gossip/Spread", rebuttalReq, resp, nil, invoker)
	require.NoError(t, err)

	assert.Len(t, rec.rebuttalEvents, 1)
	assert.Len(t, rec.gossipEvents, 0)
	assert.Equal(t, uint64(10), rec.rebuttalEvents[0].Epoch)
	assert.Equal(t, uint32(3), rec.rebuttalEvents[0].Mask)

	// 2. Regular Gossip message (ExistingHosts != nil)
	gossipReq := &pb.State{
		ExistingHosts: map[string]uint64{"peerA": 1},
		ExternalGossip: []byte("application data payload"),
	}
	respWithAcc := &pb.StateResponse{
		Accusations: []*pb.Accusation{
			{
				Accuser: []byte("acc1"),
				Accused: []byte("acc2"),
				RingNum: 1,
				Epoch:   2,
			},
		},
		Notes: []*pb.Note{
			{
				Id:    []byte("peerB"),
				Epoch: 4,
				Mask:  7,
			},
		},
	}

	err = interceptor(context.Background(), "/proto.gossip/Spread", gossipReq, respWithAcc, nil, invoker)
	require.NoError(t, err)

	assert.Len(t, rec.gossipEvents, 1)
	assert.Equal(t, len("application data payload"), rec.gossipEvents[0].PayloadDataSize)
	assert.Len(t, rec.accusationEvents, 1)
	assert.Equal(t, uint32(1), rec.accusationEvents[0].RingNum)
	assert.Len(t, rec.noteEvents, 1)
	// 3. Rebuttal with piggybacked application payload
	piggybackReq := &pb.State{
		ExistingHosts: nil,
		OwnNote: &pb.Note{
			Id:    []byte("my-node-id"),
			Epoch: 11,
			Mask:  3,
		},
		ExternalGossip: []byte("piggybacked data"),
	}
	err = interceptor(context.Background(), "/proto.gossip/Spread", piggybackReq, resp, nil, invoker)
	require.NoError(t, err)

	assert.Len(t, rec.rebuttalEvents, 2)
	assert.Equal(t, uint64(11), rec.rebuttalEvents[1].Epoch)
	assert.Len(t, rec.gossipEvents, 2)
	assert.Equal(t, len("piggybacked data"), rec.gossipEvents[1].PayloadDataSize)
}

func TestGossipServerInterceptorRebuttalVsGossip(t *testing.T) {
	rec := &recordingLogger{}
	interceptor := gossipServerInterceptorFactory(rec)

	// 1. Incoming Rebuttal message
	rebuttalReq := &pb.State{
		ExistingHosts: nil,
		OwnNote: &pb.Note{
			Id:    []byte("rebutting-peer"),
			Epoch: 8,
			Mask:  1,
		},
	}
	resp := &pb.StateResponse{}

	handler := func(ctx context.Context, req any) (any, error) {
		return resp, nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/proto.gossip/Spread",
	}

	_, err := interceptor(context.Background(), rebuttalReq, info, handler)
	require.NoError(t, err)

	assert.Len(t, rec.rebuttalEvents, 1)
	assert.Equal(t, "INCOMING", rec.rebuttalEvents[0].Direction)
	assert.Equal(t, uint64(8), rec.rebuttalEvents[0].Epoch)
	assert.Equal(t, uint32(1), rec.rebuttalEvents[0].Mask)
}

