package telemetry

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/eika123/ifrit/protobuf"
	transferpb "github.com/eika123/ifrit/reconcile/transfer/proto"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	gossipEvents     []GossipEvent
	rebuttalEvents   []RebuttalEvent
	accusationEvents []AccusationEvent
	noteEvents       []NoteEvent
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

	// 1. Rebuttal message (no fingerprints, OwnNote != nil)
	rebuttalReq := &pb.State{
		OwnNote: &pb.Note{
			Id:    []byte("my-node-id"),
			Epoch: 10,
			Mask:  3,
		},
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

	// 2. Regular Gossip message (has fingerprints and OwnNote; must NOT be classified as rebuttal)
	gossipReq := &pb.State{
		FingerprintView: []byte("fp-view"),
		OwnNote: &pb.Note{
			Id:    []byte("my-node-id"),
			Epoch: 10,
			Mask:  3,
		},
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
	}

	err = interceptor(context.Background(), "/proto.gossip/Spread", gossipReq, respWithAcc, nil, invoker)
	require.NoError(t, err)

	// Rebuttal events must still be 1 (regular gossip must NOT create a rebuttal event)
	assert.Len(t, rec.rebuttalEvents, 1)
	assert.Len(t, rec.gossipEvents, 1)
	assert.Equal(t, 0, rec.gossipEvents[0].PayloadDataSize)
	assert.Len(t, rec.accusationEvents, 1)
	assert.Equal(t, uint32(1), rec.accusationEvents[0].RingNum)
}

func TestGossipServerInterceptorRebuttalVsGossip(t *testing.T) {
	rec := &recordingLogger{}
	interceptor := gossipServerInterceptorFactory(rec)

	// 1. Incoming Rebuttal message (no fingerprints, OwnNote != nil)
	rebuttalReq := &pb.State{
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

func TestGossipInterceptorsResponseGossipLogging(t *testing.T) {
	// Client interceptor records outbound gossip exchange
	clientRec := &recordingLogger{}
	clientInterceptor := gossipClientInterceptorFactory(clientRec)

	req := &pb.State{
		FingerprintView: []byte("fp-view"),
	}
	resp := &pb.StateResponse{}

	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		return nil
	}

	// call to clientInterceptor mimics a network exchange -- the interceptor placed in middleware by the
	// comm.newClient(...) method and is called for each network call.
	err := clientInterceptor(context.Background(), "/proto.gossip/Spread", req, resp, nil, invoker)
	require.NoError(t, err)

	require.Len(t, clientRec.gossipEvents, 1)
	assert.Equal(t, "OUTGOING", clientRec.gossipEvents[0].Direction)
	assert.Equal(t, 0, clientRec.gossipEvents[0].PayloadDataSize)

	// Server interceptor handles a request
	serverRec := &recordingLogger{}
	serverInterceptor := gossipServerInterceptorFactory(serverRec)

	handler := func(ctx context.Context, req any) (any, error) {
		return resp, nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/proto.gossip/Spread",
	}

	_, err = serverInterceptor(context.Background(), req, info, handler)
	require.NoError(t, err)

	require.Len(t, serverRec.gossipEvents, 1)
	assert.Equal(t, "INCOMING", serverRec.gossipEvents[0].Direction)
	assert.Equal(t, 0, serverRec.gossipEvents[0].PayloadDataSize)
}

type mockClientStream struct {
	grpc.ClientStream
	sentMsgs []any
	recvMsgs []any
	recvIdx  int
	ctx      context.Context
}

func (m *mockClientStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

func (m *mockClientStream) SendMsg(msg any) error {
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockClientStream) RecvMsg(target any) error {
	if m.recvIdx >= len(m.recvMsgs) {
		return io.EOF
	}
	src := m.recvMsgs[m.recvIdx]
	m.recvIdx++
	if frameSrc, ok := src.(*transferpb.SyncFrame); ok {
		if frameDst, ok := target.(*transferpb.SyncFrame); ok {
			proto.Merge(frameDst, frameSrc)
			return nil
		}
	}
	return nil
}

type mockServerStream struct {
	grpc.ServerStream
	sentMsgs []any
	recvMsgs []any
	recvIdx  int
	ctx      context.Context
}

func (m *mockServerStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

func (m *mockServerStream) SendMsg(msg any) error {
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockServerStream) RecvMsg(target any) error {
	if m.recvIdx >= len(m.recvMsgs) {
		return io.EOF
	}
	src := m.recvMsgs[m.recvIdx]
	m.recvIdx++
	if frameSrc, ok := src.(*transferpb.SyncFrame); ok {
		if frameDst, ok := target.(*transferpb.SyncFrame); ok {
			proto.Merge(frameDst, frameSrc)
			return nil
		}
	}
	return nil
}

func TestStreamTelemetryInterceptors_SyncFrameAccounting(t *testing.T) {
	// Verify that client and server stream interceptors intercept /recon.Reconciler/Sync
	// DataChunk payloads and record byte accounting into TelemetryLogger.
	clientRec := &recordingLogger{}
	clientInterceptor := gossipStreamClientInterceptorFactory(clientRec)

	inData := make([]byte, 1024)
	mockCS := &mockClientStream{
		recvMsgs: []any{
			&transferpb.SyncFrame{
				Payload: &transferpb.SyncFrame_DataChunk{
					DataChunk: &transferpb.DataItemChunk{Data: inData},
				},
			},
		},
	}

	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return mockCS, nil
	}

	wrappedClientStream, err := clientInterceptor(context.Background(), &grpc.StreamDesc{}, nil, "/reconcile.transfer.ItemTransfer/Sync", streamer)
	require.NoError(t, err)

	// 1. Client sends DataChunk
	chunkData := make([]byte, 65536)
	chunkFrame := &transferpb.SyncFrame{
		Payload: &transferpb.SyncFrame_DataChunk{
			DataChunk: &transferpb.DataItemChunk{
				Data: chunkData,
			},
		},
	}
	err = wrappedClientStream.SendMsg(chunkFrame)
	require.NoError(t, err)

	require.Len(t, clientRec.gossipEvents, 1)
	assert.Equal(t, "OUTGOING", clientRec.gossipEvents[0].Direction)
	assert.Equal(t, 65536, clientRec.gossipEvents[0].PayloadDataSize)

	// 2. Client receives DataChunk
	var recvFrame transferpb.SyncFrame
	err = wrappedClientStream.RecvMsg(&recvFrame)
	require.NoError(t, err)

	require.Len(t, clientRec.gossipEvents, 2)
	assert.Equal(t, "INCOMING", clientRec.gossipEvents[1].Direction)
	assert.Equal(t, 1024, clientRec.gossipEvents[1].PayloadDataSize)

	// 3. Server stream interceptor
	serverRec := &recordingLogger{}
	serverInterceptor := gossipStreamServerInterceptorFactory(serverRec)

	mockSS := &mockServerStream{
		recvMsgs: []any{chunkFrame},
	}

	handler := func(srv any, ss grpc.ServerStream) error {
		var in transferpb.SyncFrame
		recvErr := ss.RecvMsg(&in)
		if recvErr != nil {
			return recvErr
		}
		replyChunk := &transferpb.SyncFrame{
			Payload: &transferpb.SyncFrame_DataChunk{
				DataChunk: &transferpb.DataItemChunk{Data: inData},
			},
		}
		return ss.SendMsg(replyChunk)
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/reconcile.transfer.ItemTransfer/Sync",
	}

	err = serverInterceptor(nil, mockSS, info, handler)
	require.NoError(t, err)

	require.Len(t, serverRec.gossipEvents, 2)
	assert.Equal(t, "INCOMING", serverRec.gossipEvents[0].Direction)
	assert.Equal(t, 65536, serverRec.gossipEvents[0].PayloadDataSize)
	assert.Equal(t, "OUTGOING", serverRec.gossipEvents[1].Direction)
	assert.Equal(t, 1024, serverRec.gossipEvents[1].PayloadDataSize)
}

func TestSyncStreamTelemetry_SQLiteAndDashboardQueries(t *testing.T) {
	// Campaign T3: Confirm that SQLite schema and data generated by stream
	// interceptors match the exact queries expected by serve_telemetry_ui.py.
	tmpDir, err := os.MkdirTemp("", "telemetry-dashboard-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "telemetry_test.db")
	logger, err := NewRPCInterfaceLogger(dbPath)
	require.NoError(t, err)

	now := time.Now()

	// 1. Insert notes
	logger.OnNote(NoteEvent{
		Timestamp:  now,
		Direction:  "OUTGOING",
		Host:       "127.0.0.1",
		RemoteHost: "127.0.0.2",
		NodeID:     "11223344",
		Epoch:      1,
		Mask:       7,
	})
	logger.OnNote(NoteEvent{
		Timestamp:  now,
		Direction:  "INCOMING",
		Host:       "127.0.0.1",
		RemoteHost: "127.0.0.2",
		NodeID:     "55667788",
		Epoch:      2,
		Mask:       15,
	})

	// 2. Insert accusations
	logger.OnAccusation(AccusationEvent{
		Timestamp:  now,
		Direction:  "OUTGOING",
		Host:       "127.0.0.1",
		RemoteHost: "127.0.0.2",
		Accuser:    "11223344",
		Accused:    "deadbeef",
		RingNum:    0,
		Epoch:      1,
	})
	logger.OnAccusation(AccusationEvent{
		Timestamp:  now,
		Direction:  "INCOMING",
		Host:       "127.0.0.1",
		RemoteHost: "127.0.0.2",
		Accuser:    "55667788",
		Accused:    "11223344",
		RingNum:    1,
		Epoch:      2,
	})

	// 3. Insert rebuttal
	logger.OnRebuttal(RebuttalEvent{
		Timestamp:  now,
		Direction:  "OUTGOING",
		Host:       "127.0.0.1",
		HostPort:   "9000",
		RemoteHost: "127.0.0.2",
		RemotePort: "9000",
		NodeID:     "11223344",
		Epoch:      3,
		Mask:       7,
	})

	// 4. Insert gossip data transfer
	logger.OnGossipExchange(GossipEvent{
		Timestamp:       now,
		Direction:       "OUTGOING",
		Host:            "127.0.0.1",
		HostPort:        "9000",
		RemoteHost:      "127.0.0.2",
		RemotePort:      "9000",
		PayloadDataSize: 131072,
	})

	// Flush and close WAL
	err = logger.Close()
	require.NoError(t, err)

	// Reopen SQLite database directly and run serve_telemetry_ui.py queries
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Query 1: Total rebuttals (serve_telemetry_ui.py line 191)
	var totalRebuttals int
	err = db.QueryRow("SELECT COUNT(*) FROM rebuttal_events").Scan(&totalRebuttals)
	require.NoError(t, err)
	assert.Equal(t, 1, totalRebuttals)

	// Query 2: Total accusations (serve_telemetry_ui.py line 201)
	var totalAccusations int
	err = db.QueryRow("SELECT COUNT(*) FROM accusation_events").Scan(&totalAccusations)
	require.NoError(t, err)
	assert.Equal(t, 2, totalAccusations)

	// Query 3: /api/rebuttals endpoint query (serve_telemetry_ui.py line 706)
	rows, err := db.Query("SELECT timestamp, direction, host, remote_host, node_id, epoch, mask FROM rebuttal_events ORDER BY timestamp DESC LIMIT 100")
	require.NoError(t, err)
	defer rows.Close()

	var countRebRows int
	for rows.Next() {
		countRebRows++
		var ts, dir, host, remoteHost, nodeID string
		var epoch, mask uint64
		err = rows.Scan(&ts, &dir, &host, &remoteHost, &nodeID, &epoch, &mask)
		require.NoError(t, err)
		assert.Equal(t, "OUTGOING", dir)
		assert.Equal(t, "11223344", nodeID)
		assert.Equal(t, uint64(3), epoch)
	}
	assert.Equal(t, 1, countRebRows)

	// Query 4: /api/accusations endpoint query (serve_telemetry_ui.py line 737)
	accRows, err := db.Query("SELECT timestamp, direction, host, remote_host, accuser, accused, ring_num, epoch FROM accusation_events ORDER BY timestamp DESC LIMIT 100")
	require.NoError(t, err)
	defer accRows.Close()

	var countAccRows int
	for accRows.Next() {
		countAccRows++
		var ts, dir, host, remoteHost, accuser, accused string
		var ringNum uint32
		var epoch uint64
		err = accRows.Scan(&ts, &dir, &host, &remoteHost, &accuser, &accused, &ringNum, &epoch)
		require.NoError(t, err)
		assert.NotEmpty(t, accuser)
		assert.NotEmpty(t, accused)
	}
	assert.Equal(t, 2, countAccRows)

	// Query 5: Gossip payload data size
	var totalPayload int
	err = db.QueryRow("SELECT SUM(payload_data_size) FROM gossip_exchange").Scan(&totalPayload)
	require.NoError(t, err)
	assert.Equal(t, 131072, totalPayload)
}
