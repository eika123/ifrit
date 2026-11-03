package core

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

type mockSyncStream struct {
	inbound  []*pb.SyncFrame
	inIdx    int
	outbound []*pb.SyncFrame
	ctx      context.Context
}

func newMockSyncStream(frames []*pb.SyncFrame) *mockSyncStream {
	return &mockSyncStream{
		inbound: frames,
		ctx:     context.Background(),
	}
}

func (m *mockSyncStream) Send(f *pb.SyncFrame) error {
	m.outbound = append(m.outbound, f)
	return nil
}

func (m *mockSyncStream) Recv() (*pb.SyncFrame, error) {
	if m.inIdx >= len(m.inbound) {
		return nil, io.EOF
	}
	f := m.inbound[m.inIdx]
	m.inIdx++
	return f, nil
}

func (m *mockSyncStream) Context() context.Context {
	return m.ctx
}

func TestSync_UnsolicitedDataHeader_WhenZeroExpected(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	// 0 data items negotiated
	deltas := ReconcileDeltas{}
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0xdeadbeef},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "malicious-peer-1")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnexpectedSyncFrame), "must return ErrUnexpectedSyncFrame on unsolicited header: %v", err)
}

func TestSync_UnexpectedDigest_WhenNotAllowed(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	// Negotiated item 0x1000, but peer pushes 0x9999
	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x9999},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "buggy-peer-2")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnexpectedDigest), "must return ErrUnexpectedDigest on unrequested digest: %v", err)
}

func TestSync_FramingViolation_DoubleDataHeaderWithoutEnd(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000, 0x2000},
	}
	// Sends header 1, then another header 2 without ending 1
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x1000},
			},
		},
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x2000},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "framing-violator-3")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFramingViolation), "must return ErrFramingViolation on nested header: %v", err)
}

func TestSync_FramingViolation_DataChunkWithoutHeader(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataChunk{
				DataChunk: &pb.DataItemChunk{Data: []byte("orphaned-chunk-bytes")},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "framing-violator-4")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFramingViolation), "must return ErrFramingViolation on chunk without header: %v", err)
}

func TestSync_FramingViolation_DataEndWithoutHeader(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataEnd{
				DataEnd: &pb.DataItemEnd{Digest: 0x1000},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "framing-violator-5")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFramingViolation), "must return ErrFramingViolation on end without header: %v", err)
}

func TestSync_FramingViolation_DataEndDigestMismatch(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	// Header says 0x1000, but End says 0x2000
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x1000},
			},
		},
		{
			Payload: &pb.SyncFrame_DataEnd{
				DataEnd: &pb.DataItemEnd{Digest: 0x2000},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "mismatched-end-peer")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data end digest")
}

func TestSync_ItemSizeLimitExceeded_Header(t *testing.T) {
	node := &Node{}
	cfg := SyncConfig{
		MaxItemBytes: 100,
	}

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	// Header declares 101 bytes, exceeding limit of 100
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x1000, TotalSize: 101},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "oversize-header-peer")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrItemSizeLimitExceeded), "must return ErrItemSizeLimitExceeded on oversized header: %v", err)
}

func TestSync_ItemSizeLimitExceeded_ChunkBuffer(t *testing.T) {
	node := &Node{}
	cfg := SyncConfig{
		MaxItemBytes: 50,
	}

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	// Header claims 20 bytes, but sends chunk of 60 bytes
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x1000, TotalSize: 20},
			},
		},
		{
			Payload: &pb.SyncFrame_DataChunk{
				DataChunk: &pb.DataItemChunk{Data: make([]byte, 60)},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "oversize-chunk-peer")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrItemSizeLimitExceeded), "must return ErrItemSizeLimitExceeded on chunk exceeding limit: %v", err)
}

func TestSync_TruncatedStream_EOFDuringActiveData(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	deltas := ReconcileDeltas{
		AvailableData: []uint64{0x1000},
	}
	// Stream ends abruptly with EOF while item is still active (missing DataEnd and Complete)
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x1000},
			},
		},
		{
			Payload: &pb.SyncFrame_DataChunk{
				DataChunk: &pb.DataItemChunk{Data: []byte("partial")},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "truncated-peer-1")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF), "must return ErrUnexpectedEOF on truncated active item: %v", err)
}

func TestSync_TruncatedStream_EOFBeforeSyncComplete(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	deltas := ReconcileDeltas{}
	// Stream closes without sending SyncComplete
	stream := newMockSyncStream([]*pb.SyncFrame{})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "truncated-peer-2")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF), "must return ErrUnexpectedEOF when stream closes before complete: %v", err)
}

func TestSync_QuotaCompleted_SubsequentHeaderRejected(t *testing.T) {
	node := &Node{}
	cfg := DefaultSyncConfig()

	store, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	RegisterDataStore(node, store)

	item := "record-for-sync-1"
	hasher := revIdxStore.MustDefaultHasher[string]()
	expectedDigest := uint64(hasher(item))

	deltas := ReconcileDeltas{
		AvailableData: []uint64{expectedDigest},
	}

	// 1. Legitimate item completes -> expectedData becomes empty!
	// 2. Peer attempts to send second unsolicited item -> must trigger ErrUnexpectedSyncFrame!
	stream := newMockSyncStream([]*pb.SyncFrame{
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: expectedDigest},
			},
		},
		{
			Payload: &pb.SyncFrame_DataChunk{
				DataChunk: &pb.DataItemChunk{Data: []byte(item)},
			},
		},
		{
			Payload: &pb.SyncFrame_DataEnd{
				DataEnd: &pb.DataItemEnd{Digest: expectedDigest},
			},
		},
		{
			Payload: &pb.SyncFrame_DataHeader{
				DataHeader: &pb.DataItemHeader{Digest: 0x999999},
			},
		},
	})

	comp, err := node.recvIngress(context.Background(), stream, deltas, true, cfg, nil, "quota-exceeder-peer")
	assert.Nil(t, comp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnexpectedSyncFrame), "must reject second item with ErrUnexpectedSyncFrame once quota fulfilled: %v", err)

	// Verify first item was ingested before stream was rejected
	val, ok := store.GetByDigest(revIdxStore.DigestSymbol(expectedDigest))
	assert.True(t, ok)
	assert.Equal(t, item, val)
}

