package main

import (
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/golang/protobuf/proto"
	pb "github.com/joonnna/ifrit/protobuf"
)

// TestHostEndianness checks the memory layout of the host machine.
func TestHostEndianness(t *testing.T) {
	var num uint16 = 0x0102
	lowestByteInMemory := *(*byte)(unsafe.Pointer(&num))

	switch lowestByteInMemory {
	case 0x02:
		t.Log("Host architecture is Little-Endian (expected for x86_64 and modern ARM)")
	case 0x01:
		t.Log("Host architecture is Big-Endian")
	default:
		t.Fatalf("Unexpected byte order detected: 0x%02x", lowestByteInMemory)
	}
}

// TestHostToNetwork16 verifies that hostToNetwork16 converts values correctly to Big-Endian.
// Fails on Big-Endian machines.
func TestHostToNetwork16(t *testing.T) {
	// Standard Linux ETH_P_ALL constant: 0x0003, encoded as [0x03, 0x00] in Little-Endian
	val := uint16(syscall.ETH_P_ALL)
	swappedBytes := hostToNetwork16(val)

	// In Big-Endian byte representation, 0x0003 is [0x00, 0x03]
	bigEndianBytes := [2]byte{0x00, 0x03}

	// In memory on the host, network order (Big-Endian) must ALWAYS place
	// high-order byte first: 0x00, followed by 0x03.
	actualBytesInMemory := *(*[2]byte)(unsafe.Pointer(&swappedBytes))
	if actualBytesInMemory != bigEndianBytes {
		t.Errorf("hostToNetwork16(0x%04x) placed %v in memory, expected %v",
			val, actualBytesInMemory, bigEndianBytes)
	}

	// Involutive property (applying swap twice restores original value)
	if hostToNetwork16(swappedBytes) != val {
		t.Errorf("Double swap failed: got 0x%04x, expected original 0x%04x",
			hostToNetwork16(swappedBytes), val)
	}
}

// mockPingPongEvent records an event captured by MockRecorder.
type mockPingPongEvent struct {
	Timestamp string
	EventType string
	SrcIP     string
	SrcPort   int
	DstIP     string
	DstPort   int
	NonceHex  string
	RttMs     float64
}

// mockTCPEvent records a TCP packet captured by MockRecorder.
type mockTCPEvent struct {
	Timestamp string
	SrcIP     string
	SrcPort   int
	DstIP     string
	DstPort   int
	BytesLen  int
}

// MockRecorder implements TelemetryRecorder in memory for unit testing.
type MockRecorder struct {
	PingPongEvents []mockPingPongEvent
	TCPEvents      []mockTCPEvent
}

func (m *MockRecorder) RecordPingPong(timestamp, eventType, srcIP string, srcPort int, dstIP string, dstPort int, nonceHex string, rttMs float64) error {
	m.PingPongEvents = append(m.PingPongEvents, mockPingPongEvent{
		Timestamp: timestamp,
		EventType: eventType,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		NonceHex:  nonceHex,
		RttMs:     rttMs,
	})
	return nil
}

func (m *MockRecorder) RecordTCP(timestamp, srcIP string, srcPort int, dstIP string, dstPort int, bytesLen int) error {
	m.TCPEvents = append(m.TCPEvents, mockTCPEvent{
		Timestamp: timestamp,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		BytesLen:  bytesLen,
	})
	return nil
}

func (m *MockRecorder) Close() error {
	return nil
}

// Helper function to build a synthetic Ethernet + IPv4 + UDP packet.
func buildEthernetUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ethHdr := make([]byte, EthernetHeaderLen)
	ethHdr[12] = 0x08
	ethHdr[13] = 0x00 // EtherType IPv4 (0x0800)

	totalIPLen := 20 + UDPHeaderLen + len(payload)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // IPv4, IHL = 5 (20 bytes)
	ipHdr[2] = byte(totalIPLen >> 8)
	ipHdr[3] = byte(totalIPLen & 0xff)
	ipHdr[8] = 64         // TTL
	ipHdr[9] = IPProtoUDP // Protocol UDP (17)
	copy(ipHdr[12:16], srcIP[:])
	copy(ipHdr[16:20], dstIP[:])

	udpHdr := make([]byte, UDPHeaderLen)
	udpHdr[0] = byte(srcPort >> 8)
	udpHdr[1] = byte(srcPort & 0xff)
	udpHdr[2] = byte(dstPort >> 8)
	udpHdr[3] = byte(dstPort & 0xff)
	udpLen := UDPHeaderLen + len(payload)
	udpHdr[4] = byte(udpLen >> 8)
	udpHdr[5] = byte(udpLen & 0xff)

	frame := append(ethHdr, ipHdr...)
	frame = append(frame, udpHdr...)
	frame = append(frame, payload...)
	return frame
}

// Helper function to build a synthetic Ethernet + IPv4 + TCP packet.
func buildEthernetTCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ethHdr := make([]byte, EthernetHeaderLen)
	ethHdr[12] = 0x08
	ethHdr[13] = 0x00 // EtherType IPv4

	totalIPLen := 20 + 20 + len(payload) // 20B IP + 20B TCP
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // IPv4, IHL = 5
	ipHdr[2] = byte(totalIPLen >> 8)
	ipHdr[3] = byte(totalIPLen & 0xff)
	ipHdr[8] = 64         // TTL
	ipHdr[9] = IPProtoTCP // Protocol TCP (6)
	copy(ipHdr[12:16], srcIP[:])
	copy(ipHdr[16:20], dstIP[:])

	tcpHdr := make([]byte, 20)
	tcpHdr[0] = byte(srcPort >> 8)
	tcpHdr[1] = byte(srcPort & 0xff)
	tcpHdr[2] = byte(dstPort >> 8)
	tcpHdr[3] = byte(dstPort & 0xff)
	tcpHdr[12] = 5 << 4 // Data Offset = 5 (20 bytes)

	frame := append(ethHdr, ipHdr...)
	frame = append(frame, tcpHdr...)
	frame = append(frame, payload...)
	return frame
}

// TestProcessEthernetFrame_ShortFrames verifies that packets smaller than the minimum
// Ethernet header length (14 bytes) or smaller than the IPv4 minimum header length (20 bytes)
// are safely ignored without causing panics or index out of range runtime exceptions.
func TestProcessEthernetFrame_ShortFrames(t *testing.T) {
	rec := &MockRecorder{}
	obs := NewObserverWithRecorder(Config{UDPPort: 9001, TCPPort: 9000}, rec)

	// Under Ethernet header length (< 14 bytes)
	obs.processEthernetFrame([]byte{0x01, 0x02, 0x03})
	// Exactly 14 bytes, but no IP header (< 34 bytes)
	obs.processEthernetFrame(make([]byte, 14))

	if len(rec.PingPongEvents) != 0 || len(rec.TCPEvents) != 0 {
		t.Fatalf("Expected no events for truncated frames, got %d ping/pong and %d TCP",
			len(rec.PingPongEvents), len(rec.TCPEvents))
	}
}

// TestProcessEthernetFrame_NonIPv4EtherType verifies that non-IPv4 link layer frames
// (such as ARP 0x0806 or IPv6 0x86dd) are ignored, ensuring that only standard IPv4
// traffic intended for Ifrit is processed.
func TestProcessEthernetFrame_NonIPv4EtherType(t *testing.T) {
	rec := &MockRecorder{}
	obs := NewObserverWithRecorder(Config{UDPPort: 9001, TCPPort: 9000}, rec)

	frame := make([]byte, 64)
	frame[12] = 0x08
	frame[13] = 0x06 // ARP (0x0806), not IPv4 (0x0800)

	obs.processEthernetFrame(frame)

	if len(rec.PingPongEvents) != 0 || len(rec.TCPEvents) != 0 {
		t.Fatalf("Expected non-IPv4 frames to be ignored, got events")
	}
}

// TestProcessEthernetFrame_TCPGossipTraffic verifies that valid TCP segments sent to the
// configured gossip port (9000) are decoded correctly from raw Ethernet frames, extracting
// the exact IP addresses, source/dest ports, and payload byte length for throughput metrics.
func TestProcessEthernetFrame_TCPGossipTraffic(t *testing.T) {
	rec := &MockRecorder{}
	obs := NewObserverWithRecorder(Config{UDPPort: 9001, TCPPort: 9000}, rec)

	payload := []byte("gRPC gossip data payload")
	frame := buildEthernetTCPPacket(
		[4]byte{172, 18, 0, 2},
		[4]byte{172, 18, 0, 3},
		54321,
		9000,
		payload,
	)

	obs.processEthernetFrame(frame)

	if len(rec.TCPEvents) != 1 {
		t.Fatalf("Expected 1 TCP event, got %d", len(rec.TCPEvents))
	}

	ev := rec.TCPEvents[0]
	if ev.SrcIP != "172.18.0.2" || ev.DstIP != "172.18.0.3" {
		t.Errorf("Unexpected IPs: src=%s, dst=%s", ev.SrcIP, ev.DstIP)
	}
	if ev.SrcPort != 54321 || ev.DstPort != 9000 {
		t.Errorf("Unexpected ports: src=%d, dst=%d", ev.SrcPort, ev.DstPort)
	}
	if ev.BytesLen != len(payload) {
		t.Errorf("Expected payload length %d, got %d", len(payload), ev.BytesLen)
	}
}

// TestProcessEthernetFrame_IgnoredPort verifies that traffic sent to non-monitored ports
// (e.g. port 80 HTTP, port 53 DNS) is discarded and does not produce spurious telemetry records.
func TestProcessEthernetFrame_IgnoredPort(t *testing.T) {
	rec := &MockRecorder{}
	obs := NewObserverWithRecorder(Config{UDPPort: 9001, TCPPort: 9000}, rec)

	// Send TCP to port 80 (HTTP) instead of 9000
	frame := buildEthernetTCPPacket(
		[4]byte{172, 18, 0, 2},
		[4]byte{172, 18, 0, 3},
		12345,
		80,
		[]byte("GET / HTTP/1.1"),
	)
	obs.processEthernetFrame(frame)

	if len(rec.TCPEvents) != 0 {
		t.Fatalf("Expected port 80 traffic to be ignored, recorded %d events", len(rec.TCPEvents))
	}
}

// TestProcessEthernetFrame_UDPPingAndPong verifies end-to-end passive RTT observation:
// 1. Synthesizes an outgoing UDP pb.Ping packet destined for failure detector port 9001 with a 32-byte nonce.
// 2. Verifies that the Observer logs the PING event and registers the pending challenge.
// 3. Synthesizes the returning UDP pb.Pong response with an ECDSA signature and matching nonce.
// 4. Verifies that the Observer correlates the Pong with the preceding Ping, records the PONG event,
//    and accurately calculates a positive Round-Trip Time (RTT > 0 ms).
func TestProcessEthernetFrame_UDPPingAndPong(t *testing.T) {
	rec := &MockRecorder{}
	obs := NewObserverWithRecorder(Config{UDPPort: 9001, TCPPort: 9000}, rec)

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	// 1. Synthesize and inject Ping packet (Node 1 -> Node 2:9001)
	pingMsg := &pb.Ping{Nonce: nonce}
	pingPayload, err := proto.Marshal(pingMsg)
	if err != nil {
		t.Fatalf("Failed to marshal Ping: %v", err)
	}

	pingFrame := buildEthernetUDPPacket(
		[4]byte{172, 18, 0, 2},
		[4]byte{172, 18, 0, 3},
		45678,
		9001,
		pingPayload,
	)

	obs.processEthernetFrame(pingFrame)

	if len(rec.PingPongEvents) != 1 {
		t.Fatalf("Expected 1 PING event recorded, got %d", len(rec.PingPongEvents))
	}
	pingEv := rec.PingPongEvents[0]
	if pingEv.EventType != "PING" {
		t.Errorf("Expected PING event type, got %s", pingEv.EventType)
	}
	if pingEv.RttMs != -1 {
		t.Errorf("Expected RTT -1 for PING, got %f", pingEv.RttMs)
	}

	// Simulate network round-trip delay
	time.Sleep(10 * time.Millisecond)

	// 2. Synthesize and inject Pong packet (Node 2:9001 -> Node 1:45678)
	pongMsg := &pb.Pong{
		Nonce: nonce,
		Signature: &pb.Signature{
			R: []byte{0x01, 0x02, 0x03},
			S: []byte{0x04, 0x05, 0x06},
		},
	}
	pongPayload, err := proto.Marshal(pongMsg)
	if err != nil {
		t.Fatalf("Failed to marshal Pong: %v", err)
	}

	pongFrame := buildEthernetUDPPacket(
		[4]byte{172, 18, 0, 3},
		[4]byte{172, 18, 0, 2},
		9001,
		45678,
		pongPayload,
	)

	obs.processEthernetFrame(pongFrame)

	if len(rec.PingPongEvents) != 2 {
		t.Fatalf("Expected 2 events total (PING and PONG), got %d", len(rec.PingPongEvents))
	}

	pongEv := rec.PingPongEvents[1]
	if pongEv.EventType != "PONG" {
		t.Errorf("Expected PONG event type, got %s", pongEv.EventType)
	}
	if pongEv.RttMs <= 0 {
		t.Errorf("Expected positive RTT ms for matched PONG, got %f", pongEv.RttMs)
	}
	if pongEv.NonceHex != pingEv.NonceHex {
		t.Errorf("Expected matching nonce hex %s, got %s", pingEv.NonceHex, pongEv.NonceHex)
	}
}
