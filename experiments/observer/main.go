package main

import (
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/joonnna/ifrit/protobuf"
	_ "github.com/mattn/go-sqlite3"
)

const (
	// MaxPacketBufferSize accommodates max standard jumbo frame and MTU sizes
	MaxPacketBufferSize = 65535

	// Ethernet frame constants
	EthernetHeaderLen = 14
	EtherTypeIPv4     = 0x0800

	// IPv4 constants
	IPv4MinHeaderLen = 20
	IPProtoTCP       = 6
	IPProtoUDP       = 17

	// Transport header minimum lengths
	UDPHeaderLen    = 8
	TCPMinHeaderLen = 20
)

// Config holds runtime options for the passive network observer.
type Config struct {
	Interface string
	DBPath    string
	UDPPort   int
	TCPPort   int
}

type pendingPing struct {
	nonceHex string
	sentAt   time.Time
}

// Observer coordinates passive sniffing and writing metrics into SQLite.
type Observer struct {
	cfg     Config
	db      *sql.DB
	dbLock  sync.Mutex
	stopCh  chan struct{}
	pingsMu sync.Mutex
	// Pending pings mapped by "srcIP:srcPort->dstIP:dstPort" and nonceHex
	pendingByFlow  map[string]pendingPing
	pendingByNonce map[string]time.Time
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.Interface, "iface", "any", "Network interface or bridge to sniff on (e.g., eth0, ifrit-net, any)")
	flag.StringVar(&cfg.DBPath, "db", "experiment_results/network_telemetry.db", "SQLite output database path")
	flag.IntVar(&cfg.UDPPort, "udp-port", 9001, "UDP port for failure detection ping/pong")
	flag.IntVar(&cfg.TCPPort, "tcp-port", 9000, "TCP port for gRPC gossip traffic")
	flag.Parse()

	log.Printf("Starting Ifrit Network Observer on iface '%s' -> DB '%s'\n", cfg.Interface, cfg.DBPath)

	obs, err := NewObserver(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize observer: %v", err)
	}
	defer obs.Close()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go obs.Start()

	<-sigCh
	log.Println("Shutting down network observer...")
	obs.Stop()
}

func NewObserver(cfg Config) (*Observer, error) {
	db, err := sql.Open("sqlite3", cfg.DBPath+"?_journal_mode=WAL&_busy_timeout=5000&_sync=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Initialize tables
	schema := `
	CREATE TABLE IF NOT EXISTS ping_pong_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT,
		event_type TEXT, -- 'PING' or 'PONG'
		src_ip TEXT,
		src_port INTEGER,
		dst_ip TEXT,
		dst_port INTEGER,
		nonce_hex TEXT,
		rtt_ms REAL -- Only populated for matched PONG
	);

	CREATE TABLE IF NOT EXISTS tcp_traffic_stats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT,
		src_ip TEXT,
		src_port INTEGER,
		dst_ip TEXT,
		dst_port INTEGER,
		packet_bytes INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_ping_nonce ON ping_pong_events(nonce_hex);
	CREATE INDEX IF NOT EXISTS idx_tcp_ts ON tcp_traffic_stats(timestamp);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return &Observer{
		cfg:            cfg,
		db:             db,
		stopCh:         make(chan struct{}),
		pendingByFlow:  make(map[string]pendingPing),
		pendingByNonce: make(map[string]time.Time),
	}, nil
}

func (obs *Observer) Start() {
	// Raw socket packet sniffer (AF_PACKET on Linux)
	// ETH_P_ALL = 0x0003 (captures all incoming and outgoing IP packets)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(hostToNetwork16(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("Failed to open raw socket (ensure CAP_NET_RAW / root): %v", err)
	}
	defer syscall.Close(fd)

	buf := make([]byte, MaxPacketBufferSize)
	for {
		select {
		case <-obs.stopCh:
			return
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-obs.stopCh:
				return
			default:
				continue
			}
		}

		if n < EthernetHeaderLen {
			continue // Less than Ethernet header
		}

		obs.processEthernetFrame(buf[:n])
	}
}

func (obs *Observer) Stop() {
	close(obs.stopCh)
}

func (obs *Observer) Close() {
	obs.dbLock.Lock()
	defer obs.dbLock.Unlock()
	if obs.db != nil {
		obs.db.Close()
	}
}

// processEthernetFrame parses IP, UDP, and TCP headers without external CGO/pcap libraries.
func (obs *Observer) processEthernetFrame(data []byte) {

	// IEEE 802.3 Ethernet "Packet",
	// (p.85: TCP/IP Illustrated, Volume 1, Second Edition, Kevin R. Fall, W. Richard Stevens)

	// Layout of IEEE 802.3 Ethernet "Packet"
	// |-- 7 -- | 1 |  64 - 1518     | 4 | -------------- x ---------------- |
	// |preamble|SFD| Ethernet Frame |FCS|Carrier Extension (1/2 duplex only)|
	// Note: Carrier Extension (1/2 duplex only): Variable length x

	// ---------------------------------------------------------------------------------------------
	// "Ethernet Frame"
	// (p.85: TCP/IP Illustrated, Volume 1, Second Edition, Kevin R. Fall, W. Richard Stevens)
	//  payload typically IPV4, in our case, with MTU = 1500 bytes.

	//	|    6      |    6        |     2      |  0/2      | 0/482      | 64 / 1518 | 0/46    |
	//  | dest addr | source addr | Type / Len | P / Q Tag | Other tags | payload   | Padding |
	// ---------------------------------------------------------------------------------------------

	// ---------------------------------------------------------------------------------------------
	// 	  p. 182, "TCP/IP Illustrated, Volume 1, Second Edition, Kevin R. Fall, W. Richard Stevens"
	// 	    0                   1                   2                   3
	//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |Version|  IHL  |   DSField |ecn|          Total Length         |  Bytes 0..3
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |         Identification        |Flags|      Fragment Offset    |  Bytes 4..7
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |  Time to Live |    Protocol   |         Header Checksum       |  Bytes 8..11
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |                       Source Address                          |  Bytes 12..15
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |                    Destination Address                        |  Bytes 16..19
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |                    Options                                    |  Bytes 20.. (optional)
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    <----------------------------IPv4 Payload----------------------->

	//    for us, assume the payload is fragmented if necessary, so up to 1480 bytes maximum.
	// ---------------------------------------------------------------------------------------------

	// Reconstruct little endian 16bit (2byte) from BigEndian two bytes.
	//                          MSB            LSB
	etherType := (uint16(data[12]) << 8) | uint16(data[13])
	if etherType != EtherTypeIPv4 { // Only IPv4 for now
		return
	}

	// Correctness of this assumes that the "P / Q tag" and "Other tags" fields are empty.
	// But we know that the frame is etherType == EtherTypeIPv4 == 0x0800 and Q-tagged as 0x8100,
	// so we can safely ignore the "P / Q tag" and "Other tags" fields.
	//
	// There is a possibility the ipPacket is smaller than 64 bytes, the minimum Ethernet frame size;
	// But we know the headr is at least 20 bytes long, and includes the total lenght field, so if the
	// total ethernet payload is smaller than the required 64 bytes we can infer the padding size from
	// the Total Length field.
	// See p 184 TCP/IP Illustrated, Volume 1, Second Edition, Kevin R. Fall, W. Richard Stevens.
	ipPacket := data[EthernetHeaderLen:]
	if len(ipPacket) < IPv4MinHeaderLen {
		return
	}

	// The first 4 bits of the first byte of the IPv4 header contain the version (always 4 for IPv4).
	// The next 4 bits contain the Internet Header Length (IHL), which is the number of 32-bit words in the header.
	ipv4HeaderLength := int(ipPacket[0]&0x0F) * 4
	if len(ipPacket) < ipv4HeaderLength {
		return
	}

	// Byte 9 is the Protocol field (6 for TCP, 17 for UDP).
	// Bytes 12..15 contain the 4-byte Source IP, and bytes 16..19 contain Destination IP.
	protocol := ipPacket[9]
	srcIP := net.IP(ipPacket[12:16]).String()
	dstIP := net.IP(ipPacket[16:20]).String()

	payload := ipPacket[ipv4HeaderLength:]

	switch protocol {
	case IPProtoUDP:
		if len(payload) < UDPHeaderLen {
			return
		}
		// RFC 768 page 1
		srcPort := int(uint16(payload[0])<<8 | uint16(payload[1]))
		dstPort := int(uint16(payload[2])<<8 | uint16(payload[3]))
		udpPayload := payload[UDPHeaderLen:]

		// filters away UDP traffic not destined for our observer
		if srcPort == obs.cfg.UDPPort || dstPort == obs.cfg.UDPPort {
			obs.handleUDPPacket(srcIP, dstIP, srcPort, dstPort, udpPayload)
		}

	case IPProtoTCP:
		if len(payload) < TCPMinHeaderLen {
			return
		}
		// RFC 9293 section 3.1, note data offset is the length of the TCP header in 32-bit words
		// https://www.rfc-editor.org/info/rfc9293/#section-3.1
		srcPort := int(uint16(payload[0])<<8 | uint16(payload[1]))
		dstPort := int(uint16(payload[2])<<8 | uint16(payload[3]))
		tcpHeaderLen := int((payload[12] >> 4) * 4)

		// filters away TCP traffic not destined for our observer
		if srcPort == obs.cfg.TCPPort || dstPort == obs.cfg.TCPPort {
			tcpPayloadLen := len(payload) - tcpHeaderLen
			if tcpPayloadLen > 0 {
				obs.handleTCPTraffic(srcIP, dstIP, srcPort, dstPort, tcpPayloadLen)
			}
		}
	}
}

// handleUDPPacket deserializes unencrypted Protobuf Ping and Pong payloads.
func (obs *Observer) handleUDPPacket(srcIP, dstIP string, srcPort, dstPort int, payload []byte) {
	now := time.Now()
	// 24h format: <hour:24h>:<min>:<sec>.<msec>
	nowStr := now.Format("15:04:05.000")

	// In Ifrit:
	// - Ping contains Nonce (32 bytes), Signature is nil.
	// - Pong contains Signature (R, S), while Nonce is omitted/empty.
	//
	// Try unmarshaling as Pong first:
	var pong pb.Pong
	// final two checks for R>0 and S>0: check that signature (r, s) pair is not (0, 0).
	if err := proto.Unmarshal(payload, &pong); err == nil && pong.GetSignature() != nil && len(pong.GetSignature().GetR()) > 0 && len(pong.GetSignature().GetS()) > 0 {
		var rttMs float64 = -1
		var nonceHex string

		// If pong includes nonce, match by nonce; otherwise match by reverse UDP flow (dst -> src)
		if len(pong.GetNonce()) > 0 {
			nonceHex = hex.EncodeToString(pong.GetNonce())
			obs.pingsMu.Lock()
			if sentTime, exists := obs.pendingByNonce[nonceHex]; exists {
				rttMs = float64(now.Sub(sentTime).Microseconds()) / 1000.0
				delete(obs.pendingByNonce, nonceHex)
			}
			obs.pingsMu.Unlock()
		} else {
			// Reverse flow key: the original Ping was sent from (dstIP:dstPort) to (srcIP:srcPort)
			flowKey := fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
			obs.pingsMu.Lock()
			if p, exists := obs.pendingByFlow[flowKey]; exists {
				rttMs = float64(now.Sub(p.sentAt).Microseconds()) / 1000.0
				nonceHex = p.nonceHex
				delete(obs.pendingByFlow, flowKey)
				delete(obs.pendingByNonce, p.nonceHex)
			}
			obs.pingsMu.Unlock()
		}

		obs.insertPingPong(nowStr, "PONG", srcIP, srcPort, dstIP, dstPort, nonceHex, rttMs)
		return
	}

	// Try unmarshaling as Ping:
	var ping pb.Ping
	if err := proto.Unmarshal(payload, &ping); err == nil && len(ping.GetNonce()) > 0 {
		nonceHex := hex.EncodeToString(ping.GetNonce())
		flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

		obs.pingsMu.Lock()
		obs.pendingByNonce[nonceHex] = now
		obs.pendingByFlow[flowKey] = pendingPing{
			nonceHex: nonceHex,
			sentAt:   now,
		}
		obs.pingsMu.Unlock()

		obs.insertPingPong(nowStr, "PING", srcIP, srcPort, dstIP, dstPort, nonceHex, -1)
	}
}

func (obs *Observer) handleTCPTraffic(srcIP, dstIP string, srcPort, dstPort, bytesLen int) {
	// 24h format: <hour:24h>:<min>:<sec>
	nowStr := time.Now().Format("15:04:05")

	obs.dbLock.Lock()
	defer obs.dbLock.Unlock()
	_, _ = obs.db.Exec(`
		INSERT INTO tcp_traffic_stats (timestamp, src_ip, src_port, dst_ip, dst_port, packet_bytes)
		VALUES (?, ?, ?, ?, ?, ?)
	`, nowStr, srcIP, srcPort, dstIP, dstPort, bytesLen)
}

func (obs *Observer) insertPingPong(timestamp, eventType, srcIP string, srcPort int, dstIP string, dstPort int, nonceHex string, rttMs float64) {
	obs.dbLock.Lock()
	defer obs.dbLock.Unlock()

	var rttVal sql.NullFloat64
	if rttMs >= 0 {
		rttVal = sql.NullFloat64{Float64: rttMs, Valid: true}
	}

	_, _ = obs.db.Exec(`
		INSERT INTO ping_pong_events (timestamp, event_type, src_ip, src_port, dst_ip, dst_port, nonce_hex, rtt_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, timestamp, eventType, srcIP, srcPort, dstIP, dstPort, nonceHex, rttVal)
}

// hostToNetwork16 converts a 16-bit integer from host byte order (Little-Endian on x86/ARM)
// to network byte order (Big-Endian), as the network layers encode everythin in Big-Endian.
// This is needed for the AF_PACKET raw socket to filter packets correctly.
func hostToNetwork16(i uint16) uint16 {
	return (i<<8)&0xff00 | (i>>8)&0x00ff
}
