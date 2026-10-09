package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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
	UseEBPF   bool
}

type pendingPing struct {
	nonceHex string
	sentAt   time.Time
}

// TelemetryRecorder abstracts persistent storage of network metrics.
type TelemetryRecorder interface {
	RecordPingPong(timestamp, eventType, srcIP string, srcPort int, dstIP string, dstPort int, nonceHex string, rttMs float64) error
	RecordTCP(timestamp, srcIP string, srcPort int, dstIP string, dstPort int, bytesLen int) error
	Close() error
}

// SQLiteRecorder implements TelemetryRecorder using SQLite.
type SQLiteRecorder struct {
	db     *sql.DB
	dbLock sync.Mutex
}

func NewSQLiteRecorder(dbPath string) (*SQLiteRecorder, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_sync=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

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

	return &SQLiteRecorder{db: db}, nil
}

func (r *SQLiteRecorder) RecordPingPong(timestamp, eventType, srcIP string, srcPort int, dstIP string, dstPort int, nonceHex string, rttMs float64) error {
	r.dbLock.Lock()
	defer r.dbLock.Unlock()

	var rttVal sql.NullFloat64
	if rttMs >= 0 {
		rttVal = sql.NullFloat64{Float64: rttMs, Valid: true}
	}

	_, err := r.db.Exec(`
		INSERT INTO ping_pong_events (timestamp, event_type, src_ip, src_port, dst_ip, dst_port, nonce_hex, rtt_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, timestamp, eventType, srcIP, srcPort, dstIP, dstPort, nonceHex, rttVal)
	return err
}

func (r *SQLiteRecorder) RecordTCP(timestamp, srcIP string, srcPort int, dstIP string, dstPort int, bytesLen int) error {
	r.dbLock.Lock()
	defer r.dbLock.Unlock()

	_, err := r.db.Exec(`
		INSERT INTO tcp_traffic_stats (timestamp, src_ip, src_port, dst_ip, dst_port, packet_bytes)
		VALUES (?, ?, ?, ?, ?, ?)
	`, timestamp, srcIP, srcPort, dstIP, dstPort, bytesLen)
	return err
}

func (r *SQLiteRecorder) Close() error {
	r.dbLock.Lock()
	defer r.dbLock.Unlock()
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// Observer coordinates passive sniffing and passing decoded frames to a TelemetryRecorder.
type Observer struct {
	cfg      Config
	recorder TelemetryRecorder
	stopCh   chan struct{}
	pingsMu  sync.Mutex
	// Pending pings mapped by "srcIP:srcPort->dstIP:dstPort" and nonceHex
	pendingByFlow  map[string]pendingPing
	pendingByNonce map[string]time.Time
	udpEventCount  uint64
	tcpEventCount  uint64
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.Interface, "iface", "any", "Network interface or bridge to sniff on (e.g., eth0, ifrit-net, any)")
	flag.StringVar(&cfg.DBPath, "db", "experiment_results/network_telemetry.db", "SQLite output database path")
	flag.IntVar(&cfg.UDPPort, "udp-port", 9001, "UDP port for failure detection ping/pong")
	flag.IntVar(&cfg.TCPPort, "tcp-port", 9000, "TCP port for gRPC gossip traffic")
	flag.BoolVar(&cfg.UseEBPF, "ebpf", true, "Use eBPF TC filter and RingBuffer instead of raw socket sniffer")
	flag.Parse()

	log.Printf("Starting Ifrit Network Observer (eBPF: %v) on iface '%s' -> DB '%s'\n", cfg.UseEBPF, cfg.Interface, cfg.DBPath)

	recorder, err := NewSQLiteRecorder(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	obs := NewObserverWithRecorder(cfg, recorder)
	defer obs.Close()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go obs.Start()

	<-sigCh
	log.Println("Shutting down network observer...")
	obs.Stop()
}

// NewObserver creates an Observer using a SQLite recorder.
func NewObserver(cfg Config) (*Observer, error) {
	rec, err := NewSQLiteRecorder(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	return NewObserverWithRecorder(cfg, rec), nil
}

// NewObserverWithRecorder creates an Observer injected with any TelemetryRecorder.
func NewObserverWithRecorder(cfg Config, rec TelemetryRecorder) *Observer {
	return &Observer{
		cfg:            cfg,
		recorder:       rec,
		stopCh:         make(chan struct{}),
		pendingByFlow:  make(map[string]pendingPing),
		pendingByNonce: make(map[string]time.Time),
	}
}

func (obs *Observer) Start() {
	if obs.cfg.UseEBPF {
		obs.startEBPF()
		return
	}
	obs.startRawSocket()
}

func (obs *Observer) startEBPF() {
	// Remove memory limits on locked memory for BPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Warning: failed to remove memlock limit: %v\n", err)
	}

	spec, err := loadFilter()
	if err != nil {
		log.Fatalf("Failed to load eBPF collection spec: %v", err)
	}

	// Rewrite runtime port constants in .rodata
	if varTCP, ok := spec.Variables["gossip_tcp_port"]; ok {
		if err := varTCP.Set(uint16(obs.cfg.TCPPort)); err != nil {
			log.Printf("Warning: failed to set gossip_tcp_port: %v\n", err)
		}
	}
	if varUDP, ok := spec.Variables["ping_udp_port"]; ok {
		if err := varUDP.Set(uint16(obs.cfg.UDPPort)); err != nil {
			log.Printf("Warning: failed to set ping_udp_port: %v\n", err)
		}
	}

	var objs filterObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects into kernel: %v", err)
	}
	defer objs.Close()

	// Find or auto-discover the network interface
	iface := obs.resolveInterface(obs.cfg.Interface)
	log.Printf("Selected network interface '%s' (index %d) for eBPF attachment\n", iface.Name, iface.Index)

	var (
		linksMu     sync.Mutex
		activeLinks = make(map[string]link.Link)
	)

	attachTCX := func(name string, index int, attachType ebpf.AttachType) {
		linksMu.Lock()
		defer linksMu.Unlock()
		key := fmt.Sprintf("%s-%v", name, attachType)
		if _, exists := activeLinks[key]; exists {
			return
		}
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: index,
			Program:   objs.TcPacketFilter,
			Attach:    attachType,
		})
		if err != nil {
			log.Printf("Warning: failed to attach TCX %v to '%s': %v\n", attachType, name, err)
			return
		}
		activeLinks[key] = l
		log.Printf("Successfully attached eBPF TC filter (%v) to '%s' (index %d)\n", attachType, name, index)
	}

	// Always attach to primary interface on Ingress and Egress
	attachTCX(iface.Name, iface.Index, ebpf.AttachTCXIngress)
	attachTCX(iface.Name, iface.Index, ebpf.AttachTCXEgress)

	// If the selected interface is a Linux bridge, attach TC Ingress to all slave veth interfaces
	if isBridgeInterface(iface.Name) {
		log.Printf("Interface '%s' is a Linux bridge; discovering and attaching to slave ports (veth)...\n", iface.Name)
		for _, slaveName := range getBridgeSlaves(iface.Name) {
			if sIface, err := net.InterfaceByName(slaveName); err == nil {
				attachTCX(sIface.Name, sIface.Index, ebpf.AttachTCXIngress)
			}
		}

		// Dynamic watcher goroutine to attach to any new container veth interfaces spawned during experiment
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-obs.stopCh:
					return
				case <-ticker.C:
					for _, slaveName := range getBridgeSlaves(iface.Name) {
						linksMu.Lock()
						key := fmt.Sprintf("%s-%v", slaveName, ebpf.AttachTCXIngress)
						_, attached := activeLinks[key]
						linksMu.Unlock()
						if !attached {
							if sIface, err := net.InterfaceByName(slaveName); err == nil {
								attachTCX(sIface.Name, sIface.Index, ebpf.AttachTCXIngress)
							}
						}
					}
				}
			}
		}()
	}

	defer func() {
		linksMu.Lock()
		defer linksMu.Unlock()
		for key, l := range activeLinks {
			_ = l.Close()
			delete(activeLinks, key)
		}
	}()

	// Open BPF RingBuffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ringbuffer reader: %v", err)
	}
	defer rd.Close()

	go func() {
		<-obs.stopCh
		_ = rd.Close()
	}()

	var event filterPacketEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			select {
			case <-obs.stopCh:
				return
			default:
				log.Printf("Error reading ringbuffer: %v\n", err)
				continue
			}
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Error decoding packet event: %v\n", err)
			continue
		}

		obs.processPacketEvent(&event)
	}
}

func (obs *Observer) processPacketEvent(event *filterPacketEvent) {
	// IP addresses are stored in network byte order (Big-Endian)
	srcIP := net.IPv4(byte(event.SrcIp), byte(event.SrcIp>>8), byte(event.SrcIp>>16), byte(event.SrcIp>>24)).String()
	dstIP := net.IPv4(byte(event.DstIp), byte(event.DstIp>>8), byte(event.DstIp>>16), byte(event.DstIp>>24)).String()

	srcPort := int(event.SrcPort)
	dstPort := int(event.DstPort)

	payloadLen := int(event.PayloadLen)
	if payloadLen > len(event.Payload) {
		payloadLen = len(event.Payload)
	}
	payload := event.Payload[:payloadLen]

	switch event.Protocol {
	case IPProtoUDP:
		if srcPort == obs.cfg.UDPPort || dstPort == obs.cfg.UDPPort {
			atomic.AddUint64(&obs.udpEventCount, 1)
			obs.handleUDPPacket(srcIP, dstIP, srcPort, dstPort, payload)
		}
	case IPProtoTCP:
		if srcPort == obs.cfg.TCPPort || dstPort == obs.cfg.TCPPort {
			atomic.AddUint64(&obs.tcpEventCount, 1)
			if int(event.PayloadLen) > 0 && obs.recorder != nil {
				nowStr := time.Now().Format("15:04:05")
				_ = obs.recorder.RecordTCP(nowStr, srcIP, srcPort, dstIP, dstPort, int(event.PayloadLen))
			}
		}
	}
}

func (obs *Observer) startRawSocket() {
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
	log.Printf("Network observer finished. Total captured: %d UDP events, %d TCP events\n",
		atomic.LoadUint64(&obs.udpEventCount), atomic.LoadUint64(&obs.tcpEventCount))
}

func (obs *Observer) Close() error {
	if obs.recorder != nil {
		return obs.recorder.Close()
	}
	return nil
}

// isBridgeInterface returns true if the specified network device is a Linux bridge.
func isBridgeInterface(ifaceName string) bool {
	bridgePath := filepath.Join("/sys/class/net", ifaceName, "bridge")
	if fi, err := os.Stat(bridgePath); err == nil && fi.IsDir() {
		return true
	}
	brifPath := filepath.Join("/sys/class/net", ifaceName, "brif")
	if fi, err := os.Stat(brifPath); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// getBridgeSlaves discovers all slave interfaces associated with a Linux bridge.
// It checks both /sys/class/net/<bridge>/brif/ and /sys/class/net/*/master.
func getBridgeSlaves(bridgeName string) []string {
	slavesMap := make(map[string]bool)

	// Method 1: Check sysfs bridge interface directory: /sys/class/net/<bridge>/brif/
	brifPath := filepath.Join("/sys/class/net", bridgeName, "brif")
	if entries, err := os.ReadDir(brifPath); err == nil {
		for _, entry := range entries {
			slavesMap[entry.Name()] = true
		}
	}

	// Method 2: Inspect all interfaces in /sys/class/net/*/master
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			masterPath := filepath.Join("/sys/class/net", iface.Name, "master")
			if target, err := os.Readlink(masterPath); err == nil {
				if filepath.Base(target) == bridgeName {
					slavesMap[iface.Name] = true
				}
			}
		}
	}

	var slaves []string
	for name := range slavesMap {
		slaves = append(slaves, name)
	}
	sort.Strings(slaves)
	return slaves
}

// resolveInterface resolves the target network interface or automatically discovers
// docker bridge devices (ifrit-br0, br-*, docker0) or interfaces containing "docker" or "ifrit".
func (obs *Observer) resolveInterface(target string) *net.Interface {
	lowerTarget := strings.ToLower(strings.TrimSpace(target))

	// Allow up to 15 seconds during container / network bootstrap
	deadline := time.Now().Add(15 * time.Second)

	for {
		// 1. If explicit interface given (e.g. "ifrit-br0" or "eth0"), check directly
		if lowerTarget != "" && lowerTarget != "any" && lowerTarget != "docker" && lowerTarget != "ifrit" {
			if iface, err := net.InterfaceByName(target); err == nil {
				return iface
			}
		}

		ifaces, err := net.Interfaces()
		if err == nil {
			// 2. Search for bridge with "ifrit" in the name (e.g., ifrit-br0)
			for _, i := range ifaces {
				name := strings.ToLower(i.Name)
				if strings.Contains(name, "ifrit") {
					log.Printf("Autodiscovered Ifrit interface: %s\n", i.Name)
					return &i
				}
			}

			// 3. Search for Docker compose bridges (usually br-<12char hex>)
			for _, i := range ifaces {
				if strings.HasPrefix(i.Name, "br-") {
					log.Printf("Autodiscovered Docker Compose bridge interface: %s\n", i.Name)
					return &i
				}
			}

			// 4. Search for standard docker0 bridge
			for _, i := range ifaces {
				if i.Name == "docker0" {
					log.Printf("Autodiscovered standard Docker bridge interface: %s\n", i.Name)
					return &i
				}
			}
		}

		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 5. Fallback to loopback
	if lo, err := net.InterfaceByName("lo"); err == nil {
		log.Println("No Docker bridge discovered after waiting; defaulting to loopback interface ('lo')")
		return lo
	}

	log.Fatalf("No suitable network interface found for eBPF attachment")
	return nil
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

	if len(data) < EthernetHeaderLen {
		return
	}

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
			if tcpPayloadLen > 0 && obs.recorder != nil {
				nowStr := time.Now().Format("15:04:05")
				_ = obs.recorder.RecordTCP(nowStr, srcIP, srcPort, dstIP, dstPort, tcpPayloadLen)
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
	// - Pong contains Signature (R, S), and echoes Nonce.
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

		if obs.recorder != nil {
			_ = obs.recorder.RecordPingPong(nowStr, "PONG", srcIP, srcPort, dstIP, dstPort, nonceHex, rttMs)
		}
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

		if obs.recorder != nil {
			_ = obs.recorder.RecordPingPong(nowStr, "PING", srcIP, srcPort, dstIP, dstPort, nonceHex, -1)
		}
	}
}

// hostToNetwork16 converts a 16-bit integer from host byte order (Little-Endian on x86/ARM)
// to network byte order (Big-Endian), as the network layers encode everythin in Big-Endian.
// This is needed for the AF_PACKET raw socket to filter packets correctly.
func hostToNetwork16(i uint16) uint16 {
	return (i<<8)&0xff00 | (i>>8)&0x00ff
}
