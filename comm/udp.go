package comm

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	pb "github.com/eika123/ifrit/protobuf"
	"github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
)

// udpBufferSize defines the maximum UDP receive buffer size for ping/pong datagrams.
// Set to 4096 bytes to accommodate large P-521 ECDSA signatures, nonces, and framed fingerprints
// without risking packet truncation.
const udpBufferSize = 4096

// Fingerprints bundles the three 8-byte store fingerprints piggybacked on UDP Pong replies.
type Fingerprints struct {
	Data        []byte
	Accusations []byte
	View        []byte
}

type UDPServer struct {
	conn *net.UDPConn
	addr string

	exitChan  chan bool
	pauseChan chan time.Duration

	pongSigner
	timeout time.Duration

	fpProvider func() Fingerprints
	fpMutex    sync.RWMutex
}

type pongSigner interface {
	Sign([]byte) ([]byte, []byte, error)
}

func NewUdpServer(ps pongSigner, conn *net.UDPConn, timeout time.Duration) (*UDPServer, error) {
	if timeout <= 0 {
		timeout = time.Second * 5
	}
	return &UDPServer{
		conn:       conn,
		exitChan:   make(chan bool, 1),
		pauseChan:  make(chan time.Duration, 1),
		pongSigner: ps,
		timeout:    timeout,
	}, nil
}

func (us *UDPServer) Ping(addr string, p *pb.Ping) (*pb.Pong, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	c, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(us.timeout))

	data, err := proto.Marshal(p)
	if err != nil {
		return nil, err
	}

	_, err = c.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := make([]byte, udpBufferSize)

	n, err := c.Read(bytes)
	if err != nil {
		return nil, err
	}

	pong := &pb.Pong{}

	err = proto.Unmarshal(bytes[:n], pong)
	if err != nil {
		return nil, err
	}

	return pong, nil
}

func (us *UDPServer) Start() {
	bytes := make([]byte, udpBufferSize)
	for {
		select {
		case d := <-us.pauseChan:
			time.Sleep(d)
		case <-us.exitChan:
			return
		default:
			n, addr, err := us.conn.ReadFrom(bytes)
			if err != nil {
				log.Error(err.Error())
				continue
			}

			var ping pb.Ping
			if err := proto.Unmarshal(bytes[:n], &ping); err != nil {
				log.Error("failed to unmarshal ping", "err", err)
				continue
			}

			fps := us.getFingerprints()
			content := us.PongContent(ping.GetNonce(), fps.Data, fps.Accusations, fps.View)
			r, s, err := us.Sign(content)
			if err != nil {
				log.Error(err.Error())
				continue
			}

			pong := &pb.Pong{
				Nonce: ping.GetNonce(),
				Signature: &pb.Signature{
					R: r,
					S: s,
				},
				FingerprintData:        fps.Data,
				FingerprintAccusations: fps.Accusations,
				FingerprintView:        fps.View,
			}

			resp, err := proto.Marshal(pong)
			if err != nil {
				log.Error(err.Error())
				continue
			}

			us.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
			_, err = us.conn.WriteTo(resp, addr)
			if err != nil {
				log.Error(err.Error())
				continue
			}
		}
	}
}

// SetFingerprintsProvider registers a dynamic callback returning current store fingerprints for Pong replies.
func (us *UDPServer) SetFingerprintsProvider(f func() Fingerprints) {
	us.fpMutex.Lock()
	defer us.fpMutex.Unlock()
	us.fpProvider = f
}

// SetFingerprints sets static fingerprints for Pong replies.
func (us *UDPServer) SetFingerprints(fp Fingerprints) {
	us.SetFingerprintsProvider(func() Fingerprints { return fp })
}

func (us *UDPServer) getFingerprints() Fingerprints {
	us.fpMutex.RLock()
	defer us.fpMutex.RUnlock()
	if us.fpProvider != nil {
		return us.fpProvider()
	}
	return Fingerprints{}
}

func (us *UDPServer) Addr() string {
	return us.addr
}

func (us *UDPServer) Pause(d time.Duration) {
	us.pauseChan <- d
}

func (us *UDPServer) Stop() {
	close(us.exitChan)
	us.conn.Close()
}

func appendFramed(dst []byte, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, field...)
}

// PongContent returns the canonical serialized semantic content of a Pong message (nonce, fingerprint_data, fingerprint_accusations, and fingerprint_view)
// using length-prefixed framing to prevent field-boundary shifting attacks.
func PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte) []byte {
	totalLen := 4*4 + len(nonce) + len(fpData) + len(fpAcc) + len(fpView)
	content := make([]byte, 0, totalLen)
	content = appendFramed(content, nonce)
	content = appendFramed(content, fpData)
	content = appendFramed(content, fpAcc)
	content = appendFramed(content, fpView)
	return content
}

func (us *UDPServer) PongContent(nonce []byte, fpData []byte, fpAcc []byte, fpView []byte) []byte {
	return PongContent(nonce, fpData, fpAcc, fpView)
}
