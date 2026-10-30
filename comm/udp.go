package comm

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	log "github.com/inconshreveable/log15"
	pb "github.com/joonnna/ifrit/protobuf"
)

// udpBufferSize defines the maximum UDP receive buffer size for ping/pong datagrams.
// Set to 4096 bytes to accommodate large P-521 ECDSA signatures, nonces, and framed fingerprints
// without risking packet truncation.
const udpBufferSize = 4096

type UDPServer struct {
	conn *net.UDPConn
	addr string

	exitChan  chan bool
	pauseChan chan time.Duration

	pongSigner
	timeout time.Duration

	fpDataProvider func() []byte
	fpDataMutex    sync.RWMutex

	fpAccProvider func() []byte
	fpAccMutex    sync.RWMutex

	fpViewProvider func() []byte
	fpViewMutex    sync.RWMutex
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

			fpData := us.getFingerprintData()
			fpAcc := us.getFingerprintAccusations()
			fpView := us.getFingerprintView()
			content := us.PongContent(ping.GetNonce(), fpData, fpAcc, fpView)
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
				FingerprintData:        fpData,
				FingerprintAccusations: fpAcc,
				FingerprintView:        fpView,
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

func (us *UDPServer) SetFingerprintDataProvider(f func() []byte) {
	us.fpDataMutex.Lock()
	defer us.fpDataMutex.Unlock()
	us.fpDataProvider = f
}

func (us *UDPServer) SetFingerprintData(fp []byte) {
	us.SetFingerprintDataProvider(func() []byte { return fp })
}

func (us *UDPServer) getFingerprintData() []byte {
	us.fpDataMutex.RLock()
	defer us.fpDataMutex.RUnlock()
	if us.fpDataProvider != nil {
		return us.fpDataProvider()
	}
	return nil
}

func (us *UDPServer) SetFingerprintAccusationsProvider(f func() []byte) {
	us.fpAccMutex.Lock()
	defer us.fpAccMutex.Unlock()
	us.fpAccProvider = f
}

func (us *UDPServer) SetFingerprintAccusations(fp []byte) {
	us.SetFingerprintAccusationsProvider(func() []byte { return fp })
}

func (us *UDPServer) getFingerprintAccusations() []byte {
	us.fpAccMutex.RLock()
	defer us.fpAccMutex.RUnlock()
	if us.fpAccProvider != nil {
		return us.fpAccProvider()
	}
	return nil
}

func (us *UDPServer) SetFingerprintViewProvider(f func() []byte) {
	us.fpViewMutex.Lock()
	defer us.fpViewMutex.Unlock()
	us.fpViewProvider = f
}

func (us *UDPServer) SetFingerprintView(fp []byte) {
	us.SetFingerprintViewProvider(func() []byte { return fp })
}

func (us *UDPServer) getFingerprintView() []byte {
	us.fpViewMutex.RLock()
	defer us.fpViewMutex.RUnlock()
	if us.fpViewProvider != nil {
		return us.fpViewProvider()
	}
	return nil
}

// Backwards-compatible aliases:
func (us *UDPServer) SetFingerprintProvider(f func() []byte) {
	us.SetFingerprintDataProvider(f)
}

func (us *UDPServer) SetFingerprint(fp []byte) {
	us.SetFingerprintData(fp)
}

func (us *UDPServer) getFingerprint() []byte {
	return us.getFingerprintData()
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
