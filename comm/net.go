package comm

import (
	"errors"
	"fmt"
	"net"
	"os"

	log "github.com/inconshreveable/log15"
)

var (
	ErrFoundNoPort = errors.New("could not find any available port")
)

// ListenOnPort attempts to listen on the given TCP port, incrementing up to 100 times if occupied.
func ListenOnPort(port int) (net.Listener, error) {
	startPort := port

	for {
		l, err := net.Listen("tcp4", fmt.Sprintf(":%d", startPort))
		if err == nil {
			return l, nil
		}

		if startPort > (port + 100) {
			log.Error(err.Error())
			return nil, ErrFoundNoPort
		}

		startPort++
	}
}

// GetListener attempts to bind a TCP listener on the specified port, incrementing up to 100 times.
// Returns the listener, the full host:port address string, or an error.
func GetListener(hostname string, portnum int) (net.Listener, string, error) {
	h, err := os.Hostname()
	if err != nil {
		return nil, "", err
	}

	addr, err := net.LookupHost(h)
	if err != nil {
		return nil, "", err
	}

	if hostname != "" {
		addr[0] = hostname
	}

	attempts := 0
	for {
		l, err := net.Listen("tcp4", fmt.Sprintf(":%d", portnum))
		if err == nil {
			tcpAddr := l.Addr().(*net.TCPAddr)
			fullAddr := fmt.Sprintf("%s:%d", addr[0], tcpAddr.Port)
			return l, fullAddr, nil
		} else {
			log.Error(err.Error())
		}
		attempts++
		portnum++

		if attempts > 100 {
			break
		}
	}

	return nil, "", ErrFoundNoPort
}

// ListenUdp binds a UDP connection on the specified port.
// Returns the connection, the full host:port address string, or an error.
func ListenUdp(hostname string, portnum int) (*net.UDPConn, string, error) {
	h, err := os.Hostname()
	if err != nil {
		return nil, "", err
	}

	addr, err := net.LookupHost(h)
	if err != nil {
		return nil, "", err
	}

	if hostname != "" {
		addr[0] = hostname
	}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", portnum))
	if err != nil {
		return nil, "", err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, "", err
	}

	actualUdpAddr := conn.LocalAddr().(*net.UDPAddr)
	fullAddr := fmt.Sprintf("%s:%d", addr[0], actualUdpAddr.Port)

	return conn, fullAddr, nil
}

// GetLocalIP returns the first non-loopback IPv4 address found on active network interfaces.
func GetLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}
