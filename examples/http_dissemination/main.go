package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	log "github.com/inconshreveable/log15"
)

func main() {
	httpPort := flag.Int("http-port", 8080, "HTTP server listening port")
	tcpPort := flag.Int("tcp-port", 9000, "Ifrit TCP port")
	udpPort := flag.Int("udp-port", 9001, "Ifrit UDP port")
	caAddr := flag.String("ca-addr", "127.0.0.1:8321", "Ifrit Certificate Authority address")
	hostname := flag.String("hostname", "localhost", "Hostname for X.509 certificate")
	cryptoDir := flag.String("crypto-dir", "", "Path for cryptographic keys and certificates")
	gossipInterval := flag.Int("gossip-interval", 1, "Gossip round interval in seconds")
	flag.Parse()

	// Environment variable overrides
	if p := os.Getenv("HTTP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			*httpPort = v
		}
	}
	if p := os.Getenv("IFRIT_TCP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			*tcpPort = v
		}
	}
	if p := os.Getenv("IFRIT_UDP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			*udpPort = v
		}
	}
	if addr := os.Getenv("CA_ADDR"); addr != "" {
		*caAddr = addr
	}
	if h := os.Getenv("IFRIT_HOSTNAME"); h != "" {
		*hostname = h
	}
	if d := os.Getenv("CRYPTO_DIR"); d != "" {
		*cryptoDir = d
	}
	if gi := os.Getenv("GOSSIP_INTERVAL"); gi != "" {
		if v, err := strconv.Atoi(gi); err == nil {
			*gossipInterval = v
		}
	}

	app, err := NewApp(&AppConfig{
		HTTPPort:       *httpPort,
		TCPPort:        *tcpPort,
		UDPPort:        *udpPort,
		Hostname:       *hostname,
		CaAddr:         *caAddr,
		CertPath:       *cryptoDir,
		GossipInterval: *gossipInterval,
		NewCrypto:      true,
	})
	if err != nil {
		log.Error("failed to initialize application", "err", err)
		os.Exit(1)
	}

	app.Start()
	fmt.Printf("Ifrit HTTP Node listening on %s (Ifrit TCP: %d, UDP: %d)\n", app.HTTPAddr(), *tcpPort, *udpPort)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down Ifrit HTTP Node...")
	app.Stop()
	fmt.Println("Shutdown complete.")
}
