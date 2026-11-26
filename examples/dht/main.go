package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/eika123/ifrit"
	"github.com/eika123/ifrit/services/dht"
)

func main() {
	httpPort := flag.Int("http-port", 8080, "HTTP port to expose the DHT API")
	serviceID := flag.String("service-id", "dht", "Fireflies service ID for this DHT")
	hostname := flag.String("hostname", "localhost", "Hostname for this node's certificate")
	caAddr := flag.String("ca", "", "CA address (optional; falls back to ifrit_config.yaml)")
	certPath := flag.String("cert-path", "", "Directory for node cryptographic keys/certs")
	flag.Parse()

	client, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: *hostname,
		CAAddr:   *caAddr,
		CertPath: *certPath,
	})
	if err != nil {
		panic(fmt.Errorf("create ifrit client: %w", err))
	}

	dhtSvc, err := dht.Open(client, *serviceID)
	if err != nil {
		panic(fmt.Errorf("open dht service: %w", err))
	}

	go client.Start()
	go func() {
		if err := dhtSvc.ServeDHT(*httpPort); err != nil {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
		}
	}()

	fmt.Printf("Ifrit node listening on %s\n", client.Addr())
	fmt.Printf("DHT service %q HTTP API on http://localhost:%d/%s/items\n", *serviceID, *httpPort, *serviceID)
	fmt.Printf("  PUT: curl -X PUT http://localhost:%d/%s/items -d '{\"Key\":\"hello\",\"Value\":\"d29ybGQ=\"}'\n", *httpPort, *serviceID)
	fmt.Printf("  GET: curl 'http://localhost:%d/%s/items?q=hello'\n", *httpPort, *serviceID)

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	_ = dhtSvc.Close()
	client.Stop()
}
