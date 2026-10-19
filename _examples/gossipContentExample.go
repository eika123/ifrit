package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit"
)

// User representation where all fields are comparable.
type user struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Address   string `json:"address"`
	AddedBy   string `json:"added_by"`
}

// Application represents a gossip node managing a convergent Grow-only Set (G-Set)
// of user records using Ifrit's pluggable ReverseIndexStore abstraction.
type application struct {
	ifritClient *ifrit.Client
	store       ifrit.ReverseIndexStore[user]
	exitChan    chan struct{}
	hostname    string
	port        int
	counter     int
}

func newApp() (*application, error) {
	hostname := os.Getenv("IFRIT_HOSTNAME")
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			hostname = "localhost"
		} else {
			hostname = h
		}
	}

	tcpPort := 9000
	udpPort := 9001
	if p := os.Getenv("IFRIT_TCP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			tcpPort = v
		}
	}
	if p := os.Getenv("IFRIT_UDP_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			udpPort = v
		}
	}

	c, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: hostname,
		TCPPort:  tcpPort,
		UDPPort:  udpPort,
	})
	if err != nil {
		return nil, err
	}

	// Create thread-safe reconcilable store bound to the Ifrit client.
	store := ifrit.NewNaiveGossipSet[user](c, nil)

	app := &application{
		ifritClient: c,
		store:       store,
		exitChan:    make(chan struct{}),
		hostname:    hostname,
		port:        tcpPort,
	}

	return app, nil
}

// Start runs the periodic user generation ticker and initiates Ifrit gossip.
func (a *application) Start() {
	// Start Ifrit gossip and failure detector
	go a.ifritClient.Start()

	// Incorporate an initial user on startup so nodes have state to share immediately
	a.addRandomUser()

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-a.exitChan:
			log.Info("Shutting down application")
			_ = a.store.Close()
			a.ifritClient.Stop()
			return

		case <-ticker.C:
			a.addRandomUser()
		}
	}
}

// addRandomUser creates a new local user and incorporates it via AddElement.
// The reconcilable store updates the local state and disseminates updates to peers.
func (a *application) addRandomUser() {
	a.counter++
	userID := fmt.Sprintf("%s:%d-%d", a.hostname, a.port, a.counter)
	newUser := user{
		ID:        userID,
		FirstName: fmt.Sprintf("User-%d", a.counter),
		LastName:  "Doe",
		Address:   fmt.Sprintf("%s Street", a.hostname),
		AddedBy:   fmt.Sprintf("%s:%d", a.hostname, a.port),
	}

	log.Info("Created new local user", "id", userID, "added_by", newUser.AddedBy)

	// AddElement handles mathematical insertion and deduplication
	a.store.AddElement(newUser)

	log.Info("Current store elements count", "size", a.store.Size())
}

func main() {
	r := log.Root()
	r.SetHandler(log.StreamHandler(os.Stdout, log.LogfmtFormat()))

	log.Info("Starting Ifrit Gossip Content Node (ReverseIndexStore API)")

	app, err := newApp()
	if err != nil {
		panic(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		close(app.exitChan)
	}()

	app.Start()
}
