package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit"
)

// User representation where all fields are comparable for HashiCorp Set[T].
type user struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Address   string `json:"address"`
	AddedBy   string `json:"added_by"`
}

// Application represents a gossip node managing a convergent Grow-only Set (G-Set)
// of user records using Ifrit's high-level GossipSet abstraction.
type application struct {
	ifritClient *ifrit.Client
	gossipSet   ifrit.GossipSet[user]
	exitChan    chan struct{}
	hostname    string
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

	c, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: hostname,
		TCPPort:  9000,
		UDPPort:  9001,
	})
	if err != nil {
		return nil, err
	}

	// Create thread-safe distributed gossip set bound to the Ifrit client.
	// This automatically wires up gossip handlers and starts the background merge worker.
	gSet := ifrit.NewGossipSet[user](c, nil)

	// Register reactive listener for remote updates from peers
	gSet.OnUpdate(func(newUsers []user, total int) {
		log.Info("Discovered new users from gossip peers",
			"new_count", len(newUsers),
			"total_users", total,
		)
	})

	app := &application{
		ifritClient: c,
		gossipSet:   gSet,
		exitChan:    make(chan struct{}),
		hostname:    hostname,
	}

	return app, nil
}

// Start runs the periodic user generation ticker and initiates Ifrit gossip.
func (a *application) Start() {
	// Start Ifrit gossip and failure detector
	go a.ifritClient.Start()

	ticker := time.NewTicker(time.Second * 15)
	defer ticker.Stop()

	for {
		select {
		case <-a.exitChan:
			log.Info("Shutting down application")
			a.gossipSet.Close()
			a.ifritClient.Stop()
			return

		case <-ticker.C:
			a.addRandomUser()
		}
	}
}

// addRandomUser creates a new local user and incorporates it via AddElement.
// The internal GossipSet updates the local set and publishes the new state to Ifrit gossip.
func (a *application) addRandomUser() {
	a.counter++
	userID := fmt.Sprintf("%s-%d", a.hostname, a.counter)
	newUser := user{
		ID:        userID,
		FirstName: fmt.Sprintf("User-%d", a.counter),
		LastName:  "Doe",
		Address:   fmt.Sprintf("%s Street", a.hostname),
		AddedBy:   a.hostname,
	}

	log.Info("Created new local user", "id", userID, "added_by", a.hostname)

	// AddElement handles mathematical insertion, deduplication, and gossip publishing
	a.gossipSet.AddElement(newUser)

	// Demonstrate safe inspection via Copy() - application cannot mutate internal Ifrit state
	snapshot := a.gossipSet.Copy()
	log.Info("Current set snapshot", "size", snapshot.Size())
}

func main() {
	r := log.Root()
	r.SetHandler(log.StreamHandler(os.Stdout, log.LogfmtFormat()))

	log.Info("Starting Ifrit Gossip Content Node (GossipSet API)")

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
