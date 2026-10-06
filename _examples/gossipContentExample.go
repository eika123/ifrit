package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/joonnna/ifrit"
)

// Mockup application
type application struct {
	ifritClient *ifrit.Client
	exitChan    chan bool
	dataMutex   sync.RWMutex
	data        *appData
	hostname    string
}

// Mockup data structure
type appData struct {
	Users map[string]*user `json:"users"`
}

// Mockup users
type user struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Address   string `json:"address"`
	AddedBy   string `json:"added_by"`
}

// In this example we aim to utilize the external gossip content functionality of ifrit.
// Each time our application state is altered, we set the appropriate state in ifrit
// through the SetGossipContent() function.
// Our application state will then be gossiped with our neighbours which will receive it
// through their registered message handlers.

// The example is simplified for clarity reasons and is meant to represent an example usage
// of the SetGossipContent() functionality.

// As an example we store the client instance within the application
// such that we can communicate with it as we see fit
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

	return &application{
		ifritClient: c,
		exitChan:    make(chan bool),
		hostname:    hostname,
		data: &appData{
			Users: make(map[string]*user),
		},
	}, nil
}

// Start the mockup application
func (a *application) Start() {
	a.ifritClient.RegisterGossipHandler(a.handleGossip)

	// Start the ifrit node gossip and failure detector loops
	go a.ifritClient.Start()

	ticker := time.NewTicker(time.Second * 15)
	defer ticker.Stop()

	for {
		select {
		case <-a.exitChan:
			log.Info("Shutting down application")
			a.ifritClient.Stop()
			return

		//case <-time.After(time.Second * 20):
		case <-ticker.C:
			a.addRandomUser()
		}
	}
}

func (a *application) addRandomUser() {
	a.dataMutex.Lock()
	if a.data.Users == nil {
		a.data.Users = make(map[string]*user)
	}
	userCount := len(a.data.Users) + 1
	userID := fmt.Sprintf("%s-%d", a.hostname, userCount)
	newUser := &user{
		ID:        userID,
		FirstName: fmt.Sprintf("User-%d", userCount),
		LastName:  "Doe",
		Address:   fmt.Sprintf("%s Street", a.hostname),
		AddedBy:   a.hostname,
	}
	a.data.Users[userID] = newUser
	log.Info("Created new user", "id", userID, "added_by", a.hostname, "total_users", len(a.data.Users))

	stateBytes := a.stateLocked()
	a.dataMutex.Unlock()

	a.ifritClient.SetGossipContent(stateBytes)
}

func (a *application) stateLocked() []byte {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(a.data)
	return buf.Bytes()
}

func (a *application) State() []byte {
	a.dataMutex.RLock()
	defer a.dataMutex.RUnlock()
	return a.stateLocked()
}

// This callback is invoked each time ifrit receives application gossip content.
func (a *application) handleGossip(data []byte) ([]byte, error) {
	received := &appData{}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(received)
	if err != nil {
		return nil, err
	}

	a.dataMutex.Lock()
	if a.data.Users == nil {
		a.data.Users = make(map[string]*user)
	}

	newCount := 0
	if received.Users != nil {
		for k, v := range received.Users {
			if _, exists := a.data.Users[k]; !exists {
				a.data.Users[k] = v
				newCount++
			}
		}
	}

	if newCount > 0 {
		log.Info("Merged gossip updates", "new_users", newCount, "total_users", len(a.data.Users))
	}

	stateBytes := a.stateLocked()
	a.dataMutex.Unlock()

	a.ifritClient.SetGossipContent(stateBytes)

	return stateBytes, nil
}

func main() {
	r := log.Root()
	r.SetHandler(log.StreamHandler(os.Stdout, log.LogfmtFormat()))

	log.Info("Starting Ifrit Gossip Content Node")

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
