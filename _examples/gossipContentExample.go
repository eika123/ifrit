package main

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/joonnna/ifrit"
)

var (
	caAddr = "...."
)

// Mockup application
type application struct {
	ifritClient *ifrit.Client
	caAddr      string

	exitChan chan bool
	data     *appData
}

// Mockup data structure
type appData struct {
	Users map[int]*user
}

// Mockup users
type user struct {
	FirstName string
	LastName  string
	Address   string
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
func newApp(caAddr string) (*application, error) {
	c, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: "localhost",
	})
	if err != nil {
		return nil, err
	}

	return &application{
		ifritClient: c,
		caAddr:      caAddr,
		exitChan:    make(chan bool),
		data: &appData{
			Users: make(map[int]*user),
		},
	}, nil
}

// Start the mockup application
func (a *application) Start() {
	a.ifritClient.RegisterMsgHandler(a.handleMessages)

	for {
		select {
		case <-a.exitChan:
			return

		case <-time.After(time.Second * 20):
			a.addRandomUser()
		}
	}
}

func (a *application) addRandomUser() {
	if a.data.Users == nil {
		a.data.Users = make(map[int]*user)
	}
	id := len(a.data.Users) + 1
	a.data.Users[id] = &user{
		FirstName: "John",
		LastName:  "Doe",
		Address:   "123 Main St",
	}
	a.ifritClient.SetGossipContent(a.State())
}

func (a *application) State() []byte {
	var buf bytes.Buffer

	json.NewEncoder(&buf).Encode(a.data)

	return buf.Bytes()
}

// This callback will be invoked on each received message.
func (a *application) handleMessages(data []byte) ([]byte, error) {
	received := &appData{}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(received)
	if err != nil {
		return nil, err
	}

	if received.Users != nil {
		if a.data.Users == nil {
			a.data.Users = make(map[int]*user)
		}
		for k, v := range received.Users {
			if _, ok := a.data.Users[k]; !ok {
				a.data.Users[k] = v
			}
		}
	}

	a.ifritClient.SetGossipContent(a.State())

	return nil, nil
}

//We assume that the CA is deployed on another server
func main() {
	a, err := newApp(caAddr)
	if err != nil {
		panic(err)
	}

	a.Start()
}
