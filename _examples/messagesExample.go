package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/joonnna/ifrit"
	"github.com/joonnna/ifrit/core"
)

// Mockup application
type application struct {
	ifritClient *ifrit.Client

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

// We store the client instance within the application
// such that we can communicate with it as we see fit
func newApp(config *ifrit.Config) (*application, error) {

	c, err := ifrit.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &application{
		ifritClient: c,
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

		case <-time.After(time.Second * 40):
			a.addRandomUser()
			members := a.ifritClient.Members()

			for _, addr := range members {
				ch := a.ifritClient.SendTo(addr, a.State())
				select {
				case resp := <-ch:
					a.handleResponse(resp)
				case <-time.After(time.Minute * 2):
					break
				}
			}
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
}

func (a *application) handleResponse(msg *core.Message) {
	if msg == nil || msg.Error != nil {
		return
	}
	fmt.Println("Received response:", string(msg.Data))
}

func (a *application) generateResponse() []byte {
	return []byte("Got message, here is response!!!")
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

	return a.generateResponse(), nil
}

// We assume that the CA is deployed on another server
func main() {
	a, err := newApp(&ifrit.Config{
		New:      true,
		Hostname: "localhost",
	})
	if err != nil {
		panic(err)
	}

	a.Start()
}
