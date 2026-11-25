package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/eika123/ifrit"
	"github.com/eika123/ifrit/services/messaging"
	log "github.com/inconshreveable/log15"
)

/** Example of bi-directional streaming using Ifrit library*/

type App struct {
	master    *ifrit.Client
	client    *ifrit.Client
	masterSvc *ifrit.ServiceEndpoint
	clientSvc *ifrit.ServiceEndpoint
	masterMsg *messaging.Service
	clientMsg *messaging.Service
}

func main() {
	r := log.Root()
	h := log.CallerFileHandler(log.Must.FileHandler("logfile", log.LogfmtFormat()))
	r.SetHandler(h)

	app, err := NewApp()
	if err != nil {
		panic(err)
	}

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- app.Stream()
	}()

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-streamDone:
		if err != nil {
			fmt.Printf("Stream error: %v\n", err)
		} else {
			fmt.Println("Streaming exchange finished successfully.")
		}
	case <-sigChan:
		fmt.Println("\nInterrupt received, shutting down...")
	}

	app.master.Stop()
	app.client.Stop()
}

func NewApp() (*App, error) {
	client, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: "localhost",
	})
	if err != nil {
		return nil, err
	}

	clientMsg, err := messaging.Register(client)
	if err != nil {
		return nil, err
	}
	clientSvc, err := client.Service("streaming-example")
	if err != nil {
		return nil, err
	}
	if err := clientMsg.HandleStream("streaming-example", streamHandler); err != nil {
		return nil, err
	}
	go client.Start()

	master, err := ifrit.NewClient(&ifrit.Config{
		New:      true,
		Hostname: "localhost",
	})
	if err != nil {
		return nil, err
	}

	masterMsg, err := messaging.Register(master)
	if err != nil {
		return nil, err
	}
	masterSvc, err := master.Service("streaming-example")
	if err != nil {
		return nil, err
	}

	go master.Start()
	return &App{
		master:    master,
		client:    client,
		masterSvc: masterSvc,
		clientSvc: clientSvc,
		masterMsg: masterMsg,
		clientMsg: clientMsg,
	}, nil
}

func (app *App) Stream() error {
	var wg sync.WaitGroup
	inputStream, reply := app.masterMsg.OpenStream(context.Background(), "streaming-example", app.client.Addr())

	var receivedCount int
	var receivedMu sync.Mutex

	// Read replies from server
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range reply {
			receivedMu.Lock()
			receivedCount++
			receivedMu.Unlock()
			fmt.Printf("Client got reply from server: %s\n", i)
		}
	}()

	// Send messages from client
	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("Message from client: %d", i)
		inputStream <- []byte(msg)
	}
	close(inputStream)

	wg.Wait()

	receivedMu.Lock()
	defer receivedMu.Unlock()
	if receivedCount != 10 {
		return fmt.Errorf("expected 10 replies, got %d", receivedCount)
	}
	return nil
}

func streamHandler(input, reply chan []byte) {
	defer close(reply)

	// Read messages from client and reply to each
	for msg := range input {
		fmt.Printf("Server got message: %s\n", msg)
		replyMsg := fmt.Sprintf("Server reply to client: echo %s", msg)
		reply <- []byte(replyMsg)
	}
}
