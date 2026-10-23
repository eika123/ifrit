package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/joonnna/ifrit/protobuf"
	"github.com/stretchr/testify/assert"
)

type dummyPingService struct{}

func (d *dummyPingService) Pause(time.Duration)                     {}
func (d *dummyPingService) Ping(string, *pb.Ping) (*pb.Pong, error) { return nil, nil }
func (d *dummyPingService) Start()                                  {}
func (d *dummyPingService) Stop()                                   {}
func (d *dummyPingService) PongContent(nonce []byte, fingerprint []byte) []byte {
	return nil
}

func TestVizShutdownHandler(t *testing.T) {
	// Uninitialized node -> returns 500
	vUninit := &viz{
		exitChan: make(chan bool, 1),
	}
	reqUninit := httptest.NewRequest(http.MethodPost, "/shutdownNode", nil)
	recUninit := httptest.NewRecorder()
	vUninit.shutdownHandler(recUninit, reqUninit)
	assert.Equal(t, http.StatusInternalServerError, recUninit.Code)
	assert.Contains(t, recUninit.Body.String(), "node not initialized")

	// MethodNotAllowed -> returns 405
	node := &Node{
		exitChan: make(chan bool, 1),
	}
	v := &viz{
		n:        node,
		exitChan: make(chan bool, 1),
	}
	reqBad := httptest.NewRequest(http.MethodDelete, "/shutdownNode", nil)
	recBad := httptest.NewRecorder()
	v.shutdownHandler(recBad, reqBad)
	assert.Equal(t, http.StatusMethodNotAllowed, recBad.Code)

	// Valid POST -> returns 200
	req := httptest.NewRequest(http.MethodPost, "/shutdownNode", nil)
	rec := httptest.NewRecorder()
	v.shutdownHandler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Node shutdown initiated")

	// Verify that node.Stop() was invoked and closed exitChan
	assert.Eventually(t, func() bool {
		return node.isStopping()
	}, time.Second, 10*time.Millisecond)
}

func TestVizByzantineHandler(t *testing.T) {
	// Uninitialized node/fd -> returns 500
	vUninit := &viz{
		exitChan: make(chan bool, 1),
	}
	reqUninit := httptest.NewRequest(http.MethodPost, "/byzantine", nil)
	recUninit := httptest.NewRecorder()
	vUninit.byzantineHandler(recUninit, reqUninit)
	assert.Equal(t, http.StatusInternalServerError, recUninit.Code)
	assert.Contains(t, recUninit.Body.String(), "node or failure detector not initialized")

	// MethodNotAllowed -> returns 405
	node := &Node{
		fd: &failureDetector{ps: &dummyPingService{}},
	}
	v := &viz{
		n:        node,
		exitChan: make(chan bool, 1),
	}
	reqBad := httptest.NewRequest(http.MethodPut, "/byzantine", nil)
	recBad := httptest.NewRecorder()
	v.byzantineHandler(recBad, reqBad)
	assert.Equal(t, http.StatusMethodNotAllowed, recBad.Code)

	// Valid POST -> returns 200
	req := httptest.NewRequest(http.MethodPost, "/byzantine", nil)
	rec := httptest.NewRecorder()
	v.byzantineHandler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Byzantine mode activated")
}
