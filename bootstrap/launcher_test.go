package bootstrap

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type dummyApp struct {
	started atomic.Bool
	stopped atomic.Bool
}

func (d *dummyApp) Start()       { d.started.Store(true) }
func (d *dummyApp) Stop()        { d.stopped.Store(true) }
func (d *dummyApp) Addr() string { return "127.0.1.1:9999" }

func TestAddApplicationHandlerSuccess(t *testing.T) {
	app := &dummyApp{}
	launcher := &Launcher{
		clientFactory: func() (Application, error) {
			return app, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/addApplication", nil)
	rec := httptest.NewRecorder()

	launcher.addApplicationHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Application added and started")
	assert.Eventually(t, func() bool {
		return app.started.Load()
	}, time.Second, 10*time.Millisecond)
	assert.Len(t, launcher.applicationList, 1)
}

func TestAddApplicationHandlerFactoryError(t *testing.T) {
	launcher := &Launcher{
		clientFactory: func() (Application, error) {
			return nil, errors.New("factory failed")
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/addApplication", nil)
	rec := httptest.NewRecorder()

	launcher.addApplicationHandler(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "factory failed")
	assert.Len(t, launcher.applicationList, 0)
}

func TestAddApplicationHandlerNoFactory(t *testing.T) {
	launcher := &Launcher{
		clientFactory: nil,
	}

	req := httptest.NewRequest(http.MethodPost, "/addApplication", nil)
	rec := httptest.NewRecorder()

	launcher.addApplicationHandler(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "no client factory configured")
}

func TestAddApplicationHandlerMethodNotAllowed(t *testing.T) {
	launcher := &Launcher{
		clientFactory: func() (Application, error) {
			return &dummyApp{}, nil
		},
	}

	req := httptest.NewRequest(http.MethodDelete, "/addApplication", nil)
	rec := httptest.NewRecorder()

	launcher.addApplicationHandler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Len(t, launcher.applicationList, 0)
}
