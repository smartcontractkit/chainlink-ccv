package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/health"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNewHTTPHealthServer(t *testing.T) {
	manager := NewManager()
	lggr := logger.Sugared(logger.Test(t))

	server := NewHTTPHealthServer(manager, "8080", lggr)

	assert.NotNil(t, server)
	assert.NotNil(t, server.server)
	assert.NotNil(t, server.manager)
	assert.Equal(t, ":8080", server.server.Addr)
}

func TestHTTPHealthServer_handleLiveness(t *testing.T) {
	manager := NewManager()
	lggr := logger.Sugared(logger.Test(t))
	server := NewHTTPHealthServer(manager, "8080", lggr)

	t.Run("returns alive status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
		recorder := httptest.NewRecorder()

		server.handleLiveness(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var response health.LivenessResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, health.Alive, response.Status)
	})
}

func TestHTTPHealthServer_handleReadiness(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))

	t.Run("returns ready when all components healthy", func(t *testing.T) {
		manager := NewManager()
		manager.Register(&mockHealthyComponent{name: "comp1"})
		manager.Register(&mockHealthyComponent{name: "comp2"})
		server := NewHTTPHealthServer(manager, "8080", lggr)

		req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		recorder := httptest.NewRecorder()

		server.handleReadiness(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		var response health.ReadinessResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, health.Ready, response.Status)
	})

	t.Run("returns not ready when component unhealthy", func(t *testing.T) {
		manager := NewManager()
		manager.Register(&mockHealthyComponent{name: "comp1"})
		manager.Register(&mockUnhealthyComponent{name: "comp2"})
		server := NewHTTPHealthServer(manager, "8080", lggr)

		req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		recorder := httptest.NewRecorder()

		server.handleReadiness(recorder, req)

		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)

		var response health.ReadinessResponse
		err := json.Unmarshal(recorder.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, health.NotReady, response.Status)
	})
}

func TestHTTPHealthServer_Start_Stop(t *testing.T) {
	manager := NewManager()
	lggr := logger.Sugared(logger.Test(t))
	server := NewHTTPHealthServer(manager, "0", lggr) // Port 0 for random available port

	errChan := make(chan error)
	go func() {
		errChan <- server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := server.Stop(ctx)
	require.NoError(t, err)

	select {
	case startErr := <-errChan:
		assert.ErrorIs(t, startErr, http.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}
}
