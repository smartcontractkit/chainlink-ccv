package health

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestHealthStatus_HandleLiveness(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("always returns alive", func(t *testing.T) {
		handler := NewHealthStatus(nil)

		router := gin.New()
		router.GET("/health/live", handler.HandleLiveness)

		req, _ := http.NewRequest("GET", "/health/live", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"status":"alive"}`, w.Body.String())
	})

	t.Run("works with health reporters", func(t *testing.T) {
		healthReporters := make([]protocol.HealthReporter, 0)
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/live", handler.HandleLiveness)

		req, _ := http.NewRequest("GET", "/health/live", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"status":"alive"}`, w.Body.String())
	})
}

func TestHealthStatus_HandleReadiness(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("ready when no health reporters (idle state)", func(t *testing.T) {
		handler := NewHealthStatus([]protocol.HealthReporter{})

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"status":"ready","services":[]}`, w.Body.String())
	})

	t.Run("not ready when health reporter is nil", func(t *testing.T) {
		healthReporters := []protocol.HealthReporter{nil}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [{"name": "unknown", "status": "nil", "error": "health reporter is nil"}]
		}`, w.Body.String())
	})

	t.Run("includes reporter statuses in response", func(t *testing.T) {
		handler := NewHealthStatus([]protocol.HealthReporter{nil})

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [{"name": "unknown", "status": "nil", "error": "health reporter is nil"}]
		}`, w.Body.String())
	})

	t.Run("ready when single reporter is ready", func(t *testing.T) {
		reporter := newFakeHealthReporter("coordinator-1", nil)
		healthReporters := []protocol.HealthReporter{reporter}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{
			"status": "ready",
			"services": [{"name": "coordinator-1", "status": "ready", "error": null}]
		}`, w.Body.String())
	})

	t.Run("not ready when single reporter is not ready", func(t *testing.T) {
		reporter := newFakeHealthReporter("coordinator-1", errors.New("state machine not started"))
		healthReporters := []protocol.HealthReporter{reporter}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [{"name": "coordinator-1", "status": "not_ready", "error": "state machine not started"}]
		}`, w.Body.String())
	})

	t.Run("ready when all reporters are ready", func(t *testing.T) {
		reporter1 := newFakeHealthReporter("coordinator-1", nil)
		reporter2 := newFakeHealthReporter("coordinator-2", nil)
		reporter3 := newFakeHealthReporter("coordinator-3", nil)
		healthReporters := []protocol.HealthReporter{reporter1, reporter2, reporter3}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{
			"status": "ready",
			"services": [
				{"name": "coordinator-1", "status": "ready", "error": null},
				{"name": "coordinator-2", "status": "ready", "error": null},
				{"name": "coordinator-3", "status": "ready", "error": null}
			]
		}`, w.Body.String())
	})

	t.Run("not ready when one of multiple reporters is not ready", func(t *testing.T) {
		reporter1 := newFakeHealthReporter("coordinator-1", nil)
		reporter2 := newFakeHealthReporter("coordinator-2", errors.New("database connection lost"))
		reporter3 := newFakeHealthReporter("coordinator-3", nil)
		healthReporters := []protocol.HealthReporter{reporter1, reporter2, reporter3}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [
				{"name": "coordinator-1", "status": "ready", "error": null},
				{"name": "coordinator-2", "status": "not_ready", "error": "database connection lost"},
				{"name": "coordinator-3", "status": "ready", "error": null}
			]
		}`, w.Body.String())
	})

	t.Run("not ready when all reporters are not ready", func(t *testing.T) {
		reporter1 := newFakeHealthReporter("coordinator-1", errors.New("RPC node unreachable"))
		reporter2 := newFakeHealthReporter("coordinator-2", errors.New("curse detector failed"))
		healthReporters := []protocol.HealthReporter{reporter1, reporter2}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [
				{"name": "coordinator-1", "status": "not_ready", "error": "RPC node unreachable"},
				{"name": "coordinator-2", "status": "not_ready", "error": "curse detector failed"}
			]
		}`, w.Body.String())
	})

	t.Run("mixed state with nil and ready reporters", func(t *testing.T) {
		reporter := newFakeHealthReporter("coordinator-1", nil)
		healthReporters := []protocol.HealthReporter{reporter, nil}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [
				{"name": "coordinator-1", "status": "ready", "error": null},
				{"name": "unknown", "status": "nil", "error": "health reporter is nil"}
			]
		}`, w.Body.String())
	})

	t.Run("response includes individual reporter statuses", func(t *testing.T) {
		reporter1 := newFakeHealthReporter("coordinator-1", nil)
		reporter2 := newFakeHealthReporter("coordinator-2", errors.New("not started"))
		reporter3 := newFakeHealthReporter("coordinator-3", nil)
		healthReporters := []protocol.HealthReporter{reporter1, reporter2, reporter3}
		handler := NewHealthStatus(healthReporters)

		router := gin.New()
		router.GET("/health/ready", handler.HandleReadiness)

		req, _ := http.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{
			"status": "not_ready",
			"services": [
				{"name": "coordinator-1", "status": "ready", "error": null},
				{"name": "coordinator-2", "status": "not_ready", "error": "not started"},
				{"name": "coordinator-3", "status": "ready", "error": null}
			]
		}`, w.Body.String())
	})
}

type fakeHealthReporter struct {
	readyErr     error
	healthReport map[string]error
	name         string
}

func newFakeHealthReporter(name string, readyErr error) *fakeHealthReporter {
	return &fakeHealthReporter{
		readyErr:     readyErr,
		healthReport: make(map[string]error),
		name:         name,
	}
}

func (f *fakeHealthReporter) Ready() error {
	return f.readyErr
}

func (f *fakeHealthReporter) HealthReport() map[string]error {
	return f.healthReport
}

func (f *fakeHealthReporter) Name() string {
	return f.name
}
