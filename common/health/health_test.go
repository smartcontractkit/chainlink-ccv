package health

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLivenessResponse_JSONSerialization(t *testing.T) {
	t.Run("alive status serializes correctly", func(t *testing.T) {
		response := NewAliveResponse()

		data, err := json.Marshal(response)
		require.NoError(t, err)

		expected := `{"status":"alive"}`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("status code is OK for alive", func(t *testing.T) {
		response := LivenessResponse{Status: Alive}
		assert.Equal(t, http.StatusOK, response.StatusCode())
	})

	t.Run("status code is service unavailable for non-alive", func(t *testing.T) {
		response := LivenessResponse{Status: LivenessStatus("not_alive")}
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})
}

func TestReadinessResponse_JSONSerialization_EmptyServices(t *testing.T) {
	t.Run("empty services list serializes correctly", func(t *testing.T) {
		response := NewReadinessResponse([]ServicesHealth{})

		data, err := json.Marshal(response)
		require.NoError(t, err)

		expected := `{"status":"ready","services":[]}`
		assert.JSONEq(t, expected, string(data))
		assert.Equal(t, Ready, response.Status)
	})

	t.Run("nil services list serializes correctly", func(t *testing.T) {
		response := NewReadinessResponse(nil)

		data, err := json.Marshal(response)
		require.NoError(t, err)

		// nil slice serializes as null in JSON
		expected := `{"status":"ready","services":null}`
		assert.JSONEq(t, expected, string(data))
		assert.Equal(t, Ready, response.Status)
	})
}

func TestReadinessResponse_JSONSerialization_AllHealthy(t *testing.T) {
	t.Run("all healthy services serialize correctly", func(t *testing.T) {
		services := []ServicesHealth{
			{
				Name:   "database",
				Status: Ready,
				Error:  "",
				Report: map[string]string{},
			},
			{
				Name:   "cache",
				Status: Ready,
				Error:  "",
				Report: map[string]string{},
			},
			{
				Name:   "api",
				Status: Ready,
				Error:  "",
				Report: map[string]string{},
			},
		}
		response := NewReadinessResponse(services)

		data, err := json.Marshal(response)
		require.NoError(t, err)

		expected := `{
			"status": "ready",
			"services": [
				{
					"name": "database",
					"status": "ready"
				},
				{
					"name": "cache",
					"status": "ready"
				},
				{
					"name": "api",
					"status": "ready"
				}
			]
		}`
		assert.JSONEq(t, expected, string(data))
		assert.Equal(t, Ready, response.Status)
		assert.Equal(t, http.StatusOK, response.StatusCode())
	})

	t.Run("all healthy services have correct status code", func(t *testing.T) {
		services := []ServicesHealth{
			{Name: "service1", Status: Ready},
			{Name: "service2", Status: Ready},
		}
		response := NewReadinessResponse(services)
		assert.Equal(t, http.StatusOK, response.StatusCode())
	})
}

func TestReadinessResponse_JSONSerialization_AllUnhealthy(t *testing.T) {
	t.Run("all unhealthy services serialize correctly", func(t *testing.T) {
		services := []ServicesHealth{
			{
				Name:   "database",
				Status: NotReady,
				Error:  "connection timeout",
				Report: map[string]string{
					"connection": "failed",
					"latency":    "high",
				},
			},
			{
				Name:   "cache",
				Status: NotReady,
				Error:  "unavailable",
				Report: map[string]string{
					"ping": "failed",
				},
			},
		}
		response := NewReadinessResponse(services)

		data, err := json.Marshal(response)
		require.NoError(t, err)

		expected := `{
			"status": "not_ready",
			"services": [
				{
					"name": "database",
					"status": "not_ready",
					"error": "connection timeout",
					"report": {
						"connection": "failed",
						"latency": "high"
					}
				},
				{
					"name": "cache",
					"status": "not_ready",
					"error": "unavailable",
					"report": {
						"ping": "failed"
					}
				}
			]
		}`
		assert.JSONEq(t, expected, string(data))
		assert.Equal(t, NotReady, response.Status)
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})

	t.Run("all unhealthy services have correct status code", func(t *testing.T) {
		services := []ServicesHealth{
			{Name: "service1", Status: NotReady, Error: "error1"},
			{Name: "service2", Status: NotReady, Error: "error2"},
		}
		response := NewReadinessResponse(services)
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})
}

func TestReadinessResponse_JSONSerialization_SingleUnhealthy(t *testing.T) {
	t.Run("single unhealthy service serializes correctly", func(t *testing.T) {
		services := []ServicesHealth{
			{
				Name:   "database",
				Status: Ready,
				Error:  "",
				Report: map[string]string{},
			},
			{
				Name:   "cache",
				Status: NotReady,
				Error:  "connection refused",
				Report: map[string]string{
					"host": "cache.example.com",
					"port": "6379",
				},
			},
			{
				Name:   "api",
				Status: Ready,
				Error:  "",
				Report: map[string]string{},
			},
		}
		response := NewReadinessResponse(services)

		data, err := json.Marshal(response)
		require.NoError(t, err)

		expected := `{
			"status": "not_ready",
			"services": [
				{
					"name": "database",
					"status": "ready"
				},
				{
					"name": "cache",
					"status": "not_ready",
					"error": "connection refused",
					"report": {
						"host": "cache.example.com",
						"port": "6379"
					}
				},
				{
					"name": "api",
					"status": "ready"
				}
			]
		}`
		assert.JSONEq(t, expected, string(data))
		assert.Equal(t, NotReady, response.Status)
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})

	t.Run("single unhealthy service causes not ready status", func(t *testing.T) {
		services := []ServicesHealth{
			{Name: "service1", Status: Ready},
			{Name: "service2", Status: NotReady, Error: "error"},
			{Name: "service3", Status: Ready},
		}
		response := NewReadinessResponse(services)
		assert.Equal(t, NotReady, response.Status)
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})
}

func TestServicesHealth_JSONSerialization_OmitEmpty(t *testing.T) {
	t.Run("omitempty fields are omitted when empty", func(t *testing.T) {
		service := ServicesHealth{
			Name:   "test-service",
			Status: Ready,
			Error:  "",
			Report: map[string]string{},
		}

		data, err := json.Marshal(service)
		require.NoError(t, err)

		expected := `{
			"name": "test-service",
			"status": "ready"
		}`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("omitempty fields are present when not empty", func(t *testing.T) {
		service := ServicesHealth{
			Name:   "test-service",
			Status: NotReady,
			Error:  "something went wrong",
			Report: map[string]string{
				"detail": "more info",
			},
		}

		data, err := json.Marshal(service)
		require.NoError(t, err)

		expected := `{
			"name": "test-service",
			"status": "not_ready",
			"error": "something went wrong",
			"report": {
				"detail": "more info"
			}
		}`
		assert.JSONEq(t, expected, string(data))
	})
}

func TestReadinessResponse_StatusCode(t *testing.T) {
	t.Run("ready status returns OK", func(t *testing.T) {
		response := ReadinessResponse{Status: Ready}
		assert.Equal(t, http.StatusOK, response.StatusCode())
	})

	t.Run("not ready status returns service unavailable", func(t *testing.T) {
		response := ReadinessResponse{Status: NotReady}
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})
}

func TestReadinessResponse_ComplexScenarios(t *testing.T) {
	t.Run("multiple unhealthy services with detailed reports", func(t *testing.T) {
		services := []ServicesHealth{
			{
				Name:   "postgres",
				Status: NotReady,
				Error:  "max connections reached",
				Report: map[string]string{
					"current_connections": "100",
					"max_connections":     "100",
					"wait_time":           "5s",
				},
			},
			{
				Name:   "redis",
				Status: NotReady,
				Error:  "memory limit exceeded",
				Report: map[string]string{
					"used_memory": "1GB",
					"max_memory":  "1GB",
				},
			},
			{
				Name:   "elasticsearch",
				Status: Ready,
				Error:  "",
				Report: map[string]string{},
			},
		}
		response := NewReadinessResponse(services)

		data, err := json.Marshal(response)
		require.NoError(t, err)

		expected := `{
			"status": "not_ready",
			"services": [
				{
					"name": "postgres",
					"status": "not_ready",
					"error": "max connections reached",
					"report": {
						"current_connections": "100",
						"max_connections": "100",
						"wait_time": "5s"
					}
				},
				{
					"name": "redis",
					"status": "not_ready",
					"error": "memory limit exceeded",
					"report": {
						"used_memory": "1GB",
						"max_memory": "1GB"
					}
				},
				{
					"name": "elasticsearch",
					"status": "ready"
				}
			]
		}`
		assert.JSONEq(t, expected, string(data))
		assert.Equal(t, NotReady, response.Status)
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode())
	})
}
