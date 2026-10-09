package health

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReadinessResponse_AggregatesDegradedAndNotReady(t *testing.T) {
	ready := ServicesHealth{Name: "a", Status: Ready}
	degraded := ServicesHealth{Name: "b", Status: Degraded, Error: "1 component(s) skipped at startup"}
	notReady := ServicesHealth{Name: "c", Status: NotReady, Error: "stopped"}

	tests := []struct {
		name       string
		services   []ServicesHealth
		wantStatus ReadinessStatus
		wantCode   int
	}{
		{"all ready", []ServicesHealth{ready}, Ready, http.StatusOK},
		{"degraded keeps serving", []ServicesHealth{ready, degraded}, Degraded, http.StatusOK},
		{"not ready wins over degraded", []ServicesHealth{degraded, notReady}, NotReady, http.StatusServiceUnavailable},
		{"degraded after not ready", []ServicesHealth{notReady, degraded}, NotReady, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := NewReadinessResponse(tt.services)
			assert.Equal(t, tt.wantStatus, response.Status)
			assert.Equal(t, tt.wantCode, response.StatusCode())
		})
	}
}

// plainReporter has no Degraded method, so only Ready() decides its status.
type plainReporter struct{ err error }

func (p plainReporter) Name() string                   { return "plain" }
func (p plainReporter) Ready() error                   { return p.err }
func (p plainReporter) HealthReport() map[string]error { return nil }

func TestCheckServiceHealth_DegradedOnlyWhenReadyPasses(t *testing.T) {
	assert.Equal(t, Ready, CheckServiceHealth(plainReporter{}).Status)
	assert.Equal(t, NotReady, CheckServiceHealth(plainReporter{err: errors.New("down")}).Status)

	skips := NewStartupSkips("svc.StartupSkips")
	skips.Skip("Chain[1]", errors.New("RPC down"))
	assert.Equal(t, Degraded, CheckServiceHealth(skips).Status)
}

func TestReadinessResponse_StatusCodeFailsClosedForUnknownStatus(t *testing.T) {
	for _, status := range []ReadinessStatus{Ready, Degraded} {
		response := ReadinessResponse{Status: status}
		assert.Equal(t, http.StatusOK, response.StatusCode(), "status %q must keep serving", status)
	}
	for _, status := range []ReadinessStatus{NotReady, "", "bogus"} {
		response := ReadinessResponse{Status: status}
		assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode(), "status %q must fail closed", status)
	}
}
