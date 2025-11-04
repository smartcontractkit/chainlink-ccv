package health

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.uber.org/zap/zapcore"
)

type stubHealthyComponent struct{}

func (s *stubHealthyComponent) HealthCheck(_ context.Context) *common.ComponentHealth {
	return &common.ComponentHealth{Name: "stub", Status: common.HealthStatusHealthy}
}

type stubDegradedComponent struct{}

func (s *stubDegradedComponent) HealthCheck(_ context.Context) *common.ComponentHealth {
	return &common.ComponentHealth{Name: "stub", Status: common.HealthStatusDegraded}
}

type stubUnhealthyComponent struct{}

func (s *stubUnhealthyComponent) HealthCheck(_ context.Context) *common.ComponentHealth {
	return &common.ComponentHealth{Name: "stub", Status: common.HealthStatusUnhealthy}
}

func newTestLogger(t *testing.T) logger.SugaredLogger {
	t.Helper()
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.WarnLevel))
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger.Sugared(lggr)
}

func TestHTTPHealthServer_Liveness(t *testing.T) {
	m := NewManager()
	h := NewHTTPHealthServer(m, "0", newTestLogger(t))

	req := httptest.NewRequest("GET", "/health/live", nil)
	rr := httptest.NewRecorder()
	h.handleLiveness(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var payload common.ComponentHealth
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload.Status != common.HealthStatusHealthy {
		t.Fatalf("expected healthy, got %s", payload.Status)
	}
}

func TestHTTPHealthServer_Readiness_StatusCodes(t *testing.T) {
	// Healthy
	{
		m := NewManager()
		m.Register(&stubHealthyComponent{})
		h := NewHTTPHealthServer(m, "0", newTestLogger(t))
		req := httptest.NewRequest("GET", "/health/ready", nil)
		rr := httptest.NewRecorder()
		h.handleReadiness(rr, req)
		if rr.Code != 200 {
			t.Fatalf("expected 200 for healthy, got %d", rr.Code)
		}
	}
	// Degraded
	{
		m := NewManager()
		m.Register(&stubDegradedComponent{})
		h := NewHTTPHealthServer(m, "0", newTestLogger(t))
		req := httptest.NewRequest("GET", "/health/ready", nil)
		rr := httptest.NewRecorder()
		h.handleReadiness(rr, req)
		if rr.Code != 200 {
			t.Fatalf("expected 200 for degraded, got %d", rr.Code)
		}
	}
	// Unhealthy
	{
		m := NewManager()
		m.Register(&stubUnhealthyComponent{})
		h := NewHTTPHealthServer(m, "0", newTestLogger(t))
		req := httptest.NewRequest("GET", "/health/ready", nil)
		rr := httptest.NewRecorder()
		h.handleReadiness(rr, req)
		if rr.Code != 503 {
			t.Fatalf("expected 503 for unhealthy, got %d", rr.Code)
		}
	}
}
