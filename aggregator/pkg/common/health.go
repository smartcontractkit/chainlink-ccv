package common

import (
	"context"
	"time"
)

type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

type ComponentHealth struct {
	Name      string       `json:"name"`
	Status    HealthStatus `json:"status"`
	Message   string       `json:"message,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// HealthChecker defines the interface for components that can report their health status.
type HealthChecker interface {
	// HealthCheck returns the current health status of the component.
	HealthCheck(ctx context.Context) *ComponentHealth
}
