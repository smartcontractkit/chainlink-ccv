package health

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Manager coordinates health checks across multiple components.
type Manager struct {
	components []protocol.HealthReporter
	mu         sync.RWMutex
}

// NewManager creates a new health check manager.
func NewManager() *Manager {
	return &Manager{
		components: make([]protocol.HealthReporter, 0),
	}
}

// Register adds a component to be monitored for health checks.
func (m *Manager) Register(component protocol.HealthReporter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.components = append(m.components, component)
}

// CheckLiveness returns the basic liveness status of the service.
func (m *Manager) CheckLiveness(ctx context.Context) LivenessResponse {
	return NewAliveResponse()
}

// CheckReadiness aggregates health status from all registered components.
func (m *Manager) CheckReadiness(ctx context.Context) ReadinessResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]ServicesHealth, 0, len(m.components))
	for _, component := range m.components {
		results = append(results, CheckServiceHealth(component))
	}

	return NewReadinessResponse(results)
}

// StartPeriodicHealthLogging blocks and periodically logs the health status
// of all registered components until the context is canceled.
func (m *Manager) StartPeriodicHealthLogging(ctx context.Context, l logger.SugaredLogger, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			response := m.CheckReadiness(ctx)

			componentStatus := make(map[string]string)
			for _, svc := range response.Services {
				status := "healthy"
				if svc.Error != "" {
					status = svc.Error
				}
				componentStatus[svc.Name] = status
			}

			logFn := l.Debugw
			if response.Status == NotReady {
				logFn = l.Warnw
			}

			// SERVICE LOG (status): periodic health summary; Debug when healthy, Warn otherwise.
			logFn("Service health summary",
				protocol.LogTypeKey, protocol.LogTypeServiceStatus,
				"overall_status", response.Status,
				"components", componentStatus,
			)
		case <-ctx.Done():
			return nil
		}
	}
}
