package health

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/health"
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
func (m *Manager) Register(component any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if checker, ok := component.(protocol.HealthReporter); ok {
		m.components = append(m.components, checker)
	}
}

// CheckLiveness returns the basic liveness status of the service.
func (m *Manager) CheckLiveness(ctx context.Context) health.LivenessResponse {
	return health.NewAliveResponse()
}

// CheckReadiness aggregates health status from all registered components.
func (m *Manager) CheckReadiness(ctx context.Context) health.ReadinessResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]health.ServicesHealth, 0, len(m.components))
	for _, component := range m.components {
		results = append(results, health.NewServiceHealth(component))
	}

	return health.NewReadinessResponse(results)
}
