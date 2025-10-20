package health

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

type HealthManager struct {
	components []common.HealthChecker
	mu         sync.RWMutex
}

func NewHealthManager() *HealthManager {
	return &HealthManager{
		components: make([]common.HealthChecker, 0),
	}
}

func (m *HealthManager) Register(component any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if checker, ok := component.(common.HealthChecker); ok {
		m.components = append(m.components, checker)
	}
}

func (m *HealthManager) CheckLiveness(ctx context.Context) *common.ComponentHealth {
	return &common.ComponentHealth{
		Name:      "liveness",
		Status:    common.HealthStatusHealthy,
		Message:   "service is running",
		Timestamp: time.Now(),
	}
}

func (m *HealthManager) CheckReadiness(ctx context.Context) (common.HealthStatus, []*common.ComponentHealth) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*common.ComponentHealth, 0, len(m.components))
	overallStatus := common.HealthStatusHealthy

	for _, component := range m.components {
		health := component.HealthCheck(ctx)
		results = append(results, health)

		if health.Status == common.HealthStatusUnhealthy {
			overallStatus = common.HealthStatusUnhealthy
		} else if health.Status == common.HealthStatusDegraded && overallStatus != common.HealthStatusUnhealthy {
			overallStatus = common.HealthStatusDegraded
		}
	}

	return overallStatus, results
}
