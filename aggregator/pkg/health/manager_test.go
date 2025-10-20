package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

type mockHealthyComponent struct {
	name string
}

func (m *mockHealthyComponent) HealthCheck(ctx context.Context) *common.ComponentHealth {
	return &common.ComponentHealth{
		Name:      m.name,
		Status:    common.HealthStatusHealthy,
		Message:   "all good",
		Timestamp: time.Now(),
	}
}

type mockUnhealthyComponent struct {
	name string
}

func (m *mockUnhealthyComponent) HealthCheck(ctx context.Context) *common.ComponentHealth {
	return &common.ComponentHealth{
		Name:      m.name,
		Status:    common.HealthStatusUnhealthy,
		Message:   "something wrong",
		Timestamp: time.Now(),
	}
}

type nonHealthCheckableComponent struct {
	name string
}

func TestManager_RegisterHealthCheckable(t *testing.T) {
	manager := NewManager()

	healthy := &mockHealthyComponent{name: "test"}
	manager.Register(healthy)

	require.Len(t, manager.components, 1)
}

func TestManager_RegisterNonHealthCheckable(t *testing.T) {
	manager := NewManager()

	nonHealthy := &nonHealthCheckableComponent{name: "test"}
	manager.Register(nonHealthy)

	require.Len(t, manager.components, 0)
}

func TestManager_CheckLiveness(t *testing.T) {
	manager := NewManager()

	result := manager.CheckLiveness(context.Background())

	require.Equal(t, "liveness", result.Name)
	require.Equal(t, common.HealthStatusHealthy, result.Status)
}

func TestManager_CheckReadiness_AllHealthy(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&mockHealthyComponent{name: "comp2"})

	status, components := manager.CheckReadiness(context.Background())

	require.Equal(t, common.HealthStatusHealthy, status)
	require.Len(t, components, 2)
}

func TestManager_CheckReadiness_CriticalUnhealthy(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&mockUnhealthyComponent{name: "comp2"})

	status, components := manager.CheckReadiness(context.Background())

	require.Equal(t, common.HealthStatusUnhealthy, status)
	require.Len(t, components, 2)
}

func TestManager_CheckReadiness_MixedWithNonHealthCheckable(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&nonHealthCheckableComponent{name: "ignored"})
	manager.Register(&mockHealthyComponent{name: "comp2"})

	status, components := manager.CheckReadiness(context.Background())

	require.Equal(t, common.HealthStatusHealthy, status)
	require.Len(t, components, 2)
}
