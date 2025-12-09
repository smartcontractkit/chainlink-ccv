package health

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/health"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

type mockHealthyComponent struct {
	name string
}

func (m *mockHealthyComponent) Ready() error {
	return nil
}

func (m *mockHealthyComponent) HealthReport() map[string]error {
	return map[string]error{}
}

func (m *mockHealthyComponent) Name() string {
	return m.name
}

type mockUnhealthyComponent struct {
	name string
}

func (m *mockUnhealthyComponent) Ready() error {
	return errors.New("something wrong")
}

func (m *mockUnhealthyComponent) HealthReport() map[string]error {
	return map[string]error{
		m.Name(): m.Ready(),
	}
}

func (m *mockUnhealthyComponent) Name() string {
	return m.name
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

	components := manager.CheckReadiness(t.Context())
	response := health.NewReadinessResponse(components)

	require.Equal(t, health.Ready, response.Status)
	require.Len(t, components, 2)
}

func TestManager_CheckReadiness_CriticalUnhealthy(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&mockUnhealthyComponent{name: "comp2"})

	components := manager.CheckReadiness(t.Context())
	response := health.NewReadinessResponse(components)

	require.Equal(t, health.NotReady, response.Status)
	require.Len(t, components, 2)
}

func TestManager_CheckReadiness_MixedWithNonHealthCheckable(t *testing.T) {
	manager := NewManager()
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&nonHealthCheckableComponent{name: "ignored"})
	manager.Register(&mockHealthyComponent{name: "comp2"})

	components := manager.CheckReadiness(t.Context())
	response := health.NewReadinessResponse(components)

	require.Equal(t, health.Ready, response.Status)
	require.Len(t, components, 2)
}
