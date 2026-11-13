package health

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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

func TestManager_RegisterHealthCheckable(t *testing.T) {
	manager := NewManager(logger.Nop())

	healthy := &mockHealthyComponent{name: "test"}
	manager.Register(healthy)

	require.Len(t, manager.components, 1)
}

func TestManager_RegisterDuplicatesName(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	manager := NewManager(logger.NewWithCores(core))

	first := &mockHealthyComponent{name: "dup"}
	second := &mockUnhealthyComponent{name: "dup"}
	manager.Register(first)
	manager.Register(second)

	// The later registration wins, so the component is reported once with its status, and the
	// duplicate is logged because it means a component was wired twice.
	require.Len(t, manager.components, 1)
	require.Same(t, second, manager.components[0])

	response := manager.CheckReadiness(context.Background())
	require.Len(t, response.Services, 1)
	require.Equal(t, NotReady, response.Services[0].Status)

	entries := logs.FilterMessage("Replacing a health component with a duplicate name").All()
	require.Len(t, entries, 1, "a duplicate name must be logged")
	require.Equal(t, "dup", entries[0].ContextMap()["name"])
}

func TestManager_RegisterDistinctNames(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	manager := NewManager(logger.NewWithCores(core))

	manager.Register(&mockHealthyComponent{name: "one"})
	manager.Register(&mockHealthyComponent{name: "two"})

	require.Len(t, manager.components, 2)
	require.Empty(t, logs.All(), "distinct names must not log")
}

func TestManager_CheckLiveness(t *testing.T) {
	manager := NewManager(logger.Nop())

	result := manager.CheckLiveness(context.Background())

	require.Equal(t, http.StatusOK, result.StatusCode())
	require.Equal(t, Alive, result.Status)
}

func TestManager_CheckReadiness_AllHealthy(t *testing.T) {
	manager := NewManager(logger.Nop())
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&mockHealthyComponent{name: "comp2"})

	response := manager.CheckReadiness(t.Context())

	require.Equal(t, Ready, response.Status)
	require.Len(t, response.Services, 2)
}

func TestManager_CheckReadiness_CriticalUnhealthy(t *testing.T) {
	manager := NewManager(logger.Nop())
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&mockUnhealthyComponent{name: "comp2"})

	response := manager.CheckReadiness(t.Context())

	require.Equal(t, NotReady, response.Status)
	require.Len(t, response.Services, 2)
}

func TestManager_CheckReadiness_MultipleHealthy(t *testing.T) {
	manager := NewManager(logger.Nop())
	manager.Register(&mockHealthyComponent{name: "comp1"})
	manager.Register(&mockHealthyComponent{name: "comp2"})

	response := manager.CheckReadiness(t.Context())

	require.Equal(t, Ready, response.Status)
	require.Len(t, response.Services, 2)
}
