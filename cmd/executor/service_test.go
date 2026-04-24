package executor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	require.NotNil(t, f)
	assert.Nil(t, f.coordinator)
	assert.Nil(t, f.profiler)
}

func TestFactory_Stop_NilFields(t *testing.T) {
	f := NewFactory()
	require.NoError(t, f.Stop(context.Background()))
}

// TestFactory_Stop_WithCoordinator verifies that Stop calls Close on a non-nil
// coordinator and propagates any error.
func TestFactory_Stop_WithCoordinator(t *testing.T) {
	coord, err := executorsvc.NewCoordinator(
		logger.Test(t),
		mocks.NewMockExecutor(t),
		mocks.NewMockMessageSubscriber(t),
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mocks.NewMockTimeProvider(t),
		1,
	)
	require.NoError(t, err)

	f := NewFactory()
	f.coordinator = coord
	// Close on an unstarted coordinator returns an error from the state machine.
	err = f.Stop(context.Background())
	require.Error(t, err)
}

func TestFactory_Start_InvalidTOML(t *testing.T) {
	f := NewFactory()
	spec := bootstrap.JobSpec{AppConfig: "not valid toml =="}
	err := f.Start(context.Background(), spec, bootstrap.ServiceDeps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode executor config")
}

func TestFactory_Start_EmptyConfig(t *testing.T) {
	// Empty TOML is valid; validation fails because required fields are absent.
	f := NewFactory()
	spec := bootstrap.JobSpec{AppConfig: ""}
	err := f.Start(context.Background(), spec, bootstrap.ServiceDeps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to normalize executor config")
}

// TestFactory_Start_NoAccessors provides a fully valid config but an empty
// registry so every chain accessor lookup fails. The chainlink executor
// validation then rejects the resulting empty transmitter/reader maps.
func TestFactory_Start_NoAccessors(t *testing.T) {
	const appConfig = `
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]

[chain_configuration."5009297550715157269"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
`
	// NewRegistry with no imported accessor factories produces an empty registry,
	// so GetAccessor returns an error for every chain and the loop skips all chains.
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Registry: reg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate chainlink executor")
}

func TestStartPyroscope_EmptyAddress(t *testing.T) {
	lggr := logger.Test(t)
	p, err := StartPyroscope(lggr, "", "test-service")
	if err != nil {
		assert.Nil(t, p)
		return
	}
	// Profiler started successfully — exercise the profiler != nil Stop path.
	require.NotNil(t, p)
	f := NewFactory()
	f.profiler = p
	require.NoError(t, f.Stop(context.Background()))
}

func TestSetupMonitoring_Disabled(t *testing.T) {
	lggr := logger.Test(t)
	m := SetupMonitoring(lggr, executorsvc.MonitoringConfig{Enabled: false})
	require.NotNil(t, m)
}

func TestSetupMonitoring_EnabledButNotBeholder(t *testing.T) {
	lggr := logger.Test(t)
	m := SetupMonitoring(lggr, executorsvc.MonitoringConfig{Enabled: true, Type: "noop"})
	require.NotNil(t, m)
}
