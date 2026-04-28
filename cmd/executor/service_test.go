package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// evmFactory is the per-test AccessorFactory used by the registered "evm" driver.
// Tests that need working accessor behavior assign a configured mock before calling
// Start and register cleanup via t.Cleanup to restore the nil default.
var evmFactory chainaccess.AccessorFactory

type evmFactoryProxy struct{}

func (p *evmFactoryProxy) GetAccessor(ctx context.Context, sel protocol.ChainSelector) (chainaccess.Accessor, error) {
	if evmFactory != nil {
		return evmFactory.GetAccessor(ctx, sel)
	}
	return nil, errors.New("no accessor in test mode")
}

func init() {
	// Register a test EVM factory so that NewRegistry picks it up.
	// Default nil evmFactory keeps existing tests working (GetAccessor returns error);
	// tests that need a working accessor assign evmFactory before calling Start.
	chainaccess.Register("evm", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		return &evmFactoryProxy{}, nil
	})
}

// newWorkingEVMFactory wires up a mock AccessorFactory that returns a functional
// mock Accessor (with mock ContractTransmitter and DestinationReader). It sets the
// package-level evmFactory and registers cleanup to restore the nil default.
func newWorkingEVMFactory(t *testing.T) {
	t.Helper()
	ct := mocks.NewMockContractTransmitter(t)
	dr := mocks.NewMockDestinationReader(t)
	acc := mocks.NewMockAccessor(t)
	acc.EXPECT().ContractTransmitter().Return(ct, nil)
	acc.EXPECT().DestinationReader().Return(dr, nil)
	fac := mocks.NewMockAccessorFactory(t)
	fac.EXPECT().GetAccessor(mock.Anything, mock.Anything).Return(acc, nil)
	evmFactory = fac
	t.Cleanup(func() { evmFactory = nil })
}

// --- tests ---

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

// TestFactory_Start_NoAccessors provides a fully valid config but the test EVM
// factory (in fail mode) returns an error for every chain accessor lookup. The
// chainlink executor validation then rejects the resulting empty transmitter map.
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
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Registry: reg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate chainlink executor")
}

// TestFactory_Start_InvalidChainSelector puts a non-numeric key in
// chain_configuration, which causes strconv.ParseUint to fail in both
// chain-config loops. The chain is skipped, validation fails.
func TestFactory_Start_InvalidChainSelector(t *testing.T) {
	const appConfig = `
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]

[chain_configuration."not-a-number"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
`
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Registry: reg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate chainlink executor")
}

// TestFactory_Start_InvalidExecutorAddress uses a valid chain selector but a
// non-hex default_executor_address. The second chain-config loop logs an error
// and skips the chain; validation still fails because contractTransmitters is
// empty (the accessor lookup also fails in fail mode).
func TestFactory_Start_InvalidExecutorAddress(t *testing.T) {
	const appConfig = `
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]

[chain_configuration."5009297550715157269"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "not-valid-hex"
executor_pool        = ["test-executor"]
`
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Registry: reg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate chainlink executor")
}

// TestFactory_Start_LeaderElectorError uses working accessor mocks so
// contractTransmitters becomes non-empty and validation passes, but duplicate
// entries in executor_pool cause NewHashBasedLeaderElector to fail.
func TestFactory_Start_LeaderElectorError(t *testing.T) {
	newWorkingEVMFactory(t)

	const appConfig = `
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]

[chain_configuration."5009297550715157269"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor", "test-executor"]
`
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Registry: reg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create leader elector")
}

// TestFactory_Start_Success runs a full startup/shutdown cycle using mock
// accessors and a valid config. No external services are required.
func TestFactory_Start_Success(t *testing.T) {
	newWorkingEVMFactory(t)

	const appConfig = `
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]

[chain_configuration."5009297550715157269"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
execution_interval   = "1s"
`
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Registry: reg})
	require.NoError(t, err)
	require.NoError(t, f.Stop(context.Background()))
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
