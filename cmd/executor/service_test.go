package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	// Register uses GenericConfig because the registry still decodes it.
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

// monitoredDestinationReader records what attachExecutorMonitoring delivers through the
// optional chainaccess.ExecutorMonitoringSetter capability.
type monitoredDestinationReader struct {
	chainaccess.DestinationReader
	got monitoring.Monitoring
}

func (m *monitoredDestinationReader) SetExecutorMonitoring(mon monitoring.Monitoring) { m.got = mon }

// monitoredContractTransmitter does the same for the transmitter side.
type monitoredContractTransmitter struct {
	chainaccess.ContractTransmitter
	got monitoring.Monitoring
}

func (m *monitoredContractTransmitter) SetExecutorMonitoring(mon monitoring.Monitoring) { m.got = mon }

// TestAttachExecutorMonitoring verifies that accessor-built destination components receive the
// process-level monitoring through the optional capability, and that components without the
// capability are skipped without error.
func TestAttachExecutorMonitoring(t *testing.T) {
	mon := monitoring.NewNoopExecutorMonitoring()

	dr := &monitoredDestinationReader{DestinationReader: mocks.NewMockDestinationReader(t)}
	ct := &monitoredContractTransmitter{ContractTransmitter: mocks.NewMockContractTransmitter(t)}
	attachExecutorMonitoring(dr, ct, mon)
	require.True(t, dr.got == mon, "destination reader must receive the process monitoring")
	require.True(t, ct.got == mon, "contract transmitter must receive the process monitoring")

	plainDR := mocks.NewMockDestinationReader(t)
	plainCT := mocks.NewMockContractTransmitter(t)
	attachExecutorMonitoring(plainDR, plainCT, mon) // components without the capability are skipped
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
		logger.Nop(),
		"",
		mocks.NewMockExecutor(t),
		mocks.NewMockMessageSubscriber(t),
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mocks.NewMockTimeProvider(t),
		1,
		time.Second)
	require.NoError(t, err)

	f := NewFactory()
	f.coordinator = coord
	// Close on an unstarted coordinator returns an error from the state machine.
	err = f.Stop(context.Background())
	require.Error(t, err)
}

// TestFactory_Validate exercises the ServiceFactoryValidator implementation: the same
// decode+normalize checks Start performs, but with no services constructed.
func TestFactory_Validate(t *testing.T) {
	const appConfig = `
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]

[chain_configuration."5009297550715157269"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
`
	f := NewFactory()

	require.NoError(t, f.Validate(bootstrap.JobSpec{AppConfig: appConfig}))
	assert.Nil(t, f.coordinator, "validation must not construct services")
	assert.Nil(t, f.profiler, "validation must not construct services")

	err := f.Validate(bootstrap.JobSpec{AppConfig: "not valid toml =="})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode executor config")

	// Empty TOML decodes but required fields are absent.
	err = f.Validate(bootstrap.JobSpec{AppConfig: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to normalize executor config")
}

// TestFactory_Stop_Idempotent verifies Stop clears its references after the close attempt,
// so a repeated Stop (e.g. best-effort teardown during a replacement rollback) is a no-op.
func TestFactory_Stop_Idempotent(t *testing.T) {
	coord, err := executorsvc.NewCoordinator(
		logger.Nop(),
		"",
		mocks.NewMockExecutor(t),
		mocks.NewMockMessageSubscriber(t),
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mocks.NewMockTimeProvider(t),
		1,
		time.Second,
	)
	require.NoError(t, err)

	f := NewFactory()
	f.coordinator = coord
	require.Error(t, f.Stop(context.Background()), "Close on an unstarted coordinator errors")
	assert.Nil(t, f.coordinator)
	require.NoError(t, f.Stop(context.Background()), "second Stop is a no-op")
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
	lggr := logger.Nop()
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Logger: lggr, Registry: reg})
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
	lggr := logger.Nop()
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Logger: lggr, Registry: reg})
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
	lggr := logger.Nop()
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Logger: lggr, Registry: reg})
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
	lggr := logger.Nop()
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Logger: lggr, Registry: reg})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create leader elector")
}

// freeTCPPort asks the kernel for an unused TCP port and immediately releases it, so tests
// that start an HTTP server do not collide with each other or with a real deployment on a
// shared CI host.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// TestFactory_Start_Success runs a full startup/shutdown cycle using mock
// accessors and a valid config. No external services are required.
// http_listen_port is set to a kernel-allocated free port so the test's HTTP
// server cannot collide with a real deployment or a concurrent test run.
func TestFactory_Start_Success(t *testing.T) {
	newWorkingEVMFactory(t)

	appConfig := fmt.Sprintf(`
executor_id = "test-executor"
indexer_address = ["http://localhost:9090"]
http_listen_port = %d

[chain_configuration."5009297550715157269"]
off_ramp_address     = "0x0000000000000000000000000000000000000001"
rmn_address          = "0x0000000000000000000000000000000000000002"
default_executor_address = "0x0000000000000000000000000000000000000003"
executor_pool        = ["test-executor"]
execution_interval   = "1s"
`, freeTCPPort(t))
	lggr := logger.Nop()
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	f := NewFactory()
	err = f.Start(context.Background(), bootstrap.JobSpec{AppConfig: appConfig}, bootstrap.ServiceDeps{Logger: lggr, Registry: reg})
	require.NoError(t, err)
	require.NoError(t, f.Stop(context.Background()))
}

func TestStartPyroscope_EmptyAddress(t *testing.T) {
	lggr := logger.Nop()
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
	m := SetupMonitoring(executorsvc.MonitoringConfig{})
	require.NotNil(t, m)
}
