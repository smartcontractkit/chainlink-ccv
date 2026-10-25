package bootstrap

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
)

// stopOrderSpyFactory records the order of factory start, factory stop and accessor close.
type stopOrderSpyFactory struct {
	t        *testing.T
	mu       sync.Mutex
	events   []string
	startErr error
}

func (f *stopOrderSpyFactory) record(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *stopOrderSpyFactory) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *stopOrderSpyFactory) Start(_ context.Context, _ JobSpec, deps ServiceDeps) error {
	// Hand out an accessor so CloseAll has something to close.
	acc := mocks.NewMockAccessor(f.t)
	acc.EXPECT().Close().RunAndReturn(func() error {
		f.record("CloseAll")
		return nil
	}).Maybe()
	ar := deps.Registry.(*AccessorCloserRegistry)
	ar.mu.Lock()
	ar.accessors = append(ar.accessors, acc)
	ar.mu.Unlock()
	f.record("Start")
	return f.startErr
}

func (f *stopOrderSpyFactory) Stop(context.Context) error {
	f.record("Stop")
	return nil
}

func (f *stopOrderSpyFactory) MetricViews() []sdkmetric.View { return nil }

var _ ServiceFactory = (*stopOrderSpyFactory)(nil)

func newSpyRunner(t *testing.T, fac ServiceFactory) *runner {
	t.Helper()
	return &runner{lggr: logger.Test(t), fac: fac}
}

const jobConfig = "name = \"test\"\nappConfig = \"\""

func TestRunner_StartJobFailure_StopsTheFactoryBeforeClosingAccessors(t *testing.T) {
	t.Parallel()
	fac := &stopOrderSpyFactory{t: t, startErr: errors.New("start failed")}
	r := newSpyRunner(t, fac)

	err := r.StartJob(t.Context(), jobConfig)
	require.ErrorContains(t, err, "start failed")
	require.Equal(t, []string{"Start", "Stop", "CloseAll"}, fac.log())
}

func TestBootstrapper_LocalStartFailure_StopsTheFactoryBeforeClosingAccessors(t *testing.T) {
	t.Parallel()
	fac := &stopOrderSpyFactory{t: t, startErr: errors.New("start failed")}
	appPath := writeAppConfigFile(t, "")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, ""))
	b, err := NewBootstrapper("t", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)

	require.ErrorContains(t, b.Start(t.Context()), "start failed")
	require.Equal(t, []string{"Start", "Stop", "CloseAll"}, fac.log())
}

func TestBootstrapper_StopLocal_StopsTheFactoryBeforeClosingAccessors(t *testing.T) {
	t.Parallel()
	fac := &stopOrderSpyFactory{t: t}
	appPath := writeAppConfigFile(t, "")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, ""))
	b, err := NewBootstrapper("t", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)
	require.NoError(t, b.Start(t.Context()))

	require.NoError(t, b.Stop(t.Context()))
	require.Equal(t, []string{"Start", "Stop", "CloseAll"}, fac.log())
}
