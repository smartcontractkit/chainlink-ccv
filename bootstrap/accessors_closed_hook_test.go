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
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// hookSpyFactory records the order of factory stop, accessor close and hook calls.
type hookSpyFactory struct {
	t        *testing.T
	mu       sync.Mutex
	events   []string
	startErr error
	hookErr  error
}

func (f *hookSpyFactory) record(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *hookSpyFactory) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *hookSpyFactory) Start(_ context.Context, _ JobSpec, deps ServiceDeps) error {
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

func (f *hookSpyFactory) Stop(context.Context) error {
	f.record("Stop")
	return nil
}

func (f *hookSpyFactory) MetricViews() []sdkmetric.View { return nil }

func (f *hookSpyFactory) AfterAccessorsClosed(context.Context) error {
	f.record("AfterAccessorsClosed")
	return f.hookErr
}

var (
	_ ServiceFactory      = (*hookSpyFactory)(nil)
	_ AccessorsClosedHook = (*hookSpyFactory)(nil)
)

func newHookRunner(t *testing.T, fac ServiceFactory) *runner {
	t.Helper()
	return &runner{lggr: logger.Test(t), fac: fac}
}

const jobConfig = "name = \"test\"\nappConfig = \"\""

func TestRunner_StopJob_CallsHookAfterCloseAll(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t}
	r := newHookRunner(t, fac)
	require.NoError(t, r.StartJob(t.Context(), jobConfig))

	require.NoError(t, r.StopJob(t.Context()))
	require.Equal(t, []string{"Start", "Stop", "CloseAll", "AfterAccessorsClosed"}, fac.log())
}

func TestRunner_StopJob_HookRunsWhenNoJobEverStarted(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t}
	r := newHookRunner(t, fac)

	require.NoError(t, r.StopJob(t.Context()))
	require.Equal(t, []string{"Stop", "AfterAccessorsClosed"}, fac.log())
}

func TestRunner_StopJob_HookRunsAndErrorSurfacesWhenCloseAllFails(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t, hookErr: errors.New("hook boom")}
	r := newHookRunner(t, fac)
	require.NoError(t, r.StartJob(t.Context(), jobConfig))
	// Replace the tracked accessor with one whose Close fails.
	bad := mocks.NewMockAccessor(t)
	bad.EXPECT().Close().Return(errors.New("close boom")).Once()
	r.accCloser.mu.Lock()
	r.accCloser.accessors = []chainaccess.Accessor{bad}
	r.accCloser.mu.Unlock()

	err := r.StopJob(t.Context())
	require.ErrorContains(t, err, "close boom")
	require.ErrorContains(t, err, "hook boom")
	require.Equal(t, []string{"Start", "Stop", "AfterAccessorsClosed"}, fac.log())
}

func TestRunner_StartJobFailure_CallsHookAfterStopAndCloseAll(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t, startErr: errors.New("start failed")}
	r := newHookRunner(t, fac)

	err := r.StartJob(t.Context(), jobConfig)
	require.ErrorContains(t, err, "start failed")
	require.Equal(t, []string{"Start", "Stop", "CloseAll", "AfterAccessorsClosed"}, fac.log())
}

func TestBootstrapper_LocalStartFailure_CallsHookAfterCloseAll(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t, startErr: errors.New("start failed")}
	appPath := writeAppConfigFile(t, "")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, ""))
	b, err := NewBootstrapper("t", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)

	require.ErrorContains(t, b.Start(t.Context()), "start failed")
	require.Equal(t, []string{"Start", "Stop", "CloseAll", "AfterAccessorsClosed"}, fac.log())
}

func TestBootstrapper_StopLocal_CallsHookAfterCloseAll(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t}
	appPath := writeAppConfigFile(t, "")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, ""))
	b, err := NewBootstrapper("t", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)
	require.NoError(t, b.Start(t.Context()))

	require.NoError(t, b.Stop(t.Context()))
	require.Equal(t, []string{"Start", "Stop", "CloseAll", "AfterAccessorsClosed"}, fac.log())
}

func TestBootstrapper_StopLocal_HookErrorSurfaces(t *testing.T) {
	t.Parallel()
	fac := &hookSpyFactory{t: t, hookErr: errors.New("hook boom")}
	appPath := writeAppConfigFile(t, "")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, ""))
	b, err := NewBootstrapper("t", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)
	require.NoError(t, b.Start(t.Context()))

	err = b.Stop(t.Context())
	require.ErrorContains(t, err, "failed to release resources after accessors closed")
	require.ErrorContains(t, err, "hook boom")
	require.Equal(t, []string{"Start", "Stop", "CloseAll", "AfterAccessorsClosed"}, fac.log())
}

// noHookFactory is hookSpyFactory without AfterAccessorsClosed.
type noHookFactory struct{ spy *hookSpyFactory }

func (f noHookFactory) Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error {
	return f.spy.Start(ctx, spec, deps)
}
func (f noHookFactory) Stop(ctx context.Context) error { return f.spy.Stop(ctx) }
func (f noHookFactory) MetricViews() []sdkmetric.View  { return nil }

func TestRunner_FactoryWithoutHookIsUnaffected(t *testing.T) {
	t.Parallel()
	_, isHook := ServiceFactory(noHookFactory{}).(AccessorsClosedHook)
	require.False(t, isHook)

	t.Run("StopJob", func(t *testing.T) {
		t.Parallel()
		spy := &hookSpyFactory{t: t}
		r := newHookRunner(t, noHookFactory{spy})
		require.NoError(t, r.StartJob(t.Context(), jobConfig))
		require.NoError(t, r.StopJob(t.Context()))
		require.Equal(t, []string{"Start", "Stop", "CloseAll"}, spy.log())
	})

	t.Run("failed StartJob", func(t *testing.T) {
		t.Parallel()
		spy := &hookSpyFactory{t: t, startErr: errors.New("start failed")}
		r := newHookRunner(t, noHookFactory{spy})
		require.ErrorContains(t, r.StartJob(t.Context(), jobConfig), "start failed")
		require.Equal(t, []string{"Start", "Stop", "CloseAll"}, spy.log())
	})
}
