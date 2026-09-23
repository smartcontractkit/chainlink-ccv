package evm

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
)

type stubChainRuntime struct {
	client.Client
	heads.Tracker

	transmitter chainaccess.ContractTransmitter
	transmitErr error
	clientErr   error
	trackerErr  error
	closeErr    error
	setCalls    int
	closeCalls  int
	gotMarker   string
	gotSelector protocol.ChainSelector
	gotKeystore keystore.Keystore
	gotKeyName  string
	gotOffRamp  common.Address

	sourceReaderHeaderFetchBatchSize int

	logPollerMode  evmconfig.LogPollerMode
	logPoller      logpoller.LogPoller
	logPollerErr   error
	logPollerCalls int
	gotDataSource  sqlutil.DataSource
}

type runtimeContextMarkerKey struct{}

const (
	validTestOffRampAddress   = "0x0000000000000000000000000000000000001234"
	validTestRMNRemoteAddress = "0x0000000000000000000000000000000000005678"
	zeroTestAddress           = "0x0000000000000000000000000000000000000000"
)

func (s *stubChainRuntime) ChainClient() (client.Client, error) { return s.Client, s.clientErr }
func (s *stubChainRuntime) HeadTracker() (heads.Tracker, error) { return s.Tracker, s.trackerErr }
func (s *stubChainRuntime) SourceReaderHeaderFetchBatchSize() int {
	return s.sourceReaderHeaderFetchBatchSize
}

func (s *stubChainRuntime) LogPollerMode() evmconfig.LogPollerMode { return s.logPollerMode }

func (s *stubChainRuntime) LogPoller(ctx context.Context, ds sqlutil.DataSource) (logpoller.LogPoller, error) {
	s.logPollerCalls++
	s.gotDataSource = ds
	return s.logPoller, s.logPollerErr
}

func (s *stubChainRuntime) NewContractTransmitter(
	ctx context.Context,
	selector protocol.ChainSelector,
	ks keystore.Keystore,
	keyName string,
	offRamp common.Address,
) (chainaccess.ContractTransmitter, error) {
	s.setCalls++
	s.gotMarker, _ = ctx.Value(runtimeContextMarkerKey{}).(string)
	s.gotSelector = selector
	s.gotKeystore = ks
	s.gotKeyName = keyName
	s.gotOffRamp = offRamp
	return s.transmitter, s.transmitErr
}

func (s *stubChainRuntime) Close() error {
	s.closeCalls++
	return s.closeErr
}

type noopContractTransmitter struct{}

func (noopContractTransmitter) ConvertAndWriteMessageToChain(context.Context, protocol.AbstractAggregatedReport) error {
	return nil
}

func TestAccessorStartsRuntimeContractTransmitterAndOwnsLifecycle(t *testing.T) {
	t.Parallel()

	const contextMarker = "context-marker"
	ctx := context.WithValue(context.Background(), runtimeContextMarkerKey{}, contextMarker)
	offRamp := common.HexToAddress("0x1234")
	tx := noopContractTransmitter{}
	runtime := &stubChainRuntime{transmitter: tx}
	accessor := newAccessor(
		logger.Test(t),
		protocol.ChainSelector(42),
		runtime,
		runtime.Close,
		offRamp,
		"evm-key",
		nil,
		nil,
		nil,
	).(*accessor)

	require.NoError(t, accessor.SetKeystore(ctx, nil))
	got, err := accessor.ContractTransmitter()
	require.NoError(t, err)
	require.Equal(t, tx, got)
	require.Equal(t, 1, runtime.setCalls)
	require.Equal(t, contextMarker, runtime.gotMarker)
	require.Equal(t, protocol.ChainSelector(42), runtime.gotSelector)
	require.Equal(t, "evm-key", runtime.gotKeyName)
	require.Equal(t, offRamp, runtime.gotOffRamp)

	require.NoError(t, accessor.Close())
	require.Equal(t, 1, runtime.closeCalls)
}

func TestAccessorPropagatesRuntimeContractTransmitterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("txm failed to start")
	runtime := &stubChainRuntime{transmitErr: wantErr}
	accessor := newAccessor(
		logger.Test(t),
		protocol.ChainSelector(42),
		runtime,
		runtime.Close,
		common.HexToAddress("0x1234"),
		"evm-key",
		nil,
		nil,
		nil,
	).(*accessor)

	err := accessor.SetKeystore(context.Background(), nil)
	require.ErrorIs(t, err, wantErr)
}

func TestAccessorRejectsNilRuntimeContractTransmitter(t *testing.T) {
	t.Parallel()

	runtime := &stubChainRuntime{}
	accessor := newAccessor(
		logger.Test(t),
		protocol.ChainSelector(42),
		runtime,
		runtime.Close,
		common.HexToAddress("0x1234"),
		"evm-key",
		nil,
		nil,
		nil,
	).(*accessor)

	err := accessor.SetKeystore(context.Background(), nil)
	require.ErrorContains(t, err, "transmitter is nil")
}

func TestSourceOnlyAccessorDoesNotStartTransactionManager(t *testing.T) {
	t.Parallel()

	runtime := &stubChainRuntime{transmitErr: errors.New("must not be called")}
	accessor := newAccessor(
		logger.Test(t),
		protocol.ChainSelector(42),
		runtime,
		runtime.Close,
		common.Address{},
		"evm-key",
		nil,
		nil,
		nil,
	).(*accessor)

	require.NoError(t, accessor.SetKeystore(context.Background(), nil))
	require.Zero(t, runtime.setCalls)
}

func TestFactoryRejectsAccessorWithoutCapabilitiesBeforeStartingRuntime(t *testing.T) {
	t.Parallel()

	runtimeCalls := 0
	factory := newFactory(
		logger.Test(t),
		nil,
		nil,
		nil,
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			runtimeCalls++
			return &stubChainRuntime{}, nil
		},
	)

	accessor, err := factory.GetAccessor(context.Background(), protocol.ChainSelector(5009297550715157269))
	require.Nil(t, accessor)
	require.ErrorContains(t, err, "neither source nor destination services are configured")
	require.Zero(t, runtimeCalls)
}

func TestIsValidAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		want    bool
	}{
		{name: "valid", address: validTestOffRampAddress, want: true},
		{name: "empty", address: "", want: false},
		{name: "short", address: "0x1234", want: false},
		{name: "malformed", address: "0x000000000000000000000000000000000000zzzz", want: false},
		{name: "zero", address: zeroTestAddress, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, isValidAddress(tt.address))
		})
	}
}

func TestFactoryRejectsIncompleteDestinationConfigBeforeStartingRuntime(t *testing.T) {
	t.Parallel()

	// A destination config entry with an off-ramp address set to something that is not a valid
	// non-zero address is rejected before the runtime starts. An entry carrying only the
	// deprecated rmn_address signals destination intent too and fails the same gate. An entry
	// with neither address carries no destination intent: it falls through to the "neither
	// source nor destination services are configured" gate covered by
	// TestFactoryRejectsAccessorWithoutCapabilitiesBeforeStartingRuntime.
	const selector = protocol.ChainSelector(5009297550715157269)
	tests := []struct {
		name   string
		config chainaccess.DestinationChainConfig
	}{
		{
			name:   "malformed off-ramp",
			config: chainaccess.DestinationChainConfig{OffRampAddress: "0x1234"},
		},
		{
			name:   "missing off-ramp, only deprecated rmn_address set",
			config: chainaccess.DestinationChainConfig{RmnAddress: validTestRMNRemoteAddress},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runtimeCalls := 0
			factory := newFactory(
				logger.Test(t),
				nil,
				nil,
				map[protocol.ChainSelector]chainaccess.DestinationChainConfig{selector: tt.config},
				0,
				func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
					runtimeCalls++
					return &stubChainRuntime{}, nil
				},
			)

			accessor, err := factory.GetAccessor(context.Background(), selector)
			require.Nil(t, accessor)
			require.ErrorContains(t, err, "destination services require a valid non-zero off-ramp address")
			require.Zero(t, runtimeCalls)
		})
	}
}

func TestFactoryClosesRuntimeWhenChainClientIsUnavailable(t *testing.T) {
	t.Parallel()

	const selector = protocol.ChainSelector(5009297550715157269)
	wantErr := errors.New("chain client unavailable")
	runtime := &stubChainRuntime{clientErr: wantErr}
	factory := newFactory(
		logger.Test(t),
		nil,
		nil,
		map[protocol.ChainSelector]chainaccess.DestinationChainConfig{
			selector: {
				OffRampAddress: validTestOffRampAddress,
				RmnAddress:     validTestRMNRemoteAddress,
			},
		},
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			return runtime, nil
		},
	)

	accessor, err := factory.GetAccessor(context.Background(), selector)
	require.Nil(t, accessor)
	require.ErrorIs(t, err, wantErr)
	require.ErrorContains(t, err, "failed to get EVM chain client")
	require.Equal(t, 1, runtime.closeCalls)
}

func TestFactoryRejectsNilRuntime(t *testing.T) {
	t.Parallel()

	const selector = protocol.ChainSelector(5009297550715157269)
	factory := newFactory(
		logger.Test(t),
		nil,
		nil,
		map[protocol.ChainSelector]chainaccess.DestinationChainConfig{
			selector: {
				OffRampAddress: validTestOffRampAddress,
				RmnAddress:     validTestRMNRemoteAddress,
			},
		},
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			return nil, nil
		},
	)

	accessor, err := factory.GetAccessor(context.Background(), selector)
	require.Nil(t, accessor)
	require.ErrorContains(t, err, "runtime is nil")
}

func TestFactoryIncludesRuntimeCloseFailureInComponentError(t *testing.T) {
	t.Parallel()

	const selector = protocol.ChainSelector(5009297550715157269)
	clientErr := errors.New("chain client unavailable")
	closeErr := errors.New("runtime close failed")
	runtime := &stubChainRuntime{clientErr: clientErr, closeErr: closeErr}
	factory := newFactory(
		logger.Test(t),
		nil,
		nil,
		map[protocol.ChainSelector]chainaccess.DestinationChainConfig{
			selector: {
				OffRampAddress: validTestOffRampAddress,
				RmnAddress:     validTestRMNRemoteAddress,
			},
		},
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			return runtime, nil
		},
	)

	accessor, err := factory.GetAccessor(context.Background(), selector)
	require.Nil(t, accessor)
	require.ErrorIs(t, err, clientErr)
	require.ErrorIs(t, err, closeErr)
	require.Equal(t, 1, runtime.closeCalls)
}

func TestStandaloneChainComponentAccessorsReturnErrorsWhenUnavailable(t *testing.T) {
	t.Parallel()

	runtime := &standaloneChain{}

	chainClient, err := runtime.ChainClient()
	require.Nil(t, chainClient)
	require.ErrorContains(t, err, "chain client is not available")

	headTracker, err := runtime.HeadTracker()
	require.Nil(t, headTracker)
	require.ErrorContains(t, err, "head tracker is not available")
}

// --- runtime reference counting ---------------------------------------------------------------
//
// A chain must have exactly one LogPoller per process, so factory shares one chainRuntime per
// selector and tears it down only when the last accessor holding it closes.

const refcountTestSelector = protocol.ChainSelector(5009297550715157269)

// countingRuntimeBuilder hands out the given runtimes in order, then fresh stubs, and reports how
// many times it was called.
func countingRuntimeBuilder(runtimes ...chainRuntime) (runtimeBuilder, *int) {
	calls := 0
	build := func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
		defer func() { calls++ }()
		if calls < len(runtimes) {
			return runtimes[calls], nil
		}
		return &stubChainRuntime{}, nil
	}
	return build, &calls
}

func newRefcountTestFactory(t *testing.T, build runtimeBuilder) *factory {
	t.Helper()
	return newFactory(logger.Test(t), nil, nil, nil, 0, build).(*factory)
}

// runtimeRefs reports the live reference count for a selector, and whether it is cached at all.
func runtimeRefs(t *testing.T, f *factory, selector protocol.ChainSelector) (int, bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.runtimes[selector]
	if !ok {
		return 0, false
	}
	return entry.refs, true
}

func TestFactorySharesOneRuntimePerChain(t *testing.T) {
	t.Parallel()

	build, calls := countingRuntimeBuilder()
	f := newRefcountTestFactory(t, build)

	first, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)
	second, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)

	require.Equal(t, 1, *calls, "second acquire must reuse the cached runtime, not build another")
	require.Same(t, first, second)

	refs, cached := runtimeRefs(t, f, refcountTestSelector)
	require.True(t, cached)
	require.Equal(t, 2, refs)
}

func TestFactoryKeepsRuntimeUntilLastRelease(t *testing.T) {
	t.Parallel()

	runtime := &stubChainRuntime{}
	build, _ := countingRuntimeBuilder(runtime)
	f := newRefcountTestFactory(t, build)

	_, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)
	_, err = f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)

	require.NoError(t, f.releaseRuntime(refcountTestSelector))
	require.Zero(t, runtime.closeCalls, "a runtime with a live reference must not be closed")
	refs, cached := runtimeRefs(t, f, refcountTestSelector)
	require.True(t, cached)
	require.Equal(t, 1, refs)

	require.NoError(t, f.releaseRuntime(refcountTestSelector))
	require.Equal(t, 1, runtime.closeCalls, "the last release must close the runtime exactly once")
	_, cached = runtimeRefs(t, f, refcountTestSelector)
	require.False(t, cached, "the last release must evict the entry")
}

// A closed runtime must not be handed out again: the job lifecycle restarts a job after a failed
// StopJob (lifecycle/manager.go rollbackReplacement), so a second generation acquires the same
// selector after the first has been released.
func TestFactoryRebuildsRuntimeAfterLastRelease(t *testing.T) {
	t.Parallel()

	first, second := &stubChainRuntime{}, &stubChainRuntime{}
	build, calls := countingRuntimeBuilder(first, second)
	f := newRefcountTestFactory(t, build)

	got, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)
	require.Same(t, first, got)
	require.NoError(t, f.releaseRuntime(refcountTestSelector))

	got, err = f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)
	require.Same(t, second, got, "a released runtime is closed and must never be reused")
	require.Equal(t, 2, *calls)
}

func TestFactoryAcquireCachesNothingOnFailure(t *testing.T) {
	t.Parallel()

	buildErr := errors.New("dial failed")
	tests := []struct {
		name    string
		build   runtimeBuilder
		wantErr string
	}{
		{
			name: "builder error",
			build: func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
				return nil, buildErr
			},
			wantErr: "dial failed",
		},
		{
			// Caching a nil runtime would make every later acquire for this chain return nil.
			name: "builder returned a nil runtime",
			build: func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
				return nil, nil
			},
			wantErr: "runtime is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newRefcountTestFactory(t, tt.build)
			runtime, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
			require.Nil(t, runtime)
			require.ErrorContains(t, err, tt.wantErr)
			_, cached := runtimeRefs(t, f, refcountTestSelector)
			require.False(t, cached)
		})
	}
}

func TestFactoryReleaseOfUnheldRuntimeIsNoop(t *testing.T) {
	t.Parallel()

	build, calls := countingRuntimeBuilder()
	f := newRefcountTestFactory(t, build)

	require.NoError(t, f.releaseRuntime(refcountTestSelector))
	require.Zero(t, *calls)
}

func TestFactoryRuntimeRefcountIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	runtime := &stubChainRuntime{}
	build, calls := countingRuntimeBuilder(runtime)
	f := newRefcountTestFactory(t, build)

	// One reference is held for the whole test, so the count can never reach zero and the builder
	// must run exactly once however the concurrent acquires and releases interleave.
	_, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t))
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			if _, err := f.acquireRuntime(context.Background(), refcountTestSelector, logger.Test(t)); err != nil {
				return
			}
			_ = f.releaseRuntime(refcountTestSelector)
		})
	}
	wg.Wait()

	require.Equal(t, 1, *calls)
	require.Zero(t, runtime.closeCalls)
	refs, cached := runtimeRefs(t, f, refcountTestSelector)
	require.True(t, cached)
	require.Equal(t, 1, refs)

	require.NoError(t, f.releaseRuntime(refcountTestSelector))
	require.Equal(t, 1, runtime.closeCalls)
}

// Close is exported and documented as safe to call more than once, so it must not drop a second
// reference: that would tear down a runtime another accessor is still using.
func TestAccessorCloseDropsExactlyOneReference(t *testing.T) {
	t.Parallel()

	releases := 0
	accessor := newAccessor(
		logger.Test(t),
		refcountTestSelector,
		&stubChainRuntime{},
		func() error { releases++; return nil },
		common.HexToAddress("0x1234"),
		"evm-key",
		nil,
		nil,
		nil,
	)

	require.NoError(t, accessor.Close())
	require.NoError(t, accessor.Close())
	require.NoError(t, accessor.Close())
	require.Equal(t, 1, releases)
}

// Every GetAccessor path that returns an error after a successful acquire owes exactly one
// release, or the chain's runtime and its LogPoller leak for the life of the process.
func TestGetAccessorReleasesRuntimeOnFailure(t *testing.T) {
	t.Parallel()

	clientErr := errors.New("chain client unavailable")
	trackerErr := errors.New("head tracker unavailable")
	nullClient := client.NewNullClient(big.NewInt(1), logger.Test(t))

	tests := []struct {
		name    string
		runtime *stubChainRuntime
		wantErr string
	}{
		{
			name:    "chain client error",
			runtime: &stubChainRuntime{clientErr: clientErr},
			wantErr: "chain client unavailable",
		},
		{
			name:    "nil chain client",
			runtime: &stubChainRuntime{},
			wantErr: "client is nil",
		},
		{
			name:    "head tracker error",
			runtime: &stubChainRuntime{Client: nullClient, trackerErr: trackerErr},
			wantErr: "head tracker unavailable",
		},
		{
			name:    "nil head tracker",
			runtime: &stubChainRuntime{Client: nullClient},
			wantErr: "tracker is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			build, _ := countingRuntimeBuilder(tt.runtime)
			f := newFactory(
				logger.Test(t),
				map[protocol.ChainSelector]string{refcountTestSelector: validTestOffRampAddress},
				nil,
				nil,
				0,
				build,
			).(*factory)

			accessor, err := f.GetAccessor(context.Background(), refcountTestSelector)
			require.Nil(t, accessor)
			require.ErrorContains(t, err, tt.wantErr)

			_, cached := runtimeRefs(t, f, refcountTestSelector)
			require.False(t, cached, "a failed GetAccessor must release the reference it acquired")
			require.Equal(t, 1, tt.runtime.closeCalls, "the released reference was the last one")
		})
	}
}

// SetDataSource is how the per-chain log_poller_mode gate is finally consumed: off chains must
// never touch the database, and a chain that wants a poller must fail loudly without one rather
// than start without it.
func TestAccessorSetDataSource(t *testing.T) {
	t.Parallel()

	ds := sqlx.NewDb(nil, "postgres")
	tests := []struct {
		name       string
		mode       evmconfig.LogPollerMode
		ds         sqlutil.DataSource
		wantErr    string
		wantPoller bool
	}{
		{name: "off needs no database", mode: evmconfig.LogPollerModeOff},
		{
			name:    "shadow without a database",
			mode:    evmconfig.LogPollerModeShadow,
			wantErr: `log_poller_mode "shadow" requires a database`,
		},
		{
			name:    "read without a database",
			mode:    evmconfig.LogPollerModeRead,
			wantErr: `log_poller_mode "read" requires a database`,
		},
		{name: "shadow builds the poller", mode: evmconfig.LogPollerModeShadow, ds: ds, wantPoller: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runtime := &stubChainRuntime{logPollerMode: tt.mode}
			accessor := newAccessor(
				logger.Test(t), refcountTestSelector, runtime, runtime.Close,
				common.Address{}, "evm-key", nil, nil, nil,
			).(*accessor)

			err := accessor.SetDataSource(context.Background(), tt.ds)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if !tt.wantPoller {
				require.Zero(t, runtime.logPollerCalls, "the chain must not touch the database")
				return
			}
			require.Equal(t, 1, runtime.logPollerCalls)
			require.Equal(t, tt.ds, runtime.gotDataSource)
		})
	}
}
