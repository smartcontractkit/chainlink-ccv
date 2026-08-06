package evm

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
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
}

type runtimeContextMarkerKey struct{}

const (
	validTestOffRampAddress   = "0x0000000000000000000000000000000000001234"
	validTestRMNRemoteAddress = "0x0000000000000000000000000000000000005678"
	zeroTestAddress           = "0x0000000000000000000000000000000000000000"
)

func (s *stubChainRuntime) ChainClient() (client.Client, error) { return s.Client, s.clientErr }
func (s *stubChainRuntime) HeadTracker() (heads.Tracker, error) { return s.Tracker, s.trackerErr }

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

	accessor := newAccessor(
		logger.Test(t),
		protocol.ChainSelector(42),
		&stubChainRuntime{},
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
		func(context.Context, protocol.ChainSelector, logger.Logger, sqlutil.DataSource) (chainRuntime, error) {
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

	const selector = protocol.ChainSelector(5009297550715157269)
	tests := []struct {
		name   string
		config chainaccess.DestinationChainConfig
	}{
		{
			name:   "missing RMN remote",
			config: chainaccess.DestinationChainConfig{OffRampAddress: validTestOffRampAddress},
		},
		{
			name:   "missing off-ramp",
			config: chainaccess.DestinationChainConfig{RmnAddress: validTestRMNRemoteAddress},
		},
		{
			name: "malformed off-ramp",
			config: chainaccess.DestinationChainConfig{
				OffRampAddress: "0x1234",
				RmnAddress:     validTestRMNRemoteAddress,
			},
		},
		{
			name: "zero RMN remote",
			config: chainaccess.DestinationChainConfig{
				OffRampAddress: validTestOffRampAddress,
				RmnAddress:     zeroTestAddress,
			},
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
				func(context.Context, protocol.ChainSelector, logger.Logger, sqlutil.DataSource) (chainRuntime, error) {
					runtimeCalls++
					return &stubChainRuntime{}, nil
				},
			)

			accessor, err := factory.GetAccessor(context.Background(), selector)
			require.Nil(t, accessor)
			require.ErrorContains(t, err, "destination services require valid non-zero off-ramp and RMN remote addresses")
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
		func(context.Context, protocol.ChainSelector, logger.Logger, sqlutil.DataSource) (chainRuntime, error) {
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
		func(context.Context, protocol.ChainSelector, logger.Logger, sqlutil.DataSource) (chainRuntime, error) {
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
		func(context.Context, protocol.ChainSelector, logger.Logger, sqlutil.DataSource) (chainRuntime, error) {
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
