package evm

import (
	"context"
	"errors"
	"math/big"
	"testing"

	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/pricereader/pricereadertest"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/assets"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/gas/rollups"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
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

	daOracle      rollups.L1Oracle
	daOracleErr   error
	daOracleCalls int
	addresses     []common.Address
	addressesErr  error
	gotAddrKey    string

	writer           chainaccess.FeeQuoterWriter
	writerErr        error
	gotWriterKey     string
	gotWriterAddress common.Address

	sourceReaderHeaderFetchBatchSize int
	sourceReaderMaxLogBlockRange     uint64
}

type runtimeContextMarkerKey struct{}

const (
	validTestOffRampAddress   = "0x0000000000000000000000000000000000001234"
	validTestFeeQuoterAddress = "0x0000000000000000000000000000000000009abc"
	validTestRMNRemoteAddress = "0x0000000000000000000000000000000000005678"
	zeroTestAddress           = "0x0000000000000000000000000000000000000000"
)

func (s *stubChainRuntime) ChainClient() (client.Client, error) { return s.Client, s.clientErr }
func (s *stubChainRuntime) HeadTracker() (heads.Tracker, error) { return s.Tracker, s.trackerErr }
func (s *stubChainRuntime) DAGasPriceOracle(context.Context) (rollups.L1Oracle, error) {
	s.daOracleCalls++
	return s.daOracle, s.daOracleErr
}

func (s *stubChainRuntime) TransmitterAddresses(_ context.Context, _ keystore.Keystore, keyName string) ([]common.Address, error) {
	s.gotAddrKey = keyName
	return s.addresses, s.addressesErr
}

func (s *stubChainRuntime) SourceReaderHeaderFetchBatchSize() int {
	return s.sourceReaderHeaderFetchBatchSize
}

func (s *stubChainRuntime) SourceReaderMaxLogBlockRange() uint64 {
	return s.sourceReaderMaxLogBlockRange
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

func (s *stubChainRuntime) NewFeeQuoterWriter(_ context.Context, _ keystore.Keystore, keyName string, address common.Address, _ *pricereader.TokenMetadataCache, _ uint8, _ ...pricereader.WriterOption) (chainaccess.FeeQuoterWriter, error) {
	s.gotWriterKey = keyName
	s.gotWriterAddress = address
	if s.writer == nil && s.writerErr == nil {
		return markerFeeQuoterWriter{}, nil
	}
	return s.writer, s.writerErr
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
		nil,
		nil,
		nil,
		0,
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			runtimeCalls++
			return &stubChainRuntime{}, nil
		},
	)

	accessor, err := factory.GetAccessor(context.Background(), protocol.ChainSelector(5009297550715157269))
	require.Nil(t, accessor)
	require.ErrorContains(t, err, "no source, destination or pricer services are configured")
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
				nil,
				nil,
				nil,
				0,
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
		nil,
		nil,
		nil,
		0,
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
		nil,
		nil,
		nil,
		0,
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
		nil,
		nil,
		nil,
		0,
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

// fakeDAOracle is a rollups.L1Oracle with a fixed price.
type fakeDAOracle struct{ price *assets.Wei }

func (fakeDAOracle) Start(context.Context) error { return nil }
func (fakeDAOracle) Close() error                { return nil }
func (fakeDAOracle) Ready() error                { return nil }
func (fakeDAOracle) Name() string                { return "fake-da-oracle" }
func (fakeDAOracle) HealthReport() map[string]error {
	return map[string]error{"fake-da-oracle": nil}
}
func (f fakeDAOracle) GasPrice(context.Context) (*assets.Wei, error) { return f.price, nil }

const pricerTestSelector = protocol.ChainSelector(5009297550715157269)

func newPricerFactory(t *testing.T, feeQuoterAddress string, runtime *stubChainRuntime, runtimeCalls *int) chainaccess.AccessorFactory {
	t.Helper()
	return newPricerFactoryWithDecimals(t, feeQuoterAddress, nil, runtime, runtimeCalls)
}

func newPricerFactoryWithDecimals(
	t *testing.T,
	feeQuoterAddress string,
	nativeDecimals map[protocol.ChainSelector]uint8,
	runtime *stubChainRuntime,
	runtimeCalls *int,
) chainaccess.AccessorFactory {
	t.Helper()
	return newFactory(
		logger.Test(t),
		nil,
		nil,
		nil,
		map[protocol.ChainSelector]string{pricerTestSelector: feeQuoterAddress},
		nativeDecimals,
		nil,
		0,
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			*runtimeCalls++
			return runtime, nil
		},
	)
}

func TestFactoryResolvesFeeQuoterAndGasPriceReaderFromValidConfig(t *testing.T) {
	env := pricereadertest.New(t)
	daPrice := big.NewInt(3e9)
	runtime := &stubChainRuntime{
		Client:    env.Client,
		daOracle:  fakeDAOracle{price: assets.NewWei(daPrice)},
		addresses: []common.Address{env.Owner},
	}
	runtimeCalls := 0
	factory := newPricerFactory(t, env.FeeQuoter.Hex(), runtime, &runtimeCalls)

	ctx := context.Background()
	got, err := factory.GetAccessor(ctx, pricerTestSelector)
	require.NoError(t, err)
	require.Equal(t, 1, runtimeCalls)

	feeQuoter, err := got.FeeQuoterReader()
	require.NoError(t, err)
	state, err := feeQuoter.GetFQState(ctx)
	require.NoError(t, err)
	require.Len(t, state.FeeTokens, 2)
	require.Len(t, state.FeeTokenPrices, 2)
	require.Len(t, state.DestinationChains, len(pricereadertest.DestSelectors))
	// The service address is not known before the keystore is set.
	require.False(t, state.ServiceIsAuthorized)

	require.NoError(t, got.(*accessor).SetKeystore(ctx, nil))
	require.Equal(t, contracttransmitter.DefaultKeyName, runtime.gotAddrKey)
	require.NoError(t, got.(*accessor).Degraded())
	state, err = feeQuoter.GetFQState(ctx)
	require.NoError(t, err)
	require.True(t, state.ServiceIsAuthorized)

	gasPriceReader, err := got.GasPriceReader()
	require.NoError(t, err)
	price, err := gasPriceReader.GetGasPrice(ctx)
	require.NoError(t, err)
	suggested, err := env.Client.SuggestGasPrice(ctx)
	require.NoError(t, err)
	require.Equal(t, new(big.Int).Mul(suggested, big.NewInt(1e18)), price.ExecutionFee.ToInt())
	require.Equal(t, new(big.Int).Mul(daPrice, big.NewInt(1e18)), price.DAFee.ToInt())

	writer, err := got.FeeQuoterWriter()
	require.NoError(t, err)
	_, err = writer.UpdatePrices(ctx, nil, nil)
	require.NoError(t, err)

	// A pricer-only accessor has no source or destination services.
	_, err = got.SourceReader()
	require.Error(t, err)
	_, err = got.DestinationReader()
	require.Error(t, err)
}

func TestFactoryRejectsInvalidFeeQuoterAddressBeforeStartingRuntime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
	}{
		{name: "not an address", address: "not-an-address"},
		{name: "too short", address: "0x1234"},
		{name: "zero address", address: zeroTestAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runtimeCalls := 0
			factory := newPricerFactory(t, tt.address, &stubChainRuntime{}, &runtimeCalls)

			got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
			require.Nil(t, got)
			require.ErrorContains(t, err, "invalid fee quoter address")
			require.Zero(t, runtimeCalls)
		})
	}
}

func TestFactoryDoesNotStartTheDAGasPriceOracleBeforeTheFirstGasPriceRead(t *testing.T) {
	env := pricereadertest.New(t)
	runtime := &stubChainRuntime{Client: env.Client, daOracle: fakeDAOracle{price: assets.NewWei(big.NewInt(3e9))}}
	runtimeCalls := 0
	factory := newPricerFactory(t, env.FeeQuoter.Hex(), runtime, &runtimeCalls)

	got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
	require.NoError(t, err)
	require.Zero(t, runtime.daOracleCalls, "GetAccessor must not call the chain for the oracle")

	reader, err := got.GasPriceReader()
	require.NoError(t, err)
	for range 2 {
		_, err = reader.GetGasPrice(context.Background())
		require.NoError(t, err)
	}
	require.Equal(t, 1, runtime.daOracleCalls)
}

func TestGasPriceReaderReturnsTheDAGasPriceOracleError(t *testing.T) {
	env := pricereadertest.New(t)
	oracleErr := errors.New("oracle failed")
	runtime := &stubChainRuntime{Client: env.Client, daOracleErr: oracleErr}
	runtimeCalls := 0
	factory := newPricerFactory(t, env.FeeQuoter.Hex(), runtime, &runtimeCalls)

	got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
	require.NoError(t, err)
	reader, err := got.GasPriceReader()
	require.NoError(t, err)

	_, err = reader.GetGasPrice(context.Background())
	require.ErrorIs(t, err, oracleErr)
	require.Zero(t, runtime.closeCalls, "a later call can retry, so the runtime stays open")
}

func TestAccessorWithoutFeeQuoterAddressHasNoPricerServices(t *testing.T) {
	t.Parallel()

	got := newAccessor(logger.Test(t), pricerTestSelector, &stubChainRuntime{}, common.Address{}, "evm-key", nil, nil, nil, nil, nil, nil)

	_, err := got.FeeQuoterReader()
	require.ErrorContains(t, err, "fee quoter reader not available")
	_, err = got.FeeQuoterWriter()
	require.ErrorContains(t, err, "fee quoter writer not available")
	_, err = got.GasPriceReader()
	require.ErrorContains(t, err, "gas price reader not available")
}

func TestSetKeystoreKeepsServiceUnauthorizedWhenTransmitterKeyIsMissing(t *testing.T) {
	env := pricereadertest.New(t)
	runtime := &stubChainRuntime{Client: env.Client, addressesErr: errors.New("key not found")}
	runtimeCalls := 0
	factory := newPricerFactory(t, env.FeeQuoter.Hex(), runtime, &runtimeCalls)

	got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
	require.NoError(t, err)
	require.NoError(t, got.(*accessor).SetKeystore(context.Background(), nil))

	feeQuoter, err := got.FeeQuoterReader()
	require.NoError(t, err)
	state, err := feeQuoter.GetFQState(context.Background())
	require.NoError(t, err)
	require.False(t, state.ServiceIsAuthorized)

	degraded := got.(*accessor).Degraded()
	require.ErrorContains(t, degraded, "no transmitter addresses")
	require.ErrorContains(t, degraded, "key not found")

	// A later SetKeystore that finds the key clears the degraded state.
	runtime.addressesErr = nil
	runtime.addresses = []common.Address{env.Owner}
	require.NoError(t, got.(*accessor).SetKeystore(context.Background(), nil))
	require.NoError(t, got.(*accessor).Degraded())
}

func TestFactoryUsesConfiguredNativeTokenDecimals(t *testing.T) {
	env := pricereadertest.New(t)
	daPrice := big.NewInt(3e9)
	tests := []struct {
		name     string
		decimals map[protocol.ChainSelector]uint8
		scale    *big.Int
	}{
		{name: "default is 18", decimals: nil, scale: big.NewInt(1e18)},
		{name: "other chain is ignored", decimals: map[protocol.ChainSelector]uint8{1: 8}, scale: big.NewInt(1e18)},
		{name: "override for the chain", decimals: map[protocol.ChainSelector]uint8{pricerTestSelector: 8}, scale: new(big.Int).Exp(big.NewInt(10), big.NewInt(28), nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &stubChainRuntime{Client: env.Client, daOracle: fakeDAOracle{price: assets.NewWei(daPrice)}}
			runtimeCalls := 0
			factory := newPricerFactoryWithDecimals(t, env.FeeQuoter.Hex(), tt.decimals, runtime, &runtimeCalls)

			got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
			require.NoError(t, err)
			reader, err := got.GasPriceReader()
			require.NoError(t, err)
			price, err := reader.GetGasPrice(context.Background())
			require.NoError(t, err)
			suggested, err := env.Client.SuggestGasPrice(context.Background())
			require.NoError(t, err)
			require.Equal(t, new(big.Int).Mul(suggested, tt.scale), price.ExecutionFee.ToInt())
			require.Equal(t, new(big.Int).Mul(daPrice, tt.scale), price.DAFee.ToInt())
		})
	}
}

func TestFactoryRejectsTooManyNativeTokenDecimalsBeforeStartingRuntime(t *testing.T) {
	t.Parallel()

	runtimeCalls := 0
	decimals := map[protocol.ChainSelector]uint8{pricerTestSelector: 37}
	factory := newPricerFactoryWithDecimals(t, validTestFeeQuoterAddress, decimals, &stubChainRuntime{}, &runtimeCalls)

	got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
	require.Nil(t, got)
	require.ErrorContains(t, err, "invalid native token decimals 37")
	require.Zero(t, runtimeCalls)
}

func TestFactoryIgnoresNativeTokenDecimalsWithoutFeeQuoterAddress(t *testing.T) {
	t.Parallel()

	runtimeCalls := 0
	decimals := map[protocol.ChainSelector]uint8{pricerTestSelector: 37}
	factory := newPricerFactoryWithDecimals(t, "", decimals, &stubChainRuntime{}, &runtimeCalls)

	got, err := factory.GetAccessor(context.Background(), pricerTestSelector)
	require.Nil(t, got)
	// The setting is not checked: the error is about the missing services, not the decimals.
	require.ErrorContains(t, err, "no source, destination or pricer services are configured")
	require.NotContains(t, err.Error(), "native token decimals")
}

type markerFeeQuoterWriter struct{}

func (markerFeeQuoterWriter) UpdatePrices(context.Context, []protocol.FeeTokenPriceUpdate, []protocol.GasTokenPriceUpdate) (string, error) {
	return "", nil
}

func (markerFeeQuoterWriter) EstimateUpdateCost(context.Context, []protocol.FeeTokenPriceUpdate, []protocol.GasTokenPriceUpdate) (*big.Int, error) {
	return new(big.Int), nil
}

func (markerFeeQuoterWriter) GetTransactionStatus(context.Context, string) (commontypes.TransactionStatus, error) {
	return commontypes.Unknown, nil
}

func TestFactoryAccessorProvidesAUsableCCIPAPIParser(t *testing.T) {
	t.Parallel()

	env := pricereadertest.New(t)
	runtime := &stubChainRuntime{
		Client:    env.Client,
		daOracle:  fakeDAOracle{price: assets.NewWei(big.NewInt(3e9))},
		addresses: []common.Address{env.Owner},
	}
	runtimeCalls := 0
	factory := newPricerFactory(t, env.FeeQuoter.Hex(), runtime, &runtimeCalls)

	got, err := factory.GetAccessor(t.Context(), pricerTestSelector)
	require.NoError(t, err)

	parser, err := got.CCIPAPIParser()
	require.NoError(t, err)
	require.NotNil(t, parser)

	decoded, err := parser.DecodeAddress(env.USDC.Hex())
	require.NoError(t, err)
	require.Equal(t, env.USDC.Bytes(), []byte(decoded))

	_, err = parser.DecodeAddress("0xzz")
	require.Error(t, err)
}

func TestSetKeystoreReplacesTheFeeQuoterWriterWithTheRuntimeOne(t *testing.T) {
	t.Parallel()
	runtime := &stubChainRuntime{writer: markerFeeQuoterWriter{}}
	fq := common.HexToAddress(validTestFeeQuoterAddress)
	logOnly, err := pricereader.NewEVMFeeQuoterWriter(logger.Test(t), nil, fq, defaultNativeDecimals)
	require.NoError(t, err)
	acc := newAccessor(logger.Test(t), pricerTestSelector, runtime, common.Address{}, "evm-key", nil, nil, nil, nil, logOnly, nil, withFeeQuoterAddress(fq))

	require.NoError(t, acc.(*accessor).SetKeystore(t.Context(), nil))

	got, err := acc.FeeQuoterWriter()
	require.NoError(t, err)
	require.IsType(t, markerFeeQuoterWriter{}, got)
	require.Equal(t, "evm-key", runtime.gotWriterKey)
	require.Equal(t, fq, runtime.gotWriterAddress)
	require.NoError(t, acc.(*accessor).Degraded())
}

// txmWriterRuntime builds the real TXM-backed writer on a fake TXM, so a test sees the gas limit it sends.
type txmWriterRuntime struct {
	*stubChainRuntime
	txm *recordingTxm
}

func (r *txmWriterRuntime) NewFeeQuoterWriter(_ context.Context, _ keystore.Keystore, _ string, address common.Address, tokens *pricereader.TokenMetadataCache, nativeDecimals uint8, opts ...pricereader.WriterOption) (chainaccess.FeeQuoterWriter, error) {
	from := common.HexToAddress("0x01")
	opts = append([]pricereader.WriterOption{
		pricereader.WithTxm(r.txm, firstAddressKeys{}, []common.Address{from}),
		pricereader.WithTokenCache(tokens),
	}, opts...)
	return pricereader.NewEVMFeeQuoterWriter(logger.Nop(), nil, address, nativeDecimals, opts...)
}

type recordingTxm struct {
	txmgr.TxManager
	requests []txmgr.TxRequest
}

func (f *recordingTxm) CreateTransaction(_ context.Context, r txmgr.TxRequest) (txmgr.Tx, error) {
	f.requests = append(f.requests, r)
	return txmgr.Tx{}, nil
}

type firstAddressKeys struct{}

func (firstAddressKeys) GetNextAddress(_ context.Context, addrs ...common.Address) (common.Address, error) {
	return addrs[0], nil
}

func TestFactoryBuildsFeeQuoterWritersWithAndWithoutGasOverrides(t *testing.T) {
	t.Parallel()

	const defaultBase, defaultPerUpdate = 100_000, 50_000
	override := func(base, perUpdate uint64) map[protocol.ChainSelector]chainaccess.FeeQuoterGasOverride {
		return map[protocol.ChainSelector]chainaccess.FeeQuoterGasOverride{pricerTestSelector: {BaseGas: base, GasPerUpdate: perUpdate}}
	}
	tests := []struct {
		name      string
		overrides map[protocol.ChainSelector]chainaccess.FeeQuoterGasOverride
		wantLimit uint64
	}{
		{name: "nil overrides use the defaults", wantLimit: defaultBase + defaultPerUpdate},
		{name: "empty overrides use the defaults", overrides: map[protocol.ChainSelector]chainaccess.FeeQuoterGasOverride{}, wantLimit: defaultBase + defaultPerUpdate},
		{name: "override of another chain uses the defaults", overrides: map[protocol.ChainSelector]chainaccess.FeeQuoterGasOverride{1: {BaseGas: 1, GasPerUpdate: 1}}, wantLimit: defaultBase + defaultPerUpdate},
		{name: "full override", overrides: override(200_000, 70_000), wantLimit: 200_000 + 70_000},
		{name: "base only override", overrides: override(300_000, 0), wantLimit: 300_000 + defaultPerUpdate},
		{name: "per update only override", overrides: override(0, 70_000), wantLimit: defaultBase + 70_000},
		{name: "zero override uses the defaults", overrides: override(0, 0), wantLimit: defaultBase + defaultPerUpdate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := pricereadertest.New(t)
			txm := &recordingTxm{}
			runtime := &txmWriterRuntime{
				stubChainRuntime: &stubChainRuntime{
					Client:    env.Client,
					daOracle:  fakeDAOracle{price: assets.NewWei(big.NewInt(3e9))},
					addresses: []common.Address{env.Owner},
				},
				txm: txm,
			}
			factory := newFactory(
				logger.Test(t), nil, nil, nil,
				map[protocol.ChainSelector]string{pricerTestSelector: env.FeeQuoter.Hex()},
				nil, tt.overrides, 0, 0,
				func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
					return runtime, nil
				},
			)
			got, err := factory.GetAccessor(t.Context(), pricerTestSelector)
			require.NoError(t, err)
			require.NoError(t, got.(*accessor).SetKeystore(t.Context(), nil))
			require.NoError(t, got.(*accessor).Degraded())

			writer, err := got.FeeQuoterWriter()
			require.NoError(t, err)
			_, err = writer.UpdatePrices(t.Context(), nil, []protocol.GasTokenPriceUpdate{{
				ChainSelector: 1,
				USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))},
			}})
			require.NoError(t, err)

			require.Len(t, txm.requests, 1)
			require.EqualValues(t, tt.wantLimit, txm.requests[0].FeeLimit)
		})
	}
}

func TestFactoryAppliesGasOverridesPerChain(t *testing.T) {
	t.Parallel()

	const (
		ethereum = protocol.ChainSelector(5009297550715157269)
		arbitrum = protocol.ChainSelector(4949039107694359620)
		base     = protocol.ChainSelector(15971525489660198786)
		unlisted = protocol.ChainSelector(3734403246176062136) // has a fee quoter but no override
	)
	overrides := map[protocol.ChainSelector]chainaccess.FeeQuoterGasOverride{
		ethereum: {BaseGas: 200_000, GasPerUpdate: 70_000},
		arbitrum: {GasPerUpdate: 120_000},
		base:     {BaseGas: 300_000},
	}
	wantLimit := map[protocol.ChainSelector]uint64{
		ethereum: 200_000 + 70_000,
		arbitrum: 100_000 + 120_000,
		base:     300_000 + 50_000,
		unlisted: 100_000 + 50_000,
	}

	env := pricereadertest.New(t)
	txms := map[protocol.ChainSelector]*recordingTxm{}
	feeQuoters := map[protocol.ChainSelector]string{}
	for sel := range wantLimit {
		txms[sel] = &recordingTxm{}
		feeQuoters[sel] = env.FeeQuoter.Hex()
	}
	factory := newFactory(
		logger.Test(t), nil, nil, nil, feeQuoters, nil, overrides, 0, 0,
		func(_ context.Context, sel protocol.ChainSelector, _ logger.Logger) (chainRuntime, error) {
			return &txmWriterRuntime{
				stubChainRuntime: &stubChainRuntime{
					Client:    env.Client,
					daOracle:  fakeDAOracle{price: assets.NewWei(big.NewInt(3e9))},
					addresses: []common.Address{env.Owner},
				},
				txm: txms[sel],
			}, nil
		},
	)

	gasUpdate := []protocol.GasTokenPriceUpdate{{
		ChainSelector: 1,
		USDGasPrice:   protocol.USDGasPrice{ExecutionFee: (*protocol.USDPerGasUnit)(big.NewInt(3))},
	}}
	for sel := range wantLimit {
		got, err := factory.GetAccessor(t.Context(), sel)
		require.NoError(t, err, "chain %d", sel)
		require.NoError(t, got.(*accessor).SetKeystore(t.Context(), nil), "chain %d", sel)
		writer, err := got.FeeQuoterWriter()
		require.NoError(t, err, "chain %d", sel)
		_, err = writer.UpdatePrices(t.Context(), nil, gasUpdate)
		require.NoError(t, err, "chain %d", sel)
	}

	for sel, want := range wantLimit {
		require.Len(t, txms[sel].requests, 1, "chain %d", sel)
		require.EqualValues(t, want, txms[sel].requests[0].FeeLimit, "chain %d", sel)
	}
}

func TestSetKeystoreKeepsTheLogOnlyFeeQuoterWriterAndReportsDegradedOnFailure(t *testing.T) {
	t.Parallel()
	runtime := &stubChainRuntime{writerErr: errors.New("no key")}
	logOnly, err := pricereader.NewEVMFeeQuoterWriter(logger.Test(t), nil, common.Address{}, defaultNativeDecimals)
	require.NoError(t, err)
	acc := newAccessor(logger.Test(t), pricerTestSelector, runtime, common.Address{}, "evm-key", nil, nil, nil, nil, logOnly, nil)

	require.NoError(t, acc.(*accessor).SetKeystore(t.Context(), nil))

	got, err := acc.FeeQuoterWriter()
	require.NoError(t, err)
	require.Same(t, logOnly, got)
	require.ErrorContains(t, acc.(*accessor).Degraded(), "only logs")
}

func TestSetKeystoreWithoutFeeQuoterWriterDoesNotStartOne(t *testing.T) {
	t.Parallel()
	runtime := &stubChainRuntime{writer: markerFeeQuoterWriter{}}
	acc := newAccessor(logger.Test(t), pricerTestSelector, runtime, common.Address{}, "evm-key", nil, nil, nil, nil, nil, nil)

	require.NoError(t, acc.(*accessor).SetKeystore(t.Context(), nil))
	_, err := acc.FeeQuoterWriter()
	require.Error(t, err)
	require.Empty(t, runtime.gotWriterKey)
}

func TestAccessorDegradedIncludesSkippedChainDefaults(t *testing.T) {
	t.Parallel()

	acc := &accessor{chainDefaultsErr: chainDefaultsError([]string{"ccip/Broken.toml: unknown key"})}
	require.ErrorContains(t, acc.Degraded(), "skipped EVM chain defaults")
	require.ErrorContains(t, acc.Degraded(), "ccip/Broken.toml: unknown key")
	require.NoError(t, chainDefaultsError(nil))
}
