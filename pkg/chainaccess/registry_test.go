package chainaccess_test

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// testEVMFactory and testAccessor are minimal implementations used to exercise
// the NewRegistry → GetAccessor path without any real chain connectivity.

var (
	constructorShouldFail atomic.Bool
	accessorShouldFail    atomic.Bool
	lastClosingFactory    atomic.Pointer[testClosingFactory]
	lastFailedFactory     atomic.Pointer[testClosingFactory]
)

type testEVMFactory struct{}

func (f *testEVMFactory) GetAccessor(_ context.Context, _ protocol.ChainSelector) (chainaccess.Accessor, error) {
	if accessorShouldFail.Load() {
		return nil, errors.New("test accessor error")
	}
	return &testAccessor{}, nil
}

type testClosingFactory struct {
	closeCalls atomic.Int32
}

func (*testClosingFactory) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	return &testAccessor{}, nil
}

func (f *testClosingFactory) Close() error {
	f.closeCalls.Add(1)
	return nil
}

type testAccessor struct{}

func (a *testAccessor) SourceReader() (chainaccess.SourceReader, error) {
	return nil, errors.New("source reader not available")
}

func (a *testAccessor) DestinationReader() (chainaccess.DestinationReader, error) {
	return nil, errors.New("destination reader not available")
}

func (a *testAccessor) ContractTransmitter() (chainaccess.ContractTransmitter, error) {
	return nil, errors.New("contract transmitter not available")
}

func (a *testAccessor) Close() error {
	return nil
}

func init() {
	// Register a test constructor for the "evm" family so that NewRegistry
	// can build a Registry without real RPC connections.
	chainaccess.Register("evm", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		return &testEVMFactory{}, nil
	})

	// Register a second family whose constructor can be toggled to fail.
	// "test-constructor-error" is not a real chain-selectors family, so it
	// will never be selected by GetAccessor; it only exercises the
	// NewRegistry constructor-error code path.
	chainaccess.Register("test-constructor-error", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		if constructorShouldFail.Load() {
			factory := &testClosingFactory{}
			lastFailedFactory.Store(factory)
			return factory, errors.New("test constructor error")
		}
		return &testEVMFactory{}, nil
	})

	chainaccess.Register("test-close", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
		factory := &testClosingFactory{}
		lastClosingFactory.Store(factory)
		return factory, nil
	})
}

// ethereumMainnetSelector is the chain selector for Ethereum mainnet, which the
// chain-selectors library maps to the "evm" family.
const ethereumMainnetSelector = protocol.ChainSelector(5009297550715157269)

func TestNewRegistry_GetAccessor(t *testing.T) {
	cfg := `
[on_ramp_addresses]
"5009297550715157269" = "0xOnRamp"

[rmn_remote_addresses]
"5009297550715157269" = "0xRMN"
`
	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, cfg)
	require.NoError(t, err)
	require.NotNil(t, reg)

	accessor, err := reg.GetAccessor(context.Background(), ethereumMainnetSelector)
	require.NoError(t, err)
	assert.NotNil(t, accessor)
}

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	assert.Panics(t, func() {
		chainaccess.Register("evm", func(_ logger.Logger, _ chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
			return nil, nil
		})
	})
}

func TestNewRegistry_InvalidTOML(t *testing.T) {
	lggr := logger.Test(t)
	_, err := chainaccess.NewRegistry(lggr, "}{not valid toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal generic config")
}

func TestNewRegistry_CloseFactoriesIsIdempotent(t *testing.T) {
	reg, err := chainaccess.NewRegistry(logger.Test(t), "")
	require.NoError(t, err)

	closer, ok := reg.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
	require.NoError(t, closer.Close())
	require.Equal(t, int32(1), lastClosingFactory.Load().closeCalls.Load())
}

func TestNewRegistry_ConstructorError(t *testing.T) {
	constructorShouldFail.Store(true)
	defer constructorShouldFail.Store(false)

	lggr := logger.Test(t)
	_, err := chainaccess.NewRegistry(lggr, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to construct accessor factory")
	require.Equal(t, int32(1), lastFailedFactory.Load().closeCalls.Load())
}

func TestGetAccessor_UnknownSelector(t *testing.T) {
	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	// Selector 0 is not present in the chain-selectors library.
	_, err = reg.GetAccessor(context.Background(), protocol.ChainSelector(0))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get selector family")
}

func TestGetAccessor_NoFactoryForFamily(t *testing.T) {
	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	// Solana mainnet maps to the "solana" family, which has no registered factory.
	solanaSelector := protocol.ChainSelector(chainsel.SOLANA_MAINNET.Selector)
	_, err = reg.GetAccessor(context.Background(), solanaSelector)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no factory registered for chain family")
}

func TestGetAccessor_FactoryError(t *testing.T) {
	accessorShouldFail.Store(true)
	defer accessorShouldFail.Store(false)

	lggr := logger.Test(t)
	reg, err := chainaccess.NewRegistry(lggr, "")
	require.NoError(t, err)

	_, err = reg.GetAccessor(context.Background(), ethereumMainnetSelector)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test accessor error")
}
