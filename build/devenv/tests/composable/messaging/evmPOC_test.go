package messaging

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e"
)

var (
	_ = cciptestinterfaces.ChainAsSource(&evm.CCIP17EVM{})
	_ = cciptestinterfaces.ChainAsDestination(&evm.CCIP17EVM{})
)

const (
	composableTestPath = "../../../env-out.toml"
)

func TestEVM2EVMV3(t *testing.T) {
	cfg, err := ccv.LoadOutput[ccv.Cfg](composableTestPath)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())

	_, env, err := ccv.NewCLDFOperationsEnvironment(cfg.Blockchains, cfg.CLDF.DataStore)
	require.NoError(t, err)

	sels, err := e2e.FirstTwoEVMSelectors(cfg)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(sels), 2, "expected at least 2 chains for this test in the environment")

	src, err := ccv.NewCCIP17ForChainSelector(ctx, *zerolog.Ctx(ctx), env, sels[0])
	require.NoError(t, err)
	dest, err := ccv.NewCCIP17ForChainSelector(ctx, *zerolog.Ctx(ctx), env, sels[1])
	require.NoError(t, err)

	receiver, err := dest.GetEOAReceiverAddress()
	require.NoError(t, err)

	srcChain, srcOk := src.(cciptestinterfaces.ChainAsSource)
	destChain, destOk := dest.(cciptestinterfaces.ChainAsDestination)
	require.True(t, srcOk, "srcChain does not match the chainAsSource interface!")
	require.True(t, destOk, "destChain does not match the chainAsDestination interface!")

	require.NoError(t,
		MessageV3TestScenario(ctx,
			srcChain,
			destChain,
			cciptestinterfaces.MessageFields{
				Receiver: receiver,
				Data:     []byte{},
			},
			cciptestinterfaces.MessageOptions{
				ExecutionGasLimit:   200_000,
				OutOfOrderExecution: false,
			},
			nil,
			nil,
			nil,
			nil,
		),
	)
}

func TestEVM2EVMV2(t *testing.T) {
	cfg, err := ccv.LoadOutput[ccv.Cfg](composableTestPath)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())

	_, env, err := ccv.NewCLDFOperationsEnvironment(cfg.Blockchains, cfg.CLDF.DataStore)
	require.NoError(t, err)

	sels, err := e2e.FirstTwoEVMSelectors(cfg)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(sels), 2, "expected at least 2 chains for this test in the environment")

	src, err := ccv.NewCCIP17ForChainSelector(ctx, *zerolog.Ctx(ctx), env, sels[0])
	require.NoError(t, err)
	dest, err := ccv.NewCCIP17ForChainSelector(ctx, *zerolog.Ctx(ctx), env, sels[1])
	require.NoError(t, err)

	receiver, err := dest.GetEOAReceiverAddress()
	require.NoError(t, err)

	srcChain, srcOk := src.(cciptestinterfaces.ChainAsSource)
	destChain, destOk := dest.(cciptestinterfaces.ChainAsDestination)
	require.True(t, srcOk, "srcChain does not match the chainAsSource interface!")
	require.True(t, destOk, "destChain does not match the chainAsDestination interface!")

	require.NoError(t,
		EVMMessageV2TestScenario(ctx,
			srcChain,
			destChain,
			cciptestinterfaces.MessageFields{
				Receiver: receiver,
				Data:     []byte{},
			},
			cciptestinterfaces.EVMExtraArgsV2Data{
				GasLimit:                 200_000,
				AllowOutOfOrderExecution: false,
			},
			nil,
		),
	)
}
