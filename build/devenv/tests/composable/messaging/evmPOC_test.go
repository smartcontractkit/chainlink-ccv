package messaging

import (
	"testing"

	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
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

	harness, err := tcapi.NewTestHarness(
		ctx,
		e2e.GetSmokeTestConfig(),
		cfg,
		chain_selectors.FamilyEVM,
	)
	require.NoError(t, err)

	chains, err := harness.Lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")

	src, dest := chains[0].CCIP17, chains[1].CCIP17

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

	harness, err := tcapi.NewTestHarness(
		ctx,
		e2e.GetSmokeTestConfig(),
		cfg,
		chain_selectors.FamilyEVM,
	)
	require.NoError(t, err)

	chains, err := harness.Lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")

	src, dest := chains[0].CCIP17, chains[1].CCIP17

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
