package messaging

import (
	"testing"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	routerwrapper "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/router"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/stretchr/testify/require"
)

var (
	_ = chainAsSource[routerwrapper.ClientEVM2AnyMessage](&evm.CCIP17EVM{})
	_ = chainAsDestination(&evm.CCIP17EVM{})
)

func TestEVM2EVMPOC(t *testing.T) {
	cfg, err := ccv.LoadOutput[ccv.Cfg]("../../../env-out.toml")
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
	TestBasicMessage(ctx, t, src.(chainAsSource[routerwrapper.ClientEVM2AnyMessage]), dest.(chainAsDestination), cciptestinterfaces.MessageFields{
		Receiver: receiver,
		Data:     []byte{},
	}, cciptestinterfaces.MessageOptions{
		Version:             2,
		ExecutionGasLimit:   200_000,
		OutOfOrderExecution: false,
	})
}
