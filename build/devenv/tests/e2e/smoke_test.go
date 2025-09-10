package e2e

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains)
	require.NoError(t, err)
	chains := e.BlockChains.EVMChains()
	require.NotNil(t, chains)
	srcChain := chains[selectors[0]]
	dstChain := chains[selectors[1]]
	b := ccv.NewDefaultCLDFBundle(e)
	e.OperationsBundle = b
	routerAddr, err := ccv.GetRouterAddrForSelector(in, srcChain.Selector)
	require.NoError(t, err)

	argsv2, err := ccv.NewGenericCCIP17ExtraArgsV2(ccv.GenericExtraArgsV2{
		GasLimit:                 big.NewInt(1_000_000),
		AllowOutOfOrderExecution: true,
	})
	require.NoError(t, err)

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dstChain.Selector,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(srcChain.DeployerKey.From.Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    argsv2,
		},
	}

	feeReport, err := operations.ExecuteOperation(b, router.GetFee, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: srcChain.Selector,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	require.NoError(t, err)

	// Send CCIP message with value
	ccipSendArgs.Value = feeReport.Output
	sendReport, err := operations.ExecuteOperation(b, router.CCIPSend, srcChain, contract.FunctionInput[router.CCIPSendArgs]{
		ChainSelector: srcChain.Selector,
		Address:       routerAddr,
		Args:          ccipSendArgs,
	})
	require.NoError(t, err)
	require.True(t, sendReport.Output.Executed)

	ccv.Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dstChain.Selector).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent")
}
