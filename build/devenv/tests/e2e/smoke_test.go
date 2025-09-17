package e2e

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

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
	routerAddr := ccv.MustGetContractAddressForSelector(in, srcChain.Selector, router.ContractType)

	argsV3, err := ccv.NewV3ExtraArgs(1, common.Address{}, []byte{}, []byte{}, []types.CCV{}, []types.CCV{}, 0)
	require.NoError(t, err)

	ccipSendArgs := router.CCIPSendArgs{
		DestChainSelector: dstChain.Selector,
		EVM2AnyMessage: router.EVM2AnyMessage{
			Receiver:     common.LeftPadBytes(srcChain.DeployerKey.From.Bytes(), 32),
			Data:         []byte{},
			TokenAmounts: []router.EVMTokenAmount{},
			ExtraArgs:    argsV3,
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
