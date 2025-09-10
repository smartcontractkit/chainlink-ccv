package e2e

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/stretchr/testify/require"

	routerBind "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/router"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	linkBind "github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/latest/link_token"
)

type ContractsBind struct {
	Link   *linkBind.LinkToken
	Router *routerBind.Router
}

type GenericExtraArgsV2 struct {
	GasLimit                 *big.Int
	AllowOutOfOrderExecution bool
}

func prepareExtraArgsV2(args GenericExtraArgsV2) ([]byte, error) {
	const clientABI = `
		[
			{
				"name": "encodeGenericExtraArgsV2",
				"type": "function",
				"inputs": [
					{
						"components": [
							{
								"name": "gasLimit",
								"type": "uint256"
							},
							{
								"name": "allowOutOfOrderExecution",
								"type": "bool"
							}
						],
						"name": "args",
						"type": "tuple"
					}
				],
				"outputs": [],
				"stateMutability": "pure"
			}
		]
	`

	parsedABI, err := abi.JSON(bytes.NewReader([]byte(clientABI)))
	if err != nil {
		return nil, err
	}

	encoded, err := parsedABI.Methods["encodeGenericExtraArgsV2"].Inputs.Pack(args)
	if err != nil {
		return nil, err
	}

	tag := []byte{0x18, 0x1d, 0xcf, 0x10} // GENERIC_EXTRA_ARGS_V2_TAG
	tag = append(tag, encoded...)
	return tag, nil
}

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains)
	require.NoError(t, err)
	chains := e.BlockChains.EVMChains()
	require.NotNil(t, chains)
	srcChain := chains[selectors[0]]
	dstChain := chains[selectors[1]]
	b := ccv.NewCLDFBundle(e)
	e.OperationsBundle = b
	routerAddr, err := ccv.GetRouterForSelector(in, srcChain.Selector)
	require.NoError(t, err)

	argsv2, err := prepareExtraArgsV2(GenericExtraArgsV2{
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

	ccv.Plog.Info().Bool("Executed", sendReport.Output.Executed).
		Uint64("SrcChainSelector", sendReport.Output.ChainSelector).
		Uint64("DestChainSelector", dstChain.Selector).
		Str("SrcRouter", sendReport.Output.Tx.To).
		Msg("CCIP message sent!")
}
