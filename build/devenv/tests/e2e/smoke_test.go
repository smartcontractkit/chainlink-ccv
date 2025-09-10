package e2e

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/stretchr/testify/require"

	routerBind "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/router"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	srcEthClient, srcAuth, _, err := ccv.ETHClient(in.Blockchains[0].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
	require.NoError(t, err)
	//clNodes, err := clclient.New(in.NodeSets[0].Out.CLNodes)
	//require.NoError(t, err)
	//_ = clNodes
	contracts, err := ccv.GetCLDFAddressesPerSelector(in)
	contractsSrc := contracts[0]
	//contractsDst := contracts[1]
	var (
		routerAddr string
	)
	for _, contract := range contractsSrc {
		if contract.Type == "Router" {
			routerAddr = contract.Address
		}
	}
	details, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[0].ChainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	dstSelector := details.ChainSelector
	routerContract, err := routerBind.NewRouter(common.HexToAddress(routerAddr), srcEthClient)
	routerContract.CcipSend(srcAuth, dstSelector, routerBind.ClientEVM2AnyMessage{
		Receiver:     nil,
		Data:         nil,
		TokenAmounts: nil,
		// Default Anvil address
		FeeToken:  common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		ExtraArgs: nil,
	})
	// connect your contracts with CLD here and assert CCV lanes are working
}
