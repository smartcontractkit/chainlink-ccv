package e2e

import (
	"context"
	"math/big"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/stretchr/testify/require"

	routerBind "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/router"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	linkBind "github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/latest/link_token"
)

type ContractsBind struct {
	Link   *linkBind.LinkToken
	Router *routerBind.Router
}

func loadContracts(ethClient *ethclient.Client, ethAuth *bind.TransactOpts, contractRefs []datastore.AddressRef) (*ContractsBind, error) {
	var (
		routerAddr string
		linkAddr   string
	)
	for _, contract := range contractRefs {
		if contract.Type == "Router" {
			routerAddr = contract.Address
		}
		if contract.Type == "LINK" {
			linkAddr = contract.Address
		}
	}
	routerContract, err := routerBind.NewRouter(common.HexToAddress(routerAddr), ethClient)
	if err != nil {
		return nil, err
	}
	linkContract, err := linkBind.NewLinkToken(common.HexToAddress(linkAddr), ethClient)
	if err != nil {
		return nil, err
	}
	tx, err := linkContract.GrantMintRole(ethAuth, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
	if err != nil {
		return nil, err
	}
	_, err = bind.WaitMined(context.Background(), ethClient, tx)
	if err != nil {
		return nil, err
	}
	tx, err = linkContract.Mint(ethAuth, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), big.NewInt(100))
	if err != nil {
		return nil, err
	}
	_, err = bind.WaitMined(context.Background(), ethClient, tx)
	if err != nil {
		return nil, err
	}
	balance, err := linkContract.BalanceOf(&bind.CallOpts{}, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
	if err != nil {
		return nil, err
	}
	ccv.Plog.Info().Any("LINK Balance", balance).Send()
	return &ContractsBind{
		Link:   linkContract,
		Router: routerContract,
	}, nil
}

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	srcEthClient, srcAuth, _, err := ccv.ETHClient(in.Blockchains[0].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
	require.NoError(t, err)
	contracts, err := ccv.GetCLDFAddressesPerSelector(in)
	contractsSrc, err := loadContracts(srcEthClient, srcAuth, contracts[0]) // all the source contracts
	require.NoError(t, err)

	details, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[0].ChainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	dstSelector := details.ChainSelector

	msgArgs := &types.EVMExtraArgsV3{
		RequiredCCV: []types.CCV{
			{
				CCVAddress: []byte{},
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		OptionalCCV: []types.CCV{
			{
				CCVAddress: []byte{},
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		Executor:       []byte{},
		ExecutorArgs:   []byte{},
		TokenArgs:      []byte{},
		FinalityConfig: 1,
		RequiredCCVLen: 1,
		TokenArgsLen:   1,
	}
	msgArgsBytes := msgArgs.ToBytes()

	tx, err := contractsSrc.Router.CcipSend(srcAuth, dstSelector, routerBind.ClientEVM2AnyMessage{
		Receiver: []byte("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		Data:     []byte("Hello from another chain!"),
		TokenAmounts: []routerBind.ClientEVMTokenAmount{
			{
				Token:  contractsSrc.Link.Address(),
				Amount: big.NewInt(1),
			},
		},
		FeeToken:  contractsSrc.Link.Address(),
		ExtraArgs: msgArgsBytes,
	})
	require.NoError(t, err)
	rc, err := bind.WaitMined(context.Background(), srcEthClient, tx)
	require.NoError(t, err)
	spew.Dump(rc)
}
