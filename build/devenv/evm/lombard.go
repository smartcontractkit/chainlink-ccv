package evm

import (
	"fmt"
	"math/big"

	"github.com/Masterminds/semver/v3"

	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/mock_lombard_bridge"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"

	"github.com/ethereum/go-ethereum/common"

	evm_contract "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var (
	LombardContractsQualifier = "Lombard"
	LombardTokenQualifier     = "LBTC"
)

func (m *CCIP17EVMConfig) deployLombardTokenAndPool(
	env *deployment.Environment,
	registry *changesetscore.MCMSReaderRegistry,
	ds *datastore.MemoryDataStore,
	create2Factory datastore.AddressRef,
	selector uint64,
) error {
	chain, ok := env.BlockChains.EVMChains()[selector]
	if !ok {
		return fmt.Errorf("evm chain not found for selector %d", selector)
	}

	lombardToken, bridgeV2, err := m.deployLombardContracts(env, chain, ds, selector)
	if err != nil {
		return fmt.Errorf("failed to deploy lombard contracts on chain %s: %w", chain, err)
	}

	err = m.configureLombardContracts(env, chain, selector, lombardToken)
	if err != nil {
		return fmt.Errorf("failed to configure lombard contracts on chain %s: %w", chain, err)
	}

	err = m.deployLombardChain(env, registry, ds, create2Factory, selector, lombardToken, bridgeV2, chain)
	if err != nil {
		return fmt.Errorf("failed to deploy lombard chain for chain %s: %w", chain, err)
	}

	return nil
}

func (m *CCIP17EVMConfig) deployLombardContracts(
	env *deployment.Environment,
	chain evm.Chain,
	ds *datastore.MemoryDataStore,
	selector uint64,
) (common.Address, common.Address, error) {
	var empty common.Address

	deployTokenReport, err := cldf_ops.ExecuteOperation(env.OperationsBundle, burn_mint_erc20_with_drip.Deploy, chain, evm_contract.DeployInput[burn_mint_erc20_with_drip.ConstructorArgs]{
		ChainSelector:  selector,
		TypeAndVersion: deployment.NewTypeAndVersion(burn_mint_erc20_with_drip.ContractType, *burn_mint_erc20_with_drip.Version),
		Args: burn_mint_erc20_with_drip.ConstructorArgs{
			Name:   "LBTC",
			Symbol: "LBTC",
		},
		Qualifier: &LombardContractsQualifier,
	})
	if err != nil {
		return empty, empty, fmt.Errorf("failed to deploy lombard burn mint token on chain %s: %w", chain, err)
	}
	err = ds.Addresses().Add(deployTokenReport.Output)
	if err != nil {
		return empty, empty, fmt.Errorf("failed to store lombard burn mint token address on chain %s: %w", chain, err)
	}

	lombardBridgeAddr, tx, _, err := mock_lombard_bridge.DeployMockLombardBridge(
		chain.DeployerKey,
		chain.Client,
	)
	if err != nil {
		return empty, empty, fmt.Errorf("failed to deploy lombard bridge on chain %s: %w", chain, err)
	}
	if _, err1 := chain.Confirm(tx); err1 != nil {
		return empty, empty, fmt.Errorf("failed to confirm lombard bridge deployment tx on chain %s: %w", chain, err1)
	}
	err = ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: selector,
		Type:          "MockLombardBridge",
		Version:       semver.MustParse("1.7.0"),
		Address:       lombardBridgeAddr.Hex(),
		Qualifier:     LombardContractsQualifier,
	})
	if err != nil {
		return empty, empty, fmt.Errorf("failed to store lombard bridge address on chain %s: %w", chain, err)
	}

	return common.HexToAddress(deployTokenReport.Output.Address), lombardBridgeAddr, nil
}

func (m *CCIP17EVMConfig) configureLombardContracts(
	env *deployment.Environment,
	chain evm.Chain,
	selector uint64,
	token common.Address,
) error {
	_, err := cldf_ops.ExecuteOperation(env.OperationsBundle, burn_mint_erc20_with_drip.GrantMintAndBurnRoles, chain, evm_contract.FunctionInput[common.Address]{
		ChainSelector: selector,
		Address:       token,
		Args:          chain.DeployerKey.From,
	})
	if err != nil {
		return fmt.Errorf("failed to grant burn mint permissions to deployer %s: %w", chain.DeployerKey.From.Hex(), err)
	}

	_, err = cldf_ops.ExecuteOperation(env.OperationsBundle, burn_mint_erc20_with_drip.Mint, chain, evm_contract.FunctionInput[burn_mint_erc20_with_drip.MintArgs]{
		ChainSelector: selector,
		Address:       token,
		Args: burn_mint_erc20_with_drip.MintArgs{
			Account: chain.DeployerKey.From,
			// Mint 1,000,000 LBTC (18 decimals)
			Amount: new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to initially mint LBTC to deployer %s: %w", chain.DeployerKey.From.Hex(), err)
	}
	return err
}

func (m *CCIP17EVMConfig) deployLombardChain(
	env *deployment.Environment,
	registry *changesetscore.MCMSReaderRegistry,
	ds *datastore.MemoryDataStore,
	create2Factory datastore.AddressRef,
	selector uint64,
	lombardToken common.Address,
	bridgeV2 common.Address,
	chain evm.Chain,
) error {
	lombardChainRegistry := adapters.NewLombardChainRegistry()
	lombardChainRegistry.RegisterLombardChain("evm", &evmadapters.LombardChainAdapter{})

	out, err := changesets.DeployLombardChains(lombardChainRegistry, registry).Apply(*env, changesets.DeployLombardChainsConfig{
		Chains: map[uint64]changesets.LombardChainConfig{
			selector: {
				Bridge:           bridgeV2.Hex(),
				Token:            lombardToken.Hex(),
				TokenQualifier:   LombardTokenQualifier,
				DeployerContract: create2Factory.Address,
				StorageLocations: []string{"https://test.chain.link.fake"},
				RateLimitAdmin:   chain.DeployerKey.From.Hex(),
				FeeAggregator:    common.HexToAddress("0x01").Hex(),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy Lombard chain registry on chain %d: %w", selector, err)
	}

	err = ds.Merge(out.DataStore.Seal())
	if err != nil {
		return err
	}
	return err
}

func (m *CCIP17EVMConfig) configureLombardForTransfer(
	e *deployment.Environment,
	registry *changesetscore.MCMSReaderRegistry,
	selector uint64,
	remoteSelectors []uint64,
) error {
	remoteSelectors = filterOnlySupportedSelectors(remoteSelectors)
	lombardChainRegistry := adapters.NewLombardChainRegistry()
	lombardChainRegistry.RegisterLombardChain("evm", &evmadapters.LombardChainAdapter{})

	remoteChains := make(map[uint64]adapters.RemoteLombardChainConfig)
	for _, rs := range remoteSelectors {
		remoteChains[rs] = adapters.RemoteLombardChainConfig{
			FeeUSDCents:        45,
			GasForVerification: 7_500*6 + 5_000,
			PayloadSizeBytes:   6*64 + 2*32,
			LombardChainId:     uint32(rs),
		}
	}

	tokenRef, err := e.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			selector,
			datastore.ContractType(burn_mint_erc20_with_drip.ContractType),
			semver.MustParse(burn_mint_erc20_with_drip.Deploy.Version()),
			LombardContractsQualifier,
		),
	)
	if err != nil {
		return fmt.Errorf("failed to get lombard token address ref for chain %d: %w", selector, err)
	}

	_, err = changesets.DeployLombardChains(lombardChainRegistry, registry).Apply(*e, changesets.DeployLombardChainsConfig{
		Chains: map[uint64]changesets.LombardChainConfig{
			selector: {
				Token:          tokenRef.Address,
				TokenQualifier: LombardTokenQualifier,
				RemoteChains:   remoteChains,
				FeeAggregator:  common.HexToAddress("0x01").Hex(),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy CCTP chain registry on chain %d: %w", selector, err)
	}

	return err
}
