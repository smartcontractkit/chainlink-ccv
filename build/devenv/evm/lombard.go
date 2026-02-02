package evm

import (
	"fmt"

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

var LombardContractsQualifier = "Lombard"

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
				DeployerContract: create2Factory.Address,
				StorageLocations: []string{"https://test.chain.link.fake"},
				RateLimitAdmin:   chain.DeployerKey.From.Hex(),
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
