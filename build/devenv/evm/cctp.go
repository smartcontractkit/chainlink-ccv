package evm

import (
	"fmt"
	"math/big"

	"github.com/Masterminds/semver/v3"
	gethcommon "github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/create2_factory"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/usdc_token_pool_proxy"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/mock_usdc_token_messenger"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/mock_usdc_token_transmitter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	burnminterc677ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	burn_mint_erc20_bindings "github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc20"
)

func (m *CCIP17EVMConfig) deployUSDCTokenAndPool(
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

	usdc, transmitter, messenger, err := m.deployCircleContracts(chain, ds, selector)
	if err != nil {
		return fmt.Errorf("failed to deploy Circle-owned contracts on chain %d: %w", selector, err)
	}

	err = m.configureCircleContracts(env, chain, selector, usdc, messenger, transmitter)
	if err != nil {
		return err
	}

	remoteSelectors := make([]uint64, 0)
	for _, s := range env.BlockChains.All() {
		if s.ChainSelector() != selector {
			remoteSelectors = append(remoteSelectors, s.ChainSelector())
		}
	}

	err = m.deployCCTPChain(env, registry, ds, create2Factory, selector, messenger, usdc)
	if err != nil {
		return err
	}

	err = m.deployMockReceivers(env, ds, selector)
	if err != nil {
		return err
	}

	return nil
}

func (m *CCIP17EVMConfig) configureCircleContracts(
	env *deployment.Environment,
	chain evm.Chain,
	selector uint64,
	usdc gethcommon.Address,
	messenger gethcommon.Address,
	transmitter gethcommon.Address,
) error {
	_, err := operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[gethcommon.Address]{
		ChainSelector: selector,
		Address:       usdc,
		Args:          messenger,
	})
	if err != nil {
		return fmt.Errorf("failed to grant burn mint permissions to usdc messenger %s: %w", messenger.String(), err)
	}

	_, err = operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[gethcommon.Address]{
		ChainSelector: selector,
		Address:       usdc,
		Args:          transmitter,
	})
	if err != nil {
		return fmt.Errorf("failed to grant burn mint permissions to usdc transmitter %s: %w", transmitter.String(), err)
	}

	_, err = operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[gethcommon.Address]{
		ChainSelector: selector,
		Address:       usdc,
		Args:          chain.DeployerKey.From,
	})
	if err != nil {
		return fmt.Errorf("failed to grant burn mint permissions to deployer %s: %w", chain.DeployerKey.From.Hex(), err)
	}

	_, err = operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.Mint, chain, contract.FunctionInput[burnminterc677ops.MintArgs]{
		ChainSelector: selector,
		Address:       usdc,
		Args: burnminterc677ops.MintArgs{
			Account: chain.DeployerKey.From,
			Amount:  big.NewInt(1000000 * 1e6), // Mint 1,000,000 USDC (6 decimals)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to initially mint USDC to deployer %s: %w", chain.DeployerKey.From.Hex(), err)
	}
	return err
}

func (m *CCIP17EVMConfig) deployCCTPChain(
	env *deployment.Environment,
	registry *changesetscore.MCMSReaderRegistry,
	ds *datastore.MemoryDataStore,
	create2Factory datastore.AddressRef,
	selector uint64,
	messenger gethcommon.Address,
	usdc gethcommon.Address,
) error {
	cctpChainRegistry := adapters.NewCCTPChainRegistry()
	cctpChainRegistry.RegisterCCTPChain("evm", &evmadapters.CCTPChainAdapter{})

	usdcPoolProxyRefs := usdcTokenPoolProxies(selector, nil)

	out, err := changesets.DeployCCTPChains(cctpChainRegistry, registry).Apply(*env, changesets.DeployCCTPChainsConfig{
		Chains: map[uint64]changesets.CCTPChainConfig{
			selector: {
				TokenMessenger:    messenger.Hex(),
				USDCToken:         usdc.Hex(),
				RegisteredPoolRef: usdcPoolProxyRefs[selector],
				StorageLocations:  []string{"https://test.chain.link.fake"},
				FastFinalityBps:   100,
				DeployerContract:  create2Factory.Address,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy CCTP chain registry on chain %d: %w", selector, err)
	}

	err = ds.Merge(out.DataStore.Seal())
	if err != nil {
		return err
	}
	return err
}

func (m *CCIP17EVMConfig) configureUSDCForTransfer(
	env *deployment.Environment,
	registry *changesetscore.MCMSReaderRegistry,
	selector uint64,
	remoteSelectors []uint64,
) error {
	remoteSelectors = filterOnlySupportedSelectors(remoteSelectors)
	cctpChainRegistry := adapters.NewCCTPChainRegistry()
	cctpChainRegistry.RegisterCCTPChain("evm", &evmadapters.CCTPChainAdapter{})

	create2, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(create2_factory.ContractType),
		semver.MustParse(create2_factory.Deploy.Version()),
		"",
	))
	if err != nil {
		return err
	}

	usdc, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(burnminterc677ops.ContractType),
		semver.MustParse(burnminterc677ops.Deploy.Version()),
		common.CCTPContractsQualifier,
	))
	if err != nil {
		return err
	}

	domains := map[uint64]uint32{
		chainsel.GETH_TESTNET.Selector:  101,
		chainsel.GETH_DEVNET_2.Selector: 102,
		chainsel.GETH_DEVNET_3.Selector: 104,
	}

	remoteChains := make(map[uint64]adapters.RemoteCCTPChainConfig)
	for _, rs := range remoteSelectors {
		remoteChains[rs] = adapters.RemoteCCTPChainConfig{
			FeeUSDCents:         10,
			GasForVerification:  100000,
			PayloadSizeBytes:    1000,
			LockOrBurnMechanism: "CCTP_V2_WITH_CCV",
			DomainIdentifier:    domains[rs],
		}
	}

	usdcTokenPools := usdcTokenPoolProxies(selector, remoteSelectors)
	config := map[uint64]changesets.CCTPChainConfig{
		selector: {
			USDCToken:         usdc.Address,
			RegisteredPoolRef: usdcTokenPools[selector],
			StorageLocations:  []string{"https://test.chain.link.fake"},
			FeeAggregator:     gethcommon.HexToAddress("0x04").Hex(),
			FastFinalityBps:   100,
			DeployerContract:  create2.Address,
			RemoteChains:      remoteChains,
		},
	}
	for chainSelector, poolRef := range usdcTokenPools {
		if chainSelector == selector {
			continue
		}
		config[chainSelector] = changesets.CCTPChainConfig{
			RegisteredPoolRef: poolRef,
		}
	}

	_, err = changesets.DeployCCTPChains(cctpChainRegistry, registry).Apply(*env, changesets.DeployCCTPChainsConfig{
		Chains: config,
	})
	if err != nil {
		return fmt.Errorf("failed to configure lanes for CCTP on source chain %d: %w", selector, err)
	}

	return err
}

func (m *CCIP17EVMConfig) deployMockReceivers(
	env *deployment.Environment,
	ds *datastore.MemoryDataStore,
	selector uint64,
) error {
	cctpVerifier, err := ds.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(cctp_verifier.ResolverType),
		semver.MustParse(cctp_verifier.Deploy.Version()),
		common.CCTPContractsQualifier,
	))
	if err != nil {
		return fmt.Errorf("failed to find CCTP verifier for chain %d: %w", selector, err)
	}

	committeeVerifier, err := ds.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(committee_verifier.ResolverType),
		semver.MustParse(committee_verifier.Deploy.Version()),
		common.DefaultCommitteeVerifierQualifier,
	))
	if err != nil {
		return fmt.Errorf("failed to find committee verifier for chain %d: %w", selector, err)
	}

	receivers := []struct {
		Qualifier         string
		RequiredVerifiers []datastore.AddressRef
	}{
		{
			Qualifier: common.CCTPPrimaryReceiverQualifier,
			RequiredVerifiers: []datastore.AddressRef{
				cctpVerifier,
			},
		},
		{
			Qualifier: common.CCTPSecondaryReceiverQualifier,
			RequiredVerifiers: []datastore.AddressRef{
				cctpVerifier,
				committeeVerifier,
			},
		},
	}

	for _, r := range receivers {
		requiredVerifiers := make([]gethcommon.Address, 0, len(r.RequiredVerifiers))
		for _, v := range r.RequiredVerifiers {
			requiredVerifiers = append(requiredVerifiers, gethcommon.HexToAddress(v.Address))
		}

		deployReceiverReport, err1 := operations.ExecuteOperation(
			env.OperationsBundle,
			mock_receiver.Deploy,
			env.BlockChains.EVMChains()[selector],
			contract.DeployInput[mock_receiver.ConstructorArgs]{
				TypeAndVersion: deployment.NewTypeAndVersion(mock_receiver.ContractType, *mock_receiver.Version),
				ChainSelector:  selector,
				Args: mock_receiver.ConstructorArgs{
					RequiredVerifiers: requiredVerifiers,
				},
				Qualifier: &r.Qualifier,
			})
		if err1 != nil {
			return fmt.Errorf("failed to deploy mock receiver %s on chain %d: %w", r.Qualifier, selector, err1)
		}

		err1 = ds.Addresses().Add(deployReceiverReport.Output)
		if err1 != nil {
			return fmt.Errorf("failed to register mock receiver %s on chain %d in datastore: %w", r.Qualifier, selector, err1)
		}
	}
	return nil
}

func (m *CCIP17EVMConfig) deployCircleContracts(
	chain evm.Chain,
	ds *datastore.MemoryDataStore,
	selector uint64,
) (gethcommon.Address, gethcommon.Address, gethcommon.Address, error) {
	var empty gethcommon.Address
	// We need a custom number of decimals (6) for USDC so we can't deploy erc20_with_drip here
	// which has hardcoded 18 decimals.
	usdcTokenAddr, tx, _, err := burn_mint_erc20_bindings.DeployBurnMintERC20(
		chain.DeployerKey,
		chain.Client,
		"USD Coin",
		"USDC",
		6,             // decimals
		big.NewInt(0), // maxSupply
		big.NewInt(0), // pre-mint amount
	)
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to deploy USDC token: %w", err)
	}
	if _, err1 := chain.Confirm(tx); err1 != nil {
		return empty, empty, empty, fmt.Errorf("failed to confirm USDC token deployment tx: %w", err1)
	}
	err = ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: selector,
		Type:          datastore.ContractType(burnminterc677ops.ContractType),
		Version:       burnminterc677ops.Version,
		Address:       usdcTokenAddr.Hex(),
		Qualifier:     common.CCTPContractsQualifier,
	})
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to add USDC token contract: %w", err)
	}

	messageTransmitterAddr, tx, _, err := mock_usdc_token_transmitter.DeployMockE2EUSDCTransmitter(
		chain.DeployerKey,
		chain.Client,
		uint32(1),     // version (CCTP V2)
		uint32(1),     // localDomain
		usdcTokenAddr, // token
	)
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to deploy USDC message transmitter: %w", err)
	}
	if _, err1 := chain.Confirm(tx); err1 != nil {
		return empty, empty, empty, fmt.Errorf("failed to confirm USDC message transmitter deployment tx: %w", err1)
	}
	err = ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: selector,
		Type:          "MockE2EUSDCTransmitter",
		Version:       semver.MustParse("1.0.0"),
		Address:       messageTransmitterAddr.Hex(),
		Qualifier:     common.CCTPContractsQualifier,
	})
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to add USDC message transmitter contract: %w", err)
	}

	tokenMessengerAddr, tx, _, err := mock_usdc_token_messenger.DeployMockE2EUSDCTokenMessenger(
		chain.DeployerKey,
		chain.Client,
		uint32(1),              // version (CCTP V2)
		messageTransmitterAddr, // transmitter
	)
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to deploy USDC token messenger: %w", err)
	}
	if _, err1 := chain.Confirm(tx); err1 != nil {
		return empty, empty, empty, fmt.Errorf("failed to confirm USDC token messenger deployment tx: %w", err1)
	}
	err = ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: selector,
		Type:          "MockE2EUSDCTokenMessenger",
		Version:       semver.MustParse("1.0.0"),
		Address:       tokenMessengerAddr.Hex(),
		Qualifier:     common.CCTPContractsQualifier,
	})
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to add USDC tijen messenger contract: %w", err)
	}

	return usdcTokenAddr, messageTransmitterAddr, tokenMessengerAddr, nil
}

func filterOnlySupportedSelectors(remoteSelectors []uint64) []uint64 {
	supportedRemoteSelectors := make([]uint64, 0)
	for _, rs := range remoteSelectors {
		family, err := chainsel.GetSelectorFamily(rs)
		if err != nil || family != chainsel.FamilyEVM {
			continue
		}
		supportedRemoteSelectors = append(supportedRemoteSelectors, rs)
	}
	return supportedRemoteSelectors
}

func usdcTokenPoolProxies(sourceSelector uint64, remoteSelectors []uint64) map[uint64]datastore.AddressRef {
	selectors := make([]uint64, 0)
	selectors = append(selectors, sourceSelector)
	for _, rs := range remoteSelectors {
		selectors = append(selectors, rs)
	}

	references := make(map[uint64]datastore.AddressRef)
	for _, selector := range selectors {
		references[selector] = datastore.AddressRef{
			ChainSelector: selector,
			Type:          datastore.ContractType(usdc_token_pool_proxy.ContractType),
			Version:       semver.MustParse(usdc_token_pool_proxy.Deploy.Version()),
			Qualifier:     common.CCTPContractsQualifier,
		}
	}
	return references
}
