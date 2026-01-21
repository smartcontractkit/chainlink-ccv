package evm

import (
	"fmt"
	"math/big"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_message_transmitter_proxy"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_through_ccv_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/usdc_token_pool_proxy"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/testsetup"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/mock_usdc_token_messenger"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/mock_usdc_token_transmitter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	routeroperations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	burnminterc677ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	burn_mint_erc20_bindings "github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc20"
)

const (
	CCTPContractsQualifier         = "CCTP"
	CCTPPrimaryReceiverQualifier   = "cctp-primary"
	CCTPSecondaryReceiverQualifier = "cctp-secondary"
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

	err = m.deployCCTPChain(env, registry, ds, create2Factory, selector, messenger, usdc, chain)
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
	usdc common.Address,
	messenger common.Address,
	transmitter common.Address,
) error {
	_, err := operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[common.Address]{
		ChainSelector: selector,
		Address:       usdc,
		Args:          messenger,
	})
	if err != nil {
		return fmt.Errorf("failed to grant burn mint permissions to usdc messenger %s: %w", messenger.String(), err)
	}

	_, err = operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[common.Address]{
		ChainSelector: selector,
		Address:       usdc,
		Args:          transmitter,
	})
	if err != nil {
		return fmt.Errorf("failed to grant burn mint permissions to usdc transmitter %s: %w", transmitter.String(), err)
	}

	_, err = operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[common.Address]{
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
	messenger common.Address,
	usdc common.Address,
	chain evm.Chain,
) error {
	cctpChainRegistry := adapters.NewCCTPChainRegistry()
	cctpChainRegistry.RegisterCCTPChain("evm", &evmadapters.CCTPChainAdapter{})

	out, err := changesets.DeployCCTPChains(cctpChainRegistry, registry).Apply(*env, changesets.DeployCCTPChainsConfig{
		Chains: []adapters.DeployCCTPInput[datastore.AddressRef, datastore.AddressRef]{
			{
				ChainSelector: selector,
				TokenAdminRegistry: datastore.AddressRef{
					Type:    datastore.ContractType(token_admin_registry.ContractType),
					Version: semver.MustParse(token_admin_registry.Deploy.Version()),
				},
				TokenMessenger:   messenger.Hex(),
				USDCToken:        usdc.Hex(),
				MinFinalityValue: 1,
				StorageLocations: []string{"https://test.chain.link.fake"},
				FeeAggregator:    common.HexToAddress("0x04").Hex(),
				AllowlistAdmin:   common.HexToAddress("0x05").Hex(),
				FastFinalityBps:  100,
				RMN: datastore.AddressRef{
					Type:    datastore.ContractType(rmn_remote.ContractType),
					Version: semver.MustParse(rmn_remote.Deploy.Version()),
				},
				Router: datastore.AddressRef{
					Type:    datastore.ContractType(routeroperations.ContractType),
					Version: semver.MustParse(routeroperations.Deploy.Version()),
				},
				DeployerContract:                 create2Factory.Address,
				Allowlist:                        []string{common.HexToAddress("0x08").Hex()},
				ThresholdAmountForAdditionalCCVs: big.NewInt(1e18),
				RateLimitAdmin:                   chain.DeployerKey.From.Hex(),
				RemoteChains:                     make(map[uint64]adapters.RemoteCCTPChainConfig[datastore.AddressRef, datastore.AddressRef]),
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

func (m *CCIP17EVMConfig) deployMockReceivers(
	env *deployment.Environment,
	ds *datastore.MemoryDataStore,
	selector uint64,
) error {
	cctpVerifier, err := ds.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(cctp_verifier.ResolverType),
		semver.MustParse(cctp_verifier.Deploy.Version()),
		CCTPContractsQualifier,
	))
	if err != nil {
		return fmt.Errorf("failed to find CCTP verifier for chain %d: %w", selector, err)
	}

	committeeVerifier, err := ds.Addresses().Get(datastore.NewAddressRefKey(
		selector,
		datastore.ContractType(committee_verifier.ResolverType),
		semver.MustParse(committee_verifier.Deploy.Version()),
		DefaultCommitteeVerifierQualifier,
	))
	if err != nil {
		return fmt.Errorf("failed to find committee verifier for chain %d: %w", selector, err)
	}

	receivers := []struct {
		Qualifier         string
		RequiredVerifiers []datastore.AddressRef
	}{
		{
			Qualifier: CCTPPrimaryReceiverQualifier,
			RequiredVerifiers: []datastore.AddressRef{
				cctpVerifier,
			},
		},
		{
			Qualifier: CCTPSecondaryReceiverQualifier,
			RequiredVerifiers: []datastore.AddressRef{
				cctpVerifier,
				committeeVerifier,
			},
		},
	}

	for _, r := range receivers {
		requiredVerifiers := make([]common.Address, 0, len(r.RequiredVerifiers))
		for _, v := range r.RequiredVerifiers {
			requiredVerifiers = append(requiredVerifiers, common.HexToAddress(v.Address))
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
) (common.Address, common.Address, common.Address, error) {
	var empty common.Address
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
		Qualifier:     CCTPContractsQualifier,
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
		Qualifier:     CCTPContractsQualifier,
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
		Qualifier:     CCTPContractsQualifier,
	})
	if err != nil {
		return empty, empty, empty, fmt.Errorf("failed to add USDC tijen messenger contract: %w", err)
	}

	return usdcTokenAddr, messageTransmitterAddr, tokenMessengerAddr, nil
}

func (m *CCIP17EVMConfig) configureUSDCForTransfer(env *deployment.Environment, cctpChainRegistry *adapters.CCTPChainRegistry, registry *changesetscore.MCMSReaderRegistry, create2 datastore.AddressRef, selector uint64, remoteSelectors []uint64) error {
	domains := map[uint64]uint32{
		chainsel.GETH_TESTNET.Selector:  101,
		chainsel.GETH_DEVNET_2.Selector: 102,
		chainsel.GETH_DEVNET_3.Selector: 104,
	}

	remoteChains := make(map[uint64]adapters.RemoteCCTPChainConfig[datastore.AddressRef, datastore.AddressRef])
	for _, rs := range remoteSelectors {
		pool := datastore.AddressRef{
			ChainSelector: rs,
			Type:          datastore.ContractType(usdc_token_pool_proxy.ContractType),
			Version:       semver.MustParse(usdc_token_pool_proxy.Deploy.Version()),
			Qualifier:     CCTPContractsQualifier,
		}
		remoteChains[rs] = adapters.RemoteCCTPChainConfig[datastore.AddressRef, datastore.AddressRef]{
			FeeUSDCents:         10,
			GasForVerification:  100000,
			PayloadSizeBytes:    1000,
			LockOrBurnMechanism: "CCTP_V2_WITH_CCV",
			RemoteDomain: adapters.RemoteDomain[datastore.AddressRef]{
				AllowedCallerOnDest: datastore.AddressRef{
					ChainSelector: rs,
					Type:          datastore.ContractType(cctp_message_transmitter_proxy.ContractType),
					Version:       semver.MustParse(cctp_message_transmitter_proxy.Deploy.Version()),
					Qualifier:     CCTPContractsQualifier,
				},
				AllowedCallerOnSource: datastore.AddressRef{
					ChainSelector: rs,
					Type:          datastore.ContractType(cctp_verifier.ContractType),
					Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
					Qualifier:     CCTPContractsQualifier,
				},
				DomainIdentifier: domains[rs],
			},
			TokenPoolConfig: tokenscore.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef]{
				RemotePool: pool,
				RemoteToken: datastore.AddressRef{
					ChainSelector: rs,
					Type:          datastore.ContractType(burnminterc677ops.ContractType),
					Version:       burnminterc677ops.Version,
					Qualifier:     CCTPContractsQualifier,
				},
				DefaultFinalityInboundRateLimiterConfig:  testsetup.CreateRateLimiterConfig(0, 0),
				DefaultFinalityOutboundRateLimiterConfig: testsetup.CreateRateLimiterConfig(0, 0),
				CustomFinalityInboundRateLimiterConfig:   testsetup.CreateRateLimiterConfig(0, 0),
				CustomFinalityOutboundRateLimiterConfig:  testsetup.CreateRateLimiterConfig(0, 0),
			},
		}
	}

	_, err := changesets.DeployCCTPChains(cctpChainRegistry, registry).Apply(*env, changesets.DeployCCTPChainsConfig{
		Chains: []adapters.DeployCCTPInput[datastore.AddressRef, datastore.AddressRef]{
			{
				ChainSelector:    selector,
				MinFinalityValue: 1,
				Router: datastore.AddressRef{
					Type:    datastore.ContractType(routeroperations.ContractType),
					Version: semver.MustParse(routeroperations.Deploy.Version()),
				},
				MessageTransmitterProxy: datastore.AddressRef{
					ChainSelector: selector,
					Type:          datastore.ContractType(cctp_message_transmitter_proxy.ContractType),
					Version:       semver.MustParse(cctp_message_transmitter_proxy.Deploy.Version()),
				},
				TokenPool: []datastore.AddressRef{
					{
						ChainSelector: selector,
						Type:          datastore.ContractType(usdc_token_pool_proxy.ContractType),
						Version:       semver.MustParse(usdc_token_pool_proxy.Deploy.Version()),
					},
					{
						ChainSelector: selector,
						Type:          datastore.ContractType(cctp_through_ccv_token_pool.ContractType),
						Version:       semver.MustParse(cctp_through_ccv_token_pool.Deploy.Version()),
					},
				},
				CCTPVerifier: []datastore.AddressRef{
					{
						ChainSelector: selector,
						Type:          datastore.ContractType(cctp_verifier.ContractType),
						Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
					},
					{
						ChainSelector: selector,
						Type:          datastore.ContractType(cctp_verifier.ResolverType),
						Version:       semver.MustParse(cctp_verifier.Deploy.Version()),
					},
				},
				TokenAdminRegistry: datastore.AddressRef{
					Type:    datastore.ContractType(token_admin_registry.ContractType),
					Version: semver.MustParse(token_admin_registry.Deploy.Version()),
				},
				RemoteChains: remoteChains,
			},
		},
	},
	)
	if err != nil {
		return fmt.Errorf("failed to deploy CCTP chain registry on chain %d: %w", selector, err)
	}
	return nil
}
