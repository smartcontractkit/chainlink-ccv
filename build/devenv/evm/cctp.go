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

	usdc, _, messenger, err := m.deployCircleOwnedContracts(chain)
	if err != nil {
		return fmt.Errorf("failed to deploy Circle-owned contracts on chain %d: %w", selector, err)
	}

	// Register USDC ERC20 token in datastore for transfers in tests
	err = ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: selector,
		Type:          datastore.ContractType(burnminterc677ops.ContractType),
		Version:       burnminterc677ops.Version,
		Address:       usdc.Hex(),
		Qualifier:     "CCTP",
	})
	if err != nil {
		return err
	}

	// Grant mint and burn roles to deployer
	_, err = operations.ExecuteOperation(env.OperationsBundle, burnminterc677ops.GrantMintAndBurnRoles, chain, contract.FunctionInput[common.Address]{
		ChainSelector: selector,
		Address:       usdc,
		Args:          chain.DeployerKey.From,
	})
	if err != nil {
		return err
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
		return err
	}

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
	return nil
}

func (m *CCIP17EVMConfig) deployCircleOwnedContracts(chain evm.Chain) (common.Address, common.Address, common.Address, error) {
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
			Qualifier:     "CCTP",
		}
		remoteChains[rs] = adapters.RemoteCCTPChainConfig[datastore.AddressRef, datastore.AddressRef]{
			FeeUSDCents:         10,
			GasForVerification:  100000,
			PayloadSizeBytes:    1000,
			LockOrBurnMechanism: "CCTP_V2_WITH_CCV",
			RemoteDomain: adapters.RemoteDomain[datastore.AddressRef]{
				AllowedCallerOnDest:   pool,
				AllowedCallerOnSource: pool,
				MintRecipientOnDest:   pool,
				DomainIdentifier:      domains[rs],
			},
			TokenPoolConfig: tokenscore.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef]{
				RemotePool: pool,
				RemoteToken: datastore.AddressRef{
					ChainSelector: rs,
					Type:          datastore.ContractType(burnminterc677ops.ContractType),
					Version:       burnminterc677ops.Version,
					Qualifier:     "CCTP",
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
				ChainSelector: selector,
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
