package ccv

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
)

var Plog = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel).With().Fields(map[string]any{"component": "ccv"}).Logger()

type CLDF struct {
	mu        sync.Mutex          `toml:"-"`
	Addresses []string            `toml:"addresses"`
	DataStore datastore.DataStore `toml:"-"`
}

func (c *CLDF) Init() {
	c.DataStore = datastore.NewMemoryDataStore().Seal()
}

func (c *CLDF) AddAddresses(addresses string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Addresses = append(c.Addresses, addresses)
}

func NewCLDFOperationsEnvironment(bc []*blockchain.Input, dataStore datastore.DataStore) ([]uint64, *deployment.Environment, error) {
	providers := make([]cldf_chain.BlockChain, 0)
	selectors := make([]uint64, 0)
	for _, b := range bc {
		chainID := b.Out.ChainID
		rpcWSURL := b.Out.Nodes[0].ExternalWSUrl
		rpcHTTPURL := b.Out.Nodes[0].ExternalHTTPUrl

		d, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, nil, err
		}
		selectors = append(selectors, d.ChainSelector)

		p, err := cldf_evm_provider.NewRPCChainProvider(
			d.ChainSelector,
			cldf_evm_provider.RPCChainProviderConfig{
				DeployerTransactorGen: cldf_evm_provider.TransactorFromRaw(
					getNetworkPrivateKey(),
				),
				RPCs: []rpcclient.RPC{
					{
						Name:               "default",
						WSURL:              rpcWSURL,
						HTTPURL:            rpcHTTPURL,
						PreferredURLScheme: rpcclient.URLSchemePreferenceHTTP,
					},
				},
				ConfirmFunctor: cldf_evm_provider.ConfirmFuncGeth(1 * time.Minute),
			},
		).Initialize(context.Background())
		if err != nil {
			return nil, nil, err
		}
		providers = append(providers, p)
	}

	blockchains := cldf_chain.NewBlockChainsFromSlice(providers)

	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		return nil, nil, err
	}

	e := deployment.Environment{
		GetContext:  func() context.Context { return context.Background() },
		Logger:      lggr,
		BlockChains: blockchains,
		DataStore:   dataStore,
	}
	return selectors, &e, nil
}

// NewDefaultCLDFBundle creates a new default CLDF bundle.
func NewDefaultCLDFBundle(e *deployment.Environment) operations.Bundle {
	return operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
}

// NewCLDFOperationsEnvironmentWithVirtualSelectors creates a CLDF environment where multiple
// virtual selectors all map to the same physical blockchain. This allows deploying multiple
// independent contract sets to a single chain for testing multi-chain scenarios.
func NewCLDFOperationsEnvironmentWithVirtualSelectors(
	physicalBC *blockchain.Input,
	virtualSelectors []uint64,
	dataStore datastore.DataStore,
) ([]uint64, *deployment.Environment, error) {
	chainID := physicalBC.Out.ChainID
	rpcWSURL := physicalBC.Out.Nodes[0].ExternalWSUrl
	rpcHTTPURL := physicalBC.Out.Nodes[0].ExternalHTTPUrl

	// Get the physical chain details for the real chain selector
	physicalChainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
	if err != nil {
		return nil, nil, err
	}

	Plog.Info().
		Str("ChainID", chainID).
		Uint64("PhysicalSelector", physicalChainDetails.ChainSelector).
		Int("VirtualSelectors", len(virtualSelectors)).
		Msg("Creating CLDF environment with virtual selectors")

	// Create ONE provider using the REAL chain selector (so it passes validation)
	// but we'll map it to multiple virtual selectors externally
	provider, err := cldf_evm_provider.NewRPCChainProvider(
		physicalChainDetails.ChainSelector, // Use real selector for internal provider operations
		cldf_evm_provider.RPCChainProviderConfig{
			DeployerTransactorGen: cldf_evm_provider.TransactorFromRaw(
				getNetworkPrivateKey(),
			),
			RPCs: []rpcclient.RPC{
				{
					Name:               "default",
					WSURL:              rpcWSURL,
					HTTPURL:            rpcHTTPURL,
					PreferredURLScheme: rpcclient.URLSchemePreferenceHTTP,
				},
			},
			ConfirmFunctor: cldf_evm_provider.ConfirmFuncGeth(1 * time.Minute),
		},
	).Initialize(context.Background())
	if err != nil {
		return nil, nil, err
	}

	// Cast to evm.Chain so we can work with it directly
	evmChain, ok := provider.(evm.Chain)
	if !ok {
		return nil, nil, fmt.Errorf("provider is not an evm.Chain")
	}

	// Create a copy of the EVM chain for each virtual selector, changing only the Selector field
	blockchainMap := make(map[uint64]cldf_chain.BlockChain)
	for _, selector := range virtualSelectors {
		// Create a new evm.Chain with the virtual selector but same client/keys
		virtualChain := evm.Chain{
			Selector:            selector, // Virtual selector
			Client:              evmChain.Client,
			DeployerKey:         evmChain.DeployerKey,
			Confirm:             evmChain.Confirm,
			Users:               evmChain.Users,
			SignHash:            evmChain.SignHash,
			IsZkSyncVM:          evmChain.IsZkSyncVM,
			ClientZkSyncVM:      evmChain.ClientZkSyncVM,
			DeployerKeyZkSyncVM: evmChain.DeployerKeyZkSyncVM,
		}
		blockchainMap[selector] = virtualChain
		Plog.Info().
			Uint64("VirtualSelector", selector).
			Uint64("PhysicalSelector", physicalChainDetails.ChainSelector).
			Str("PhysicalChainID", chainID).
			Msg("Virtual selector mapped to physical chain provider")
	}

	blockchains := cldf_chain.NewBlockChains(blockchainMap)

	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		return nil, nil, err
	}

	e := deployment.Environment{
		GetContext:  func() context.Context { return context.Background() },
		Logger:      lggr,
		BlockChains: blockchains,
		DataStore:   dataStore,
	}

	return virtualSelectors, &e, nil
}
