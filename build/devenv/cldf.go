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

func NewCLDFOperationsEnvironment(
	blockchains []*blockchain.Input,
	virtualSelectors []*VirtualSelector,
	dataStore datastore.DataStore,
) ([]uint64, *deployment.Environment, map[uint64]*PhysicalChainInfo, error) {
	blockchainsByName := make(map[string]*blockchain.Input)
	for i := range blockchains {
		blockchainsByName[blockchains[i].ContainerName] = blockchains[i]
	}

	physicalProviders := make(map[string]evm.Chain)
	for _, vs := range virtualSelectors {
		physicalName := vs.PhysicalChain
		if _, exists := physicalProviders[physicalName]; exists {
			continue
		}

		bc := blockchainsByName[physicalName]
		chainID := bc.Out.ChainID
		rpcWSURL := bc.Out.Nodes[0].ExternalWSUrl
		rpcHTTPURL := bc.Out.Nodes[0].ExternalHTTPUrl

		physicalChainDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get chain details for %s: %w", physicalName, err)
		}

		Plog.Info().
			Str("ContainerName", physicalName).
			Str("ChainID", chainID).
			Uint64("PhysicalSelector", physicalChainDetails.ChainSelector).
			Msg("Creating RPC provider for physical blockchain")

		provider, err := cldf_evm_provider.NewRPCChainProvider(
			physicalChainDetails.ChainSelector,
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
			return nil, nil, nil, fmt.Errorf("initialize provider for %s: %w", physicalName, err)
		}

		evmChain, ok := provider.(evm.Chain)
		if !ok {
			return nil, nil, nil, fmt.Errorf("provider for %s is not an evm.Chain", physicalName)
		}
		physicalProviders[physicalName] = evmChain
	}

	blockchainMap := make(map[uint64]cldf_chain.BlockChain)
	selectors := make([]uint64, 0, len(virtualSelectors))
	for _, vs := range virtualSelectors {
		physicalProvider := physicalProviders[vs.PhysicalChain]

		virtualChain := evm.Chain{
			Selector:            uint64(vs.Selector),
			Client:              physicalProvider.Client,
			DeployerKey:         physicalProvider.DeployerKey,
			Confirm:             physicalProvider.Confirm,
			Users:               physicalProvider.Users,
			SignHash:            physicalProvider.SignHash,
			IsZkSyncVM:          physicalProvider.IsZkSyncVM,
			ClientZkSyncVM:      physicalProvider.ClientZkSyncVM,
			DeployerKeyZkSyncVM: physicalProvider.DeployerKeyZkSyncVM,
		}
		blockchainMap[uint64(vs.Selector)] = virtualChain
		selectors = append(selectors, uint64(vs.Selector))

		bc := blockchainsByName[vs.PhysicalChain]
		Plog.Info().
			Uint64("VirtualSelector", uint64(vs.Selector)).
			Str("VirtualName", vs.Name).
			Str("PhysicalChain", vs.PhysicalChain).
			Str("PhysicalChainID", bc.ChainID).
			Msg("Virtual selector mapped to physical chain")
	}

	chains := cldf_chain.NewBlockChains(blockchainMap)

	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		return nil, nil, nil, err
	}

	e := deployment.Environment{
		GetContext:  func() context.Context { return context.Background() },
		Logger:      lggr,
		BlockChains: chains,
		DataStore:   dataStore,
	}

	physicalChainMap := make(map[uint64]*PhysicalChainInfo)
	for _, vs := range virtualSelectors {
		bc := blockchainsByName[vs.PhysicalChain]
		physicalChainMap[uint64(vs.Selector)] = &PhysicalChainInfo{
			ChainID:       bc.ChainID,
			WSURL:         bc.Out.Nodes[0].ExternalWSUrl,
			HTTPURL:       bc.Out.Nodes[0].ExternalHTTPUrl,
			ContainerName: vs.PhysicalChain,
		}
	}

	return selectors, &e, physicalChainMap, nil
}

// NewDefaultCLDFBundle creates a new default CLDF bundle.
func NewDefaultCLDFBundle(e *deployment.Environment) operations.Bundle {
	return operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)
}
