package ccv

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

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

type CLDFEnvironmentConfig struct {
	Blockchains    []*blockchain.Input
	DataStore      datastore.DataStore
	OffchainClient offchain.Client
	NodeIDs        []string
}

func NewCLDFOperationsEnvironment(bc []*blockchain.Input, dataStore datastore.DataStore) ([]uint64, *deployment.Environment, error) {
	return NewCLDFOperationsEnvironmentWithOffchain(CLDFEnvironmentConfig{
		Blockchains: bc,
		DataStore:   dataStore,
	})
}

func NewCLDFOperationsEnvironmentWithOffchain(cfg CLDFEnvironmentConfig) ([]uint64, *deployment.Environment, error) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}

	providers := make([]cldf_chain.BlockChain, 0)
	selectors := make([]uint64, 0)

	for _, b := range cfg.Blockchains {
		factory, ok := registry.GetGlobalCLDFProviderRegistry().Get(b.Out.Family)
		if !ok {
			return nil, nil, fmt.Errorf("unsupported blockchain family, missing CLDF provider factory: %s", b.Out.Family)
		}
		provider, selector, err := factory(context.Background(), b)
		if err != nil {
			return nil, nil, err
		}
		selectors = append(selectors, selector)
		providers = append(providers, provider)
	}

	blockchains := cldf_chain.NewBlockChainsFromSlice(providers)

	getCtx := func() context.Context { return context.Background() }
	e := deployment.Environment{
		GetContext:  getCtx,
		Logger:      lggr,
		BlockChains: blockchains,
		DataStore:   cfg.DataStore,
		Offchain:    cfg.OffchainClient,
		NodeIDs:     cfg.NodeIDs,
		OperationsBundle: operations.NewBundle(
			getCtx,
			lggr,
			operations.NewMemoryReporter(),
		),
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

func GenerateUserTransactors(privateKeys []string) []cldf_evm_provider.SignerGenerator {
	transactors := make([]cldf_evm_provider.SignerGenerator, 0, len(privateKeys))
	for _, pk := range privateKeys {
		transactors = append(transactors, cldf_evm_provider.TransactorFromRaw(pk))
	}
	return transactors
}
