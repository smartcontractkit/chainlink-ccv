package ccv

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_canton "github.com/smartcontractkit/chainlink-deployments-framework/chain/canton"
	cldf_canton_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/canton/provider"
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
	providers := make([]cldf_chain.BlockChain, 0)
	selectors := make([]uint64, 0)
	defaultTxTimeout := 30 * time.Second
	for _, b := range cfg.Blockchains {
		switch b.Out.Family {
		case blockchain.FamilyEVM:
			chainID := b.Out.ChainID
			rpcWSURL := b.Out.Nodes[0].ExternalWSUrl
			rpcHTTPURL := b.Out.Nodes[0].ExternalHTTPUrl

			d, err := chainsel.GetChainDetailsByChainIDAndFamily(chainID, chainsel.FamilyEVM)
			if err != nil {
				return nil, nil, err
			}
			selectors = append(selectors, d.ChainSelector)

			var confirmer cldf_evm_provider.ConfirmFunctor
			switch b.Type {
			case blockchain.TypeAnvil:
				confirmer = cldf_evm_provider.ConfirmFuncGeth(defaultTxTimeout, cldf_evm_provider.WithTickInterval(5*time.Millisecond))
			case blockchain.TypeGeth:
				confirmer = cldf_evm_provider.ConfirmFuncGeth(defaultTxTimeout)
			default:
				panic(fmt.Sprintf("EVM blockchain type %s is not supported", b.Type))
			}

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
					UsersTransactorGen: GenerateUserTransactors(getUserPrivateKeys()),
					ConfirmFunctor:     confirmer,
				},
			).Initialize(context.Background())
			if err != nil {
				return nil, nil, err
			}
			providers = append(providers, p)
		case blockchain.FamilyCanton:
			d, err := chainsel.GetChainDetailsByChainIDAndFamily(b.Out.ChainID, chainsel.FamilyCanton)
			if err != nil {
				return nil, nil, err
			}
			selectors = append(selectors, d.ChainSelector)

			var (
				endpoints    []cldf_canton.ParticipantEndpoints
				jwtProviders []cldf_canton.JWTProvider
			)
			for _, p := range b.Out.NetworkSpecificData.CantonEndpoints.Participants {
				endpoints = append(endpoints, cldf_canton.ParticipantEndpoints{
					JSONLedgerAPIURL: p.JSONLedgerAPIURL,
					GRPCLedgerAPIURL: p.GRPCLedgerAPIURL,
					AdminAPIURL:      p.AdminAPIURL,
					ValidatorAPIURL:  p.ValidatorAPIURL,
				})
				jwtProviders = append(jwtProviders, cldf_canton.NewStaticJWTProvider(p.JWT))
			}

			p, err := cldf_canton_provider.NewRPCChainProvider(d.ChainSelector, cldf_canton_provider.RPCChainProviderConfig{
				Endpoints:    endpoints,
				JWTProviders: jwtProviders,
			}).Initialize(context.TODO())
			if err != nil {
				return nil, nil, err
			}
			providers = append(providers, p)
		case blockchain.FamilyStellar:
			details, err := chainsel.GetChainDetailsByChainIDAndFamily(b.Out.ChainID, chainsel.FamilyStellar)
			if err != nil {
				return nil, nil, err
			}
			selectors = append(selectors, details.ChainSelector)

			var (
				networkPassphrase string
				friendbotURL      string
				sorobanRPCURL     string
			)
			if b.Out.NetworkSpecificData.StellarNetwork != nil {
				networkPassphrase = b.Out.NetworkSpecificData.StellarNetwork.NetworkPassphrase
				friendbotURL = b.Out.NetworkSpecificData.StellarNetwork.FriendbotURL
				sorobanRPCURL = b.Out.Nodes[0].ExternalHTTPUrl
			}

			log.Info().Msgf("Stellar network passphrase: %s", networkPassphrase)
			log.Info().Msgf("Stellar friendbot URL: %s", friendbotURL)
			log.Info().Msgf("Stellar Soroban RPC URL: %s", sorobanRPCURL)

			// TODO: implement Stellar CLDF provider
			// p, err := stellar.NewRPCChainProvider(details.ChainSelector, stellar.RPCChainProviderConfig{
			// 	NetworkPassphrase: networkPassphrase,
			// 	FriendbotURL:      friendbotURL,
			// 	SorobanRPCURL:     sorobanRPCURL,
			// }).Initialize(context.Background())
			//
			// if err != nil {
			// 	return nil, nil, err
			// }
			//
			// providers = append(providers, p)
		default:
			return nil, nil, fmt.Errorf("unsupported blockchain family: %s", b.Out.Family)
		}
	}

	blockchains := cldf_chain.NewBlockChainsFromSlice(providers)

	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create logger: %w", err)
	}

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
