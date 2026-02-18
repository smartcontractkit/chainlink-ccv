package ccv

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	adminv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/admin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/canton/provider/authentication"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider/rpcclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_canton_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/canton/provider"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
	cldf_stellar_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/stellar/provider"
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

			providerConfig := cldf_canton_provider.RPCChainProviderConfig{
				Participants: make([]cldf_canton_provider.ParticipantConfig, len(b.Out.NetworkSpecificData.CantonEndpoints.Participants)),
			}

			for i, config := range b.Out.NetworkSpecificData.CantonEndpoints.Participants {
				authProvider := authentication.NewInsecureStaticProvider(config.JWT)
				// Get Primary Party for user
				ledgerApiConn, err := grpc.NewClient(
					config.GRPCLedgerAPIURL,
					grpc.WithTransportCredentials(authProvider.TransportCredentials()),
					grpc.WithPerRPCCredentials(authProvider.PerRPCCredentials()),
				)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to create gRPC connection to Ledger API for Canton participant %d: %w", i+1, err)
				}
				userResp, err := adminv2.NewUserManagementServiceClient(ledgerApiConn).GetUser(context.Background(), &adminv2.GetUserRequest{UserId: config.UserID})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to get user info for user %s for Canton participant %d: %w", config.UserID, i+1, err)
				}
				party := userResp.GetUser().GetPrimaryParty()
				if party == "" {
					return nil, nil, fmt.Errorf("no primary party found for user %s for Canton participant %d", config.UserID, i+1)
				}
				lggr.Debugw("No party specified for Canton participant, using primary party of the user", "user", config.UserID, "party", party, "participantIndex", i)
				_ = ledgerApiConn.Close()

				providerConfig.Participants[i] = cldf_canton_provider.ParticipantConfig{
					JSONLedgerAPIURL: config.JSONLedgerAPIURL,
					GRPCLedgerAPIURL: config.GRPCLedgerAPIURL,
					AdminAPIURL:      config.AdminAPIURL,
					ValidatorAPIURL:  config.ValidatorAPIURL,
					UserID:           config.UserID,
					PartyID:          party,
					AuthProvider:     authProvider,
				}
			}
			p, err := cldf_canton_provider.NewRPCChainProvider(d.ChainSelector, providerConfig).Initialize(context.TODO())
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
				networkPassphrase  string
				friendbotURL       string
				sorobanRPCURL      string
				deployerKeypairGen cldf_stellar_provider.KeypairGenerator
			)
			if b.Out.NetworkSpecificData.StellarNetwork != nil {
				networkPassphrase = b.Out.NetworkSpecificData.StellarNetwork.NetworkPassphrase
				friendbotURL = b.Out.NetworkSpecificData.StellarNetwork.FriendbotURL
				sorobanRPCURL = b.Out.Nodes[0].ExternalHTTPUrl
				deployerKeypairGen = cldf_stellar_provider.KeypairFromHex(os.Getenv("STELLAR_DEPLOYER_PRIVATE_KEY"))
			} else {
				return nil, nil, fmt.Errorf("Stellar network specific data is required")
			}

			log.Info().Msgf("Stellar network passphrase: %s", networkPassphrase)
			log.Info().Msgf("Stellar friendbot URL: %s", friendbotURL)
			log.Info().Msgf("Stellar Soroban RPC URL: %s", sorobanRPCURL)
			deployerKeypair, err := deployerKeypairGen.Generate()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate deployer keypair: %w", err)
			}
			log.Info().Msgf("Stellar deployer keypair: %s", deployerKeypair.Address())

			p, err := cldf_stellar_provider.NewRPCChainProvider(details.ChainSelector, cldf_stellar_provider.RPCChainProviderConfig{
				NetworkPassphrase:  networkPassphrase,
				FriendbotURL:       friendbotURL,
				SorobanRPCURL:      sorobanRPCURL,
				DeployerKeypairGen: deployerKeypairGen,
			}).Initialize(context.Background())

			if err != nil {
				return nil, nil, err
			}

			providers = append(providers, p)
		default:
			return nil, nil, fmt.Errorf("unsupported blockchain family: %s", b.Out.Family)
		}
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
