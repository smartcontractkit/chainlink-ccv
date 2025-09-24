package ccv

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/commit_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_evm_provider "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/provider"
)

var Plog = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel).With().Fields(map[string]any{"component": "ccv"}).Logger()

type CCV struct {
	EAFake              *EAFake       `toml:"ea_fake"`
	Jobs                *Jobs         `toml:"jobs"`
	LinkContractAddress string        `toml:"link_contract_address"`
	CLNodesFundingETH   float64       `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink  float64       `toml:"cl_nodes_funding_link"`
	ChainFinalityDepth  int64         `toml:"chain_finality_depth"`
	VerificationTimeout time.Duration `toml:"verification_timeout"`
	Verify              bool          `toml:"verify"`

	// Contracts (CLDF)
	AddressesMu *sync.Mutex         `toml:"-"`
	Addresses   []string            `toml:"addresses"`
	DataStore   datastore.DataStore `toml:"-"`

	// These are the settings for CLDF missing functionality we cover with ETHClient, we should remove them later
	GasSettings *GasSettings `toml:"gas_settings"`
}

type DeployedContracts struct {
	// your deployed contract structs here with `toml:''` tags
}

type GasSettings struct {
	FeeCapMultiplier int64 `toml:"fee_cap_multiplier"`
	TipCapMultiplier int64 `toml:"tip_cap_multiplier"`
}

type Jobs struct {
	ConfigPollIntervalSeconds time.Duration `toml:"config_poll_interval_sec"` //nolint:staticcheck
	MaxTaskDurationSec        time.Duration `toml:"max_task_duration_sec"`    //nolint:staticcheck
}

type EAFake struct {
	LowValue  int64 `toml:"low_value"`
	HighValue int64 `toml:"high_value"`
}

func NewCLDFOperationsEnvironment(bc []*blockchain.Input) ([]uint64, *deployment.Environment, error) {
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
				RPCs: []deployment.RPC{
					{
						Name:               "default",
						WSURL:              rpcWSURL,
						HTTPURL:            rpcHTTPURL,
						PreferredURLScheme: deployment.URLSchemePreferenceHTTP,
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
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
	return selectors, &e, nil
}

// deployCommitVerifierForSelector deploys a new verifier to the given chain selector.
func deployCommitVerifierForSelector(
	e *deployment.Environment,
	selector uint64,
	onRampConstructorArgs commit_onramp.ConstructorArgs,
	offRampConstructorArgs commit_offramp.ConstructorArgs,
	signatureConfigArgs commit_offramp.SignatureConfigArgs,
) (onRamp, offRamp datastore.AddressRef, err error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		err = fmt.Errorf("no EVM chain found for selector %d", selector)
		return onRamp, offRamp, err
	}
	commitOnRampReport, err := operations.ExecuteOperation(e.OperationsBundle, commit_onramp.Deploy, chain, contract.DeployInput[commit_onramp.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          onRampConstructorArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to deploy CommitOnRamp: %w", err)
		return onRamp, offRamp, err
	}
	commitOffRampReport, err := operations.ExecuteOperation(e.OperationsBundle, commit_offramp.Deploy, chain, contract.DeployInput[commit_offramp.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          offRampConstructorArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to deploy CommitOnRamp: %w", err)
		return onRamp, offRamp, err
	}
	_, err = operations.ExecuteOperation(e.OperationsBundle, commit_offramp.SetSignatureConfigs, chain, contract.FunctionInput[commit_offramp.SignatureConfigArgs]{
		Address:       common.HexToAddress(commitOffRampReport.Output.Address),
		ChainSelector: chain.Selector,
		Args:          signatureConfigArgs,
	})
	if err != nil {
		err = fmt.Errorf("failed to set CommitOffRamp signature config: %w", err)
		return onRamp, offRamp, err
	}
	onRamp = commitOnRampReport.Output
	offRamp = commitOffRampReport.Output
	return onRamp, offRamp, err
}

// configureVerifierOnSelectorForLanes configures an existing verifier on the given chain selector for the given lanes.
func configureCommitVerifierOnSelectorForLanes(e *deployment.Environment, selector uint64, commitOnRamp common.Address, destConfigArgs []commit_onramp.DestChainConfigArgs) error {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return fmt.Errorf("no EVM chain found for selector %d", selector)
	}

	_, err := operations.ExecuteOperation(e.OperationsBundle, commit_onramp.ApplyDestChainConfigUpdates, chain, contract.FunctionInput[[]commit_onramp.DestChainConfigArgs]{
		ChainSelector: chain.Selector,
		Address:       commitOnRamp,
		Args:          destConfigArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to apply dest chain config updates to CommitOnRamp(%s) on chain %s: %w", commitOnRamp, chain, err)
	}

	return nil
}

// deployReceiverForSelector deploys a new mock receiver to the given chain selector.
func deployReceiverForSelector(e *deployment.Environment, selector uint64, args mock_receiver.ConstructorArgs) (datastore.AddressRef, error) {
	chain, ok := e.BlockChains.EVMChains()[selector]
	if !ok {
		return datastore.AddressRef{}, fmt.Errorf("no EVM chain found for selector %d", selector)
	}
	report, err := operations.ExecuteOperation(e.OperationsBundle, mock_receiver.Deploy, chain, contract.DeployInput[mock_receiver.ConstructorArgs]{
		ChainSelector: chain.Selector,
		Args:          args,
	})
	if err != nil {
		return datastore.AddressRef{}, fmt.Errorf("failed to deploy MockReceiver: %w", err)
	}
	return report.Output, nil
}

// DefaultProductConfiguration is default product configuration that includes:
// - CL nodes config generation
// - On-chain part deployment using CLDF.
//func DefaultProductConfiguration(in *Cfg) error {
//	Plog.Info().Msg("Generating CL nodes config")
//	pkey := getNetworkPrivateKey()
//	if pkey == "" {
//		return fmt.Errorf("PRIVATE_KEY environment variable not set")
//	}
//	//* Funding all CL nodes with ETH *//
//
//	Plog.Info().Msg("Connecting to CL nodes")
//	nodeClients, err := clclient.New(in.NodeSets[0].Out.CLNodes)
//	if err != nil {
//		return fmt.Errorf("connecting to CL nodes: %w", err)
//	}
//	ethKeyAddressesSrc, ethKeyAddressesDst := make([]string, 0), make([]string, 0)
//	for i, nc := range nodeClients {
//		addrSrc, err := nc.ReadPrimaryETHKey(in.Blockchains[0].ChainID)
//		if err != nil {
//			return fmt.Errorf("getting primary ETH key from OCR node %d (src chain): %w", i, err)
//		}
//		ethKeyAddressesSrc = append(ethKeyAddressesSrc, addrSrc.Attributes.Address)
//		addrDst, err := nc.ReadPrimaryETHKey(in.Blockchains[1].ChainID)
//		if err != nil {
//			return fmt.Errorf("getting primary ETH key from OCR node %d (dst chain): %w", i, err)
//		}
//		ethKeyAddressesDst = append(ethKeyAddressesDst, addrDst.Attributes.Address)
//		Plog.Info().
//			Int("Idx", i).
//			Str("ETHKeySrc", addrSrc.Attributes.Address).
//			Str("ETHKeyDst", addrDst.Attributes.Address).
//			Msg("Node info")
//	}
//	clientSrc, _, _, err := ETHClient(in.Blockchains[0].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
//	if err != nil {
//		return fmt.Errorf("could not create basic eth client: %w", err)
//	}
//	clientDst, _, _, err := ETHClient(in.Blockchains[1].Out.Nodes[0].ExternalWSUrl, in.CCV.GasSettings)
//	if err != nil {
//		return fmt.Errorf("could not create basic eth client: %w", err)
//	}
//	for _, addr := range ethKeyAddressesSrc {
//		if err := FundNodeEIP1559(clientSrc, pkey, addr, in.CCV.CLNodesFundingETH); err != nil {
//			return fmt.Errorf("failed to fund CL nodes on src chain: %w", err)
//		}
//	}
//	for _, addr := range ethKeyAddressesDst {
//		if err := FundNodeEIP1559(clientDst, pkey, addr, in.CCV.CLNodesFundingETH); err != nil {
//			return fmt.Errorf("failed to fund CL nodes on dst chain: %w", err)
//		}
//	}
//
//	// * Configuring src and dst contracts * //
//	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
//	if err != nil {
//		return fmt.Errorf("creating CLDF operations environment: %w", err)
//	}
//	L.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")
//	eg := &errgroup.Group{}
//	in.CCV.AddressesMu = &sync.Mutex{}
//	runningDS := datastore.NewMemoryDataStore()
//	for _, sel := range selectors {
//		eg.Go(func() error {
//			ds, err := deployContractsForSelector(in, e, sel)
//			if err != nil {
//				return fmt.Errorf("could not configure contracts for chain selector %d: %w", sel, err)
//			}
//			return runningDS.Merge(ds)
//		})
//	}
//	if err := eg.Wait(); err != nil {
//		return err
//	}
//	e.DataStore = runningDS.Seal()
//	for _, sel := range selectors {
//		eg.Go(func() error {
//			remoteSelectors := make([]uint64, 0, len(selectors)-1)
//			for _, s := range selectors {
//				if s != sel {
//					remoteSelectors = append(remoteSelectors, s)
//				}
//			}
//			err = configureContractsOnSelectorForLanes(e, sel, remoteSelectors)
//			if err != nil {
//				return fmt.Errorf("could not configure contracts on chain selector %d for lanes: %w", sel, err)
//			}
//			return nil
//		})
//	}
//	if err := eg.Wait(); err != nil {
//		return err
//	}
//
//	Plog.Info().Str("BootstrapNode", in.NodeSets[0].Out.CLNodes[0].Node.ExternalURL).Send()
//	for _, n := range in.NodeSets[0].Out.CLNodes[1:] {
//		Plog.Info().Str("Node", n.Node.ExternalURL).Send()
//	}
//	return nil
//}

func CommonCLNodeConfig() string {
	return `
       [Log]
       JSONConsole = true
       Level = 'debug'
       [Pyroscope]
       ServerAddress = 'http://host.docker.internal:4040'
       Environment = 'local'
       [WebServer]
       SessionTimeout = '999h0m0s'
       HTTPWriteTimeout = '3m'
       SecureCookies = false
       HTTPPort = 6688
       [WebServer.TLS]
       HTTPSPort = 0
       [WebServer.RateLimit]
       Authenticated = 5000
       Unauthenticated = 5000
       [JobPipeline]
       [JobPipeline.HTTPRequest]
       DefaultTimeout = '1m'
       [Log.File]
       MaxSize = '0b'
       [Feature]
       FeedsManager = true
       LogPoller = true
       UICSAKeys = true
       [OCR2]
       Enabled = true
       SimulateTransactions = false
       DefaultTransactionQueueDepth = 1
       [P2P.V2]
       Enabled = true
       ListenAddresses = ['0.0.0.0:6690']`
}
