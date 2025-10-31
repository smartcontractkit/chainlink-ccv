package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const (
	CommonCLNodesConfig = `
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
			ListenAddresses = ['0.0.0.0:6690']
`
)

type Cfg struct {
	CLDF               CLDF                        `toml:"cldf"                  validate:"required"`
	Fake               *services.FakeInput         `toml:"fake"                  validate:"required"`
	Verifier           []*services.VerifierInput   `toml:"verifier"              validate:"required"`
	Executor           *services.ExecutorInput     `toml:"executor"              validate:"required"`
	Indexer            *services.IndexerInput      `toml:"indexer"               validate:"required"`
	Aggregator         []*services.AggregatorInput `toml:"aggregator"            validate:"required"`
	Blockchains        []*blockchain.Input         `toml:"blockchains"           validate:"required"`
	NodeSets           []*ns.Input                 `toml:"nodesets"              validate:"required"`
	CLNodesFundingETH  float64                     `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64                     `toml:"cl_nodes_funding_link"`
}

func checkKeys(in *Cfg) error {
	if getNetworkPrivateKey() != DefaultAnvilKey && in.Blockchains[0].ChainID == "1337" && in.Blockchains[1].ChainID == "2337" {
		return errors.New("you are trying to run simulated chains with a key that do not belong to Anvil, please run 'unset PRIVATE_KEY'")
	}
	if getNetworkPrivateKey() == DefaultAnvilKey && in.Blockchains[0].ChainID != "1337" && in.Blockchains[1].ChainID != "2337" {
		return errors.New("you are trying to run on real networks but is not using the Anvil private key, export your private key 'export PRIVATE_KEY=...'")
	}
	return nil
}

func NewProductConfigurationFromNetwork(typ string) (cciptestinterfaces.CCIP17ProductConfiguration, error) {
	switch typ {
	case "anvil":
		return &ccvEvm.CCIP17EVM{}, nil
	case "canton":
		// see devenv-evm implementation and add Canton
		return nil, nil
	default:
		return nil, errors.New("unknown devenv network type " + typ)
	}
}

// NewEnvironment creates a new CCIP CCV environment either locally in Docker or remotely in K8s.
func NewEnvironment() (in *Cfg, err error) {
	ctx := context.Background()
	timeTrack := NewTimeTracker(Plog)

	// track environment startup result and time using getDX app
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, timeTrack.SinceStart().Seconds())
	}()

	ctx = L.WithContext(ctx)
	if err = framework.DefaultNetwork(nil); err != nil {
		return nil, err
	}

	in, err = Load[Cfg](strings.Split(os.Getenv(EnvVarTestConfigs), ","))
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	if err = checkKeys(in); err != nil {
		return nil, err
	}

	_, err = services.NewFake(in.Fake)
	if err != nil {
		return nil, fmt.Errorf("failed to create fake data provider: %w", err)
	}

	impls := make([]cciptestinterfaces.CCIP17ProductConfiguration, 0)
	for _, bc := range in.Blockchains {
		var impl cciptestinterfaces.CCIP17ProductConfiguration
		impl, err = NewProductConfigurationFromNetwork(bc.Type)
		if err != nil {
			return nil, err
		}
		impls = append(impls, impl)
	}
	for i, impl := range impls {
		_, err = impl.DeployLocalNetwork(ctx, in.Blockchains[i])
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local networks: %w", err)
		}
	}

	_, err = services.NewIndexer(in.Indexer)
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer service: %w", err)
	}

	for _, aggregatorInput := range in.Aggregator {
		_, err = services.NewAggregator(aggregatorInput)
		if err != nil {
			return nil, fmt.Errorf("failed to create aggregator service for committee %s: %w", aggregatorInput.CommitteeName, err)
		}
	}

	timeTrack.Record("[infra] deploying blockchains")

	clChainConfigs := make([]string, 0)
	clChainConfigs = append(clChainConfigs, CommonCLNodesConfig)
	for i, impl := range impls {
		var clChainConfig string
		clChainConfig, err = impl.ConfigureNodes(ctx, in.Blockchains[i])
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local networks: %w", err)
		}
		clChainConfigs = append(clChainConfigs, clChainConfig)
	}
	allConfigs := strings.Join(clChainConfigs, "\n")
	for _, nodeSpec := range in.NodeSets[0].NodeSpecs {
		nodeSpec.Node.TestConfigOverrides = allConfigs
	}
	Plog.Info().Msg("Nodes network configuration is generated")

	timeTrack.Record("[changeset] configured nodes network")
	_, err = ns.NewSharedDBNodeSet(in.NodeSets[0], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new shared db node set: %w", err)
	}

	var selectors []uint64
	var e *deployment.Environment
	// the CLDF datastore is not initialized at this point because contracts are not deployed yet.
	// it will get populated in the loop below.
	in.CLDF.Init()
	selectors, e, err = NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}

	// Check if contracts are pre-deployed (addresses already in config)
	hasPreDeployedContracts := len(in.CLDF.Addresses) > 0
	if hasPreDeployedContracts {
		L.Info().Int("AddressSets", len(in.CLDF.Addresses)).Msg("Using pre-deployed contracts from configuration, skipping deployment")
	} else {
		L.Info().Any("Selectors", selectors).Msg("Deploying contracts for chain selectors")
	}

	ds := datastore.NewMemoryDataStore()
	for i, impl := range impls {
		if err = impl.FundNodes(ctx, in.NodeSets, in.Blockchains[i], big.NewInt(1), big.NewInt(5)); err != nil {
			return nil, err
		}
		var networkInfo chainsel.ChainDetails
		networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, err
		}
		L.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deployed chain selector")

		// Only deploy contracts if not pre-deployed
		if !hasPreDeployedContracts {
			var dsi datastore.DataStore
			dsi, err = impl.DeployContractsForSelector(ctx, e, networkInfo.ChainSelector)
			if err != nil {
				return nil, err
			}
			var addresses []datastore.AddressRef
			addresses, err = dsi.Addresses().Fetch()
			if err != nil {
				return nil, err
			}
			var a []byte
			a, err = json.Marshal(addresses)
			if err != nil {
				return nil, err
			}
			in.CLDF.AddAddresses(string(a))
			if err = ds.Merge(dsi); err != nil {
				return nil, err
			}
		}
	}

	// Load pre-deployed addresses into datastore if they exist
	if hasPreDeployedContracts {
		for _, addrRefJSON := range in.CLDF.Addresses {
			var addrs []datastore.AddressRef
			if err := json.Unmarshal([]byte(addrRefJSON), &addrs); err != nil {
				return nil, fmt.Errorf("failed to unmarshal pre-deployed addresses from config: %w", err)
			}
			for _, addr := range addrs {
				if err := ds.Addresses().Add(addr); err != nil {
					return nil, fmt.Errorf("failed to add pre-deployed address to datastore: %w", err)
				}
			}
		}
	}

	e.DataStore = ds.Seal()

	// Only connect contracts if we deployed them (skip for pre-deployed)
	if !hasPreDeployedContracts {
		for i, impl := range impls {
			var networkInfo chainsel.ChainDetails
			networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, chainsel.FamilyEVM)
			if err != nil {
				return nil, err
			}
			selsToConnect := make([]uint64, 0)
			for _, sel := range selectors {
				if sel != networkInfo.ChainSelector {
					selsToConnect = append(selsToConnect, sel)
				}
			}
			err = impl.ConnectContractsWithSelectors(ctx, e, networkInfo.ChainSelector, selsToConnect)
			if err != nil {
				return nil, err
			}
		}
	}

	timeTrack.Record("[infra] deployed CL nodes")
	timeTrack.Record("[changeset] deployed product contracts")

	_, err = services.NewExecutor(in.Executor)
	if err != nil {
		return nil, fmt.Errorf("failed to create executor service: %w", err)
	}

	for _, ver := range in.Verifier {
		ver.ConfigFilePath = fmt.Sprintf("/app/cmd/verifier/testconfig/%s/verifier-%d.toml", ver.CommitteeName, ver.NodeIndex+1)
		ver.SigningKey = cciptestinterfaces.XXXNewVerifierPrivateKey(ver.CommitteeName, ver.NodeIndex)
		_, err = services.NewVerifier(ver)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier service: %w", err)
		}
	}

	Plog.Info().Str("BootstrapNode", in.NodeSets[0].Out.CLNodes[0].Node.ExternalURL).Send()
	for _, n := range in.NodeSets[0].Out.CLNodes[1:] {
		Plog.Info().Str("Node", n.Node.ExternalURL).Send()
	}

	timeTrack.Print()
	if err = PrintCLDFAddresses(in); err != nil {
		return nil, err
	}

	return in, Store(in)
}
