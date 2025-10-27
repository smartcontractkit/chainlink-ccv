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
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

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
	CLDF               CLDF                      `toml:"cldf"                  validate:"required"`
	Fake               *services.FakeInput       `toml:"fake"                  validate:"required"`
	Verifier           []*services.VerifierInput `toml:"verifier"              validate:"required"`
	Executor           *services.ExecutorInput   `toml:"executor"              validate:"required"`
	Indexer            *services.IndexerInput    `toml:"indexer"               validate:"required"`
	Aggregator         *services.AggregatorInput `toml:"aggregator"            validate:"required"`
	Blockchains        []*blockchain.Input       `toml:"blockchains"           validate:"required"`
	VirtualSelectors   []*VirtualSelector        `toml:"virtual_selectors"`
	NodeSets           []*ns.Input               `toml:"nodesets"              validate:"required"`
	CLNodesFundingETH  float64                   `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64                   `toml:"cl_nodes_funding_link"`
}

func (c *Cfg) ValidateVirtualSelectors() error {
	if len(c.VirtualSelectors) == 0 {
		return fmt.Errorf("no virtual selectors configured")
	}

	bcMap := make(map[string]bool)
	for _, bc := range c.Blockchains {
		bcMap[bc.ContainerName] = true
	}

	for _, vs := range c.VirtualSelectors {
		if vs.PhysicalChain == "" {
			return fmt.Errorf("virtual selector %d missing physical_chain", uint64(vs.Selector))
		}
		if !bcMap[vs.PhysicalChain] {
			return fmt.Errorf("virtual selector %d references unknown physical_chain: %s",
				uint64(vs.Selector), vs.PhysicalChain)
		}
	}
	return nil
}

func checkKeys(in *Cfg) error {
	// Updated validation for single blockchain with virtual selectors
	if len(in.Blockchains) > 0 {
		if getNetworkPrivateKey() != DefaultAnvilKey && in.Blockchains[0].ChainID == "1337" {
			return errors.New("you are trying to run simulated chains with a key that do not belong to Anvil, please run 'unset PRIVATE_KEY'")
		}
		if getNetworkPrivateKey() == DefaultAnvilKey && in.Blockchains[0].ChainID != "1337" {
			return errors.New("you are trying to run on real networks but is not using the Anvil private key, export your private key 'export PRIVATE_KEY=...'")
		}
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
func NewEnvironment() (*Cfg, error) {
	ctx := context.Background()
	track := NewTimeTracker(Plog)
	ctx = L.WithContext(ctx)
	if err := framework.DefaultNetwork(nil); err != nil {
		return nil, err
	}

	in, err := Load[Cfg](strings.Split(os.Getenv(EnvVarTestConfigs), ","))
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	if err := checkKeys(in); err != nil {
		return nil, err
	}

	if err := in.ValidateVirtualSelectors(); err != nil {
		return nil, fmt.Errorf("invalid virtual selectors: %w", err)
	}

	_, err = services.NewFake(in.Fake)
	if err != nil {
		return nil, fmt.Errorf("failed to create fake data provider: %w", err)
	}

	impl, err := NewProductConfigurationFromNetwork(in.Blockchains[0].Type)
	if err != nil {
		return nil, err
	}

	for _, bc := range in.Blockchains {
		_, err = impl.DeployLocalNetwork(ctx, bc)
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local network %s: %w", bc.ContainerName, err)
		}
	}

	_, err = services.NewIndexer(in.Indexer)
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer service: %w", err)
	}

	_, err = services.NewAggregator(in.Aggregator)
	if err != nil {
		return nil, fmt.Errorf("failed to create aggregator service: %w", err)
	}

	track.Record("[infra] deploying blockchains")

	clChainConfigs := make([]string, 0)
	clChainConfigs = append(clChainConfigs, CommonCLNodesConfig)

	for _, bc := range in.Blockchains {
		clChainConfig, err := impl.ConfigureNodes(ctx, bc)
		if err != nil {
			return nil, fmt.Errorf("failed to configure nodes for %s: %w", bc.ContainerName, err)
		}
		clChainConfigs = append(clChainConfigs, clChainConfig)
	}

	allConfigs := strings.Join(clChainConfigs, "\n")
	for _, nodeSpec := range in.NodeSets[0].NodeSpecs {
		nodeSpec.Node.TestConfigOverrides = allConfigs
	}
	Plog.Info().Msg("Nodes network configuration is generated")

	track.Record("[changeset] configured nodes network")
	_, err = ns.NewSharedDBNodeSet(in.NodeSets[0], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new shared db node set: %w", err)
	}

	in.CLDF.Init()

	selectors, e, _, err := NewCLDFOperationsEnvironment(
		in.Blockchains,
		in.VirtualSelectors,
		in.CLDF.DataStore,
	)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	Plog.Info().Int("VirtualSelectors", len(in.VirtualSelectors)).Msg("Deploying for virtual chain selectors")

	blockchainsByName := make(map[string]*blockchain.Input)
	for i := range in.Blockchains {
		blockchainsByName[in.Blockchains[i].ContainerName] = in.Blockchains[i]
	}

	fundedChains := make(map[string]bool)
	for _, vs := range in.VirtualSelectors {
		if !fundedChains[vs.PhysicalChain] {
			bc := blockchainsByName[vs.PhysicalChain]
			if err := impl.FundNodes(ctx, in.NodeSets, bc, big.NewInt(1), big.NewInt(5)); err != nil {
				return nil, fmt.Errorf("failed to fund nodes for %s: %w", vs.PhysicalChain, err)
			}
			fundedChains[vs.PhysicalChain] = true
		}
	}

	// Deploy contracts for each virtual selector to the same physical chain
	ds := datastore.NewMemoryDataStore()
	for _, selector := range selectors {
		L.Info().Uint64("VirtualSelector", selector).Msg("Deploying contracts for virtual selector")
		dsi, err := impl.DeployContractsForSelector(ctx, e, selector)
		if err != nil {
			return nil, fmt.Errorf("failed to deploy for selector %d: %w", selector, err)
		}
		addresses, err := dsi.Addresses().Fetch()
		if err != nil {
			return nil, err
		}
		a, err := json.Marshal(addresses)
		if err != nil {
			return nil, err
		}
		in.CLDF.AddAddresses(string(a))
		if err := ds.Merge(dsi); err != nil {
			return nil, err
		}
	}
	e.DataStore = ds.Seal()

	// Connect all virtual selectors to each other
	for i, fromSelector := range selectors {
		selsToConnect := make([]uint64, 0)
		for j, toSelector := range selectors {
			if i != j {
				selsToConnect = append(selsToConnect, toSelector)
			}
		}
		L.Info().
			Uint64("FromSelector", fromSelector).
			Any("ToSelectors", selsToConnect).
			Msg("Connecting virtual selectors")
		err = impl.ConnectContractsWithSelectors(ctx, e, fromSelector, selsToConnect)
		if err != nil {
			return nil, err
		}
	}

	track.Record("[infra] deployed CL nodes")
	track.Record("[changeset] deployed product contracts")

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

	track.Print()
	if err := PrintCLDFAddresses(in); err != nil {
		return nil, err
	}
	return in, Store(in)
}
