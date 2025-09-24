package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"

	chainsel "github.com/smartcontractkit/chain-selectors"
	devenv_common "github.com/smartcontractkit/chainlink-ccv/devenv-common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"

	evmImpl "github.com/smartcontractkit/chainlink-ccv/devenv-evm"
)

type Cfg struct {
	CCV         *CCV                      `toml:"ccv"         validate:"required"`
	Fake        *services.FakeInput       `toml:"fake"        validate:"required"`
	Verifier    []*services.VerifierInput `toml:"verifier"    validate:"required"`
	Executor    *services.ExecutorInput   `toml:"executor"    validate:"required"`
	Indexer     *services.IndexerInput    `toml:"indexer"     validate:"required"`
	Aggregator  *services.AggregatorInput `toml:"aggregator"  validate:"required"`
	Blockchains []*blockchain.Input       `toml:"blockchains" validate:"required"`
	NodeSets    []*ns.Input               `toml:"nodesets"    validate:"required"`
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

func NewDevenvNetwork(typ string) (devenv_common.CCIP17Configuration, error) {
	switch typ {
	case "anvil":
		return &evmImpl.EVMDevenvNetwork{}, nil
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

	_, err = services.NewFake(in.Fake)
	if err != nil {
		return nil, fmt.Errorf("failed to create fake data provider: %w", err)
	}

	impls := make([]devenv_common.CCIP17Configuration, 0)
	for _, bc := range in.Blockchains {
		impl, err := NewDevenvNetwork(bc.Type)
		if err != nil {
			return nil, err
		}
		impls = append(impls, impl)
	}
	for i, impl := range impls {
		_, err := impl.DeployLocalNetwork(ctx, in.Blockchains[i])
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local networks: %w", err)
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
	clChainConfigs = append(clChainConfigs, CommonCLNodeConfig())
	for i, impl := range impls {
		clChainConfig, err := impl.ConfigureNodes(ctx, in.Blockchains[i])
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

	track.Record("[changeset] configured nodes network")
	_, err = ns.NewSharedDBNodeSet(in.NodeSets[0], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new shared db node set: %w", err)
	}

	in.CCV.AddressesMu = &sync.Mutex{}
	selectors, e, err := NewCLDFOperationsEnvironment(in.Blockchains)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	L.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")

	ds := datastore.NewMemoryDataStore()
	for i, impl := range impls {
		if err := impl.FundNodes(ctx, in.NodeSets, in.Blockchains[i], big.NewInt(1), big.NewInt(5)); err != nil {
			return nil, err
		}
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, err
		}
		L.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deployed chain selector")
		dsi, err := impl.DeployContractsForSelector(ctx, e, networkInfo.ChainSelector)
		if err != nil {
			return nil, err
		}
		addresses, err := dsi.Addresses().Fetch()
		if err != nil {
			return nil, err
		}
		in.CCV.AddressesMu.Lock()
		a, err := json.Marshal(addresses)
		if err != nil {
			return nil, err
		}
		in.CCV.Addresses = append(in.CCV.Addresses, string(a))
		in.CCV.AddressesMu.Unlock()
		if err := ds.Merge(dsi); err != nil {
			return nil, err
		}
	}
	e.DataStore = ds.Seal()

	for i, impl := range impls {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, chainsel.FamilyEVM)
		if err != nil {
			return nil, err
		}
		selsToConnect := make([]uint64, 0)
		for _, sel := range selectors {
			if sel != networkInfo.ChainSelector {
				selsToConnect = append(selsToConnect, sel)
			}
		}
		err = impl.ConnectContractsWithSelector(ctx, e, networkInfo.ChainSelector, selsToConnect)
		if err != nil {
			return nil, err
		}
	}

	track.Record("[infra] deployed CL nodes")
	//if err := DefaultProductConfiguration(in); err != nil {
	//	return nil, fmt.Errorf("failed to setup default CLDF orchestration: %w", err)
	//}
	track.Record("[changeset] deployed product contracts")

	_, err = services.NewExecutor(in.Executor)
	if err != nil {
		return nil, fmt.Errorf("failed to create executor service: %w", err)
	}

	for i, ver := range in.Verifier {
		ver.ConfigFilePath = fmt.Sprintf("/app/verifier-%d.toml", i+1)
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
	return in, Store[Cfg](in)
}
