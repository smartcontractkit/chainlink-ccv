// Package clnode is the phased-devenv component for Chainlink-node ("CL node")
// support (issue 16).
//
// NOTE: This is a STEP-1 THROWAWAY PROTOTYPE. It launches + funds CL nodes
// directly in Phase 2 purely to prove that nodeset launch works inside the
// phased runtime. The agreed final design is different: clnode becomes a
// config-vehicle component that only decodes its config and publishes it as
// the "_clnode" output key, and the committeeccv component performs the
// secrets-baked launch (CL node secrets are boot-only, so the aggregator HMAC
// creds must be injected before launch, which only committeeccv has). Do not
// build on the launch logic here without revisiting that plan.
package clnode

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const configKey = "clnode"

// Version is the clnode component config schema version. Exactly this version
// is supported; configs declaring any other version are rejected.
const Version = 1

// commonCLNodesConfig is a prototype-local copy of ccv.CommonCLNodesConfig.
// The ccv package blank-imports every component, so a component cannot import
// it back without a cycle; duplication is acceptable for the throwaway.
const commonCLNodesConfig = `
[Log]
JSONConsole = true
Level = 'info'
[Pyroscope]
ServerAddress = 'http://host.docker.internal:4040'
Environment = 'local'
[WebServer]
SessionTimeout = '999h0m0s'
HTTPWriteTimeout = '3m'
SecureCookies = false
HTTPPort = 6688
AllowOrigins = 'http://localhost:3000'
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

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("clnode component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

// Config is the versioned wrapper around the CL node set definitions. Adding a
// version field is why this is a [clnode] table rather than a bare top-level
// [[nodesets]] array.
type Config struct {
	Version            int         `toml:"version"`
	CLNodesFundingETH  float64     `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64     `toml:"cl_nodes_funding_link"`
	NodeSets           []*ns.Input `toml:"node_sets"`
}

// decodeConfig round-trips the raw TOML component config into a typed Config
// and verifies its declared version.
func decodeConfig(raw any) (Config, error) {
	b, err := toml.Marshal(raw)
	if err != nil {
		return Config{}, fmt.Errorf("re-encoding clnode config: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("decoding clnode config: %w", err)
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, Version); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decodeConfig(componentConfig)
	return err
}

// RunPhase2 (THROWAWAY) launches and funds the configured CL node sets. It runs
// in Phase 2 because it needs the Phase-1 "blockchains" output for chain config
// and funding. It produces no outputs and emits no effects yet.
func (c *component) RunPhase2(
	ctx context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	cfg, err := decodeConfig(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	if len(cfg.NodeSets) == 0 {
		return map[string]any{}, nil, nil
	}

	blockchains, ok := priorOutputs["blockchains"].([]*ctfblockchain.Input)
	if !ok || len(blockchains) == 0 {
		return nil, nil, fmt.Errorf("clnode: blockchains not found in phase outputs")
	}

	impls := make([]cciptestinterfaces.CCIP17Configuration, 0, len(blockchains))
	for _, bc := range blockchains {
		impl, ierr := chainreg.NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return nil, nil, fmt.Errorf("clnode: impl for %q: %w", bc.Type, ierr)
		}
		impls = append(impls, impl)
	}

	// Assemble the CL node chain-config overrides from each chain impl.
	chainConfigs := []string{commonCLNodesConfig}
	for i, impl := range impls {
		cc, cerr := impl.ConfigureNodes(ctx, blockchains[i])
		if cerr != nil {
			return nil, nil, fmt.Errorf("clnode: ConfigureNodes for %q: %w", blockchains[i].Type, cerr)
		}
		chainConfigs = append(chainConfigs, cc)
	}
	allConfigs := strings.Join(chainConfigs, "\n")
	for _, nodeSet := range cfg.NodeSets {
		for _, nodeSpec := range nodeSet.NodeSpecs {
			nodeSpec.Node.TestConfigOverrides = allConfigs
		}
	}

	// Launch each node set (shared DB per set).
	for _, nodeSet := range cfg.NodeSets {
		if _, nerr := ns.NewSharedDBNodeSet(nodeSet, nil); nerr != nil {
			return nil, nil, fmt.Errorf("clnode: NewSharedDBNodeSet %q: %w", nodeSet.Name, nerr)
		}
	}

	// Fund the nodes on every fundable chain. FundNodes takes (link, native).
	link := toBigUnits(cfg.CLNodesFundingLink, 1)
	native := toBigUnits(cfg.CLNodesFundingETH, 5)
	for i, impl := range impls {
		if ferr := impl.FundNodes(ctx, cfg.NodeSets, blockchains[i], link, native); ferr != nil {
			return nil, nil, fmt.Errorf("clnode: FundNodes on %q: %w", blockchains[i].Type, ferr)
		}
	}

	return map[string]any{}, nil, nil
}

// toBigUnits converts a whole-unit funding amount to *big.Int, falling back to
// def when the configured value is non-positive.
func toBigUnits(v float64, def int64) *big.Int {
	if v <= 0 {
		return big.NewInt(def)
	}
	return big.NewInt(int64(v))
}
