// Package clnode is the phased-devenv component for Chainlink-node ("CL node")
// support (issue 16).
//
// The component itself is a config vehicle: it claims the top-level [clnode]
// config key, decodes the versioned config, and publishes it as the
// runtime-only output key "_clnode". It does NOT launch anything.
//
// The committeeccv component (Phase 3) consumes "_clnode" and drives the
// actual launch via LaunchNodeSets, because CL node secrets are boot-only and
// the aggregator HMAC credentials that must be baked into the node spec before
// launch are owned by committeeccv. Keeping the launch helper here keeps the
// node-launch code beside its config while letting committeeccv sequence it.
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

// OutputKey is the runtime-only output key under which the decoded clnode
// config is published for committeeccv to consume.
const OutputKey = "_clnode"

// Version is the clnode component config schema version. Exactly this version
// is supported; configs declaring any other version are rejected.
const Version = 1

// CommonCLNodesConfig is the base TOML config applied to every CL node. It is a
// copy of ccv.CommonCLNodesConfig; the ccv package blank-imports every
// component, so a component cannot import it back without a cycle.
const CommonCLNodesConfig = `
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

// RunPhase1 decodes the clnode config and publishes it under OutputKey for
// committeeccv (Phase 3) to consume. It launches nothing.
func (c *component) RunPhase1(
	_ context.Context,
	_ map[string]any,
	componentConfig any,
) (map[string]any, []devenvruntime.Effect, error) {
	cfg, err := decodeConfig(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	out := cfg
	return map[string]any{OutputKey: &out}, nil, nil
}

// LaunchNodeSets configures, launches, and funds the CL node sets in cfg using
// the chains in blockchains. It is called by committeeccv during Phase 3.
//
// NOTE: secret injection (TestSecretsOverrides) must happen on the node specs
// before this is called, because CL node secrets are boot-only. Step 1 launches
// without secrets; committeeccv will bake them in a later step.
func LaunchNodeSets(ctx context.Context, cfg *Config, blockchains []*ctfblockchain.Input) error {
	if cfg == nil || len(cfg.NodeSets) == 0 {
		return nil
	}
	if len(blockchains) == 0 {
		return fmt.Errorf("clnode: no blockchains available to configure CL nodes")
	}

	impls := make([]cciptestinterfaces.CCIP17Configuration, 0, len(blockchains))
	for _, bc := range blockchains {
		impl, ierr := chainreg.NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return fmt.Errorf("clnode: impl for %q: %w", bc.Type, ierr)
		}
		impls = append(impls, impl)
	}

	// Assemble the CL node chain-config overrides from each chain impl.
	chainConfigs := []string{CommonCLNodesConfig}
	for i, impl := range impls {
		cc, cerr := impl.ConfigureNodes(ctx, blockchains[i])
		if cerr != nil {
			return fmt.Errorf("clnode: ConfigureNodes for %q: %w", blockchains[i].Type, cerr)
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
			return fmt.Errorf("clnode: NewSharedDBNodeSet %q: %w", nodeSet.Name, nerr)
		}
	}

	// Fund the nodes on every fundable chain. FundNodes takes (link, native).
	link := toBigUnits(cfg.CLNodesFundingLink, 1)
	native := toBigUnits(cfg.CLNodesFundingETH, 5)
	for i, impl := range impls {
		if ferr := impl.FundNodes(ctx, cfg.NodeSets, blockchains[i], link, native); ferr != nil {
			return fmt.Errorf("clnode: FundNodes on %q: %w", blockchains[i].Type, ferr)
		}
	}
	return nil
}

// toBigUnits converts a whole-unit funding amount to *big.Int, falling back to
// def when the configured value is non-positive.
func toBigUnits(v float64, def int64) *big.Int {
	if v <= 0 {
		return big.NewInt(def)
	}
	return big.NewInt(int64(v))
}
