// Package chainlinknode is the phased-runtime component that brings up
// Chainlink node containers as blank templates loaded with per-chain TOML
// produced by each blockchain's OffChainConfigurable.
//
// The component depends only on the blockchains Phase 1 output. It does not
// generate keys, register with JD, inject aggregator HMAC secrets, or fund
// nodes — those steps live in environment_phased.go and will eventually be
// driven by the CL node API + JD in later refactors.
package chainlinknode

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const (
	configKey      = "nodesets"
	blockchainsKey = "blockchains"
	outputsKey     = "nodesets"

	// commonCLNodesConfig is the chain-agnostic TOML preamble injected into
	// every CL node spec. Each blockchain's OffChainConfigurable.ConfigureNodes
	// appends its own per-chain section on top.
	commonCLNodesConfig = `
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
)

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("chainlinknode component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

// ValidateConfig decodes the raw [[nodesets]] config and ensures at least
// one nodeset is declared. No service-presence checks (no hasAService).
func (c *component) ValidateConfig(componentConfig any) error {
	nss, err := decode(componentConfig)
	if err != nil {
		return err
	}
	if len(nss) == 0 {
		return errors.New("no [[nodesets]] entries declared in config")
	}
	return nil
}

// RunPhase2 creates Chainlink node containers loaded with each blockchain's
// per-chain TOML config. Inputs:
//
//   - componentConfig: raw [[nodesets]] TOML map.
//   - priorOutputs["blockchains"]: []*blockchain.Input deployed in Phase 1
//     (with .Out populated).
//
// Output: "nodesets" -> []*ns.Input (same slice, with .Out populated by the
// node-set framework). Callers that splice this back into a *Cfg must use
// the same pointer slice so downstream mutations propagate.
func (c *component) RunPhase2(
	ctx context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, error) {
	nss, err := decode(componentConfig)
	if err != nil {
		return nil, err
	}

	bcs, ok := priorOutputs[blockchainsKey].([]*blockchain.Input)
	if !ok {
		return nil, fmt.Errorf("chainlinknode: phase 1 did not produce []*blockchain.Input under %q", blockchainsKey)
	}
	if len(bcs) == 0 {
		return nil, errors.New("chainlinknode: no blockchains available from phase 1")
	}

	fragments := make([]string, 0, len(bcs)+1)
	fragments = append(fragments, commonCLNodesConfig)
	for i, bc := range bcs {
		if bc.Out == nil {
			return nil, fmt.Errorf("chainlinknode: blockchain[%d] %q has no phase 1 output", i, bc.ContainerName)
		}
		family, err := blockchain.TypeToFamily(bc.Type)
		if err != nil {
			return nil, fmt.Errorf("chainlinknode: resolving family for blockchain[%d] type %q: %w", i, bc.Type, err)
		}
		fac, err := chainimpl.GetImplFactory(string(family))
		if err != nil {
			return nil, fmt.Errorf("chainlinknode: impl factory for family %q: %w", string(family), err)
		}
		frag, err := fac.NewEmpty().ConfigureNodes(ctx, bc)
		if err != nil {
			return nil, fmt.Errorf("chainlinknode: ConfigureNodes for blockchain[%d] %q: %w", i, bc.ContainerName, err)
		}
		fragments = append(fragments, frag)
	}
	allConfigs := strings.Join(fragments, "\n")

	for _, nodeSet := range nss {
		for _, nodeSpec := range nodeSet.NodeSpecs {
			nodeSpec.Node.TestConfigOverrides = allConfigs
		}
	}

	for _, nodeset := range nss {
		if _, err := ns.NewSharedDBNodeSet(nodeset, nil); err != nil {
			return nil, fmt.Errorf("chainlinknode: NewSharedDBNodeSet for %q: %w", nodeset.Name, err)
		}
	}

	return map[string]any{outputsKey: nss}, nil
}

// decode round-trips the raw TOML map[string]any into []*ns.Input by
// re-encoding through go-toml. The runtime hands components their config as
// the untyped value parsed by loadRaw, so we re-encode and decode into the
// framework's typed struct.
func decode(raw any) ([]*ns.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"nodesets"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding nodesets config: %w", err)
	}
	var wrapper struct {
		V []*ns.Input `toml:"nodesets"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding nodesets config: %w", err)
	}
	return wrapper.V, nil
}
