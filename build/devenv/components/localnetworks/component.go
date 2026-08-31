// Package localnetworks owns the [local_networks] section of a phased devenv
// config: the opt-in, chain-family-owned extensions layered on top of the
// blockchains devenv has launched (today, RPC failover proxies).
//
// The work itself runs inside the blockchains component rather than here. The
// phased runtime hides a component's output from its phase siblings, so nothing
// else in phase 1 can see the blockchain outputs these extensions need to
// mutate, and every consumer of a node URL runs in a later phase. This package
// therefore owns the schema and the configure/finalize helpers, and the
// blockchains component calls them at the one point in the run where the
// blockchains are up and no consumer has read them yet.
package localnetworks

import (
	"context"
	"fmt"
	"sort"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	// Key is the top-level config key and the output key this component owns.
	Key = "local_networks"

	// FinalizersKey carries the local network finalizers out of the runtime.
	// The "_" prefix keeps it out of the serialized environment output.
	FinalizersKey = "_local_network_finalizers"

	// VersionKey is the schema version marker inside [local_networks]. It shares
	// the table with the family names, so "version" is not a usable family.
	VersionKey = "version"
)

// Version is the [local_networks] config schema version. Exactly this version
// is supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(Key, factory); err != nil {
		panic(fmt.Sprintf("local networks component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

// component implements no phase interface on purpose; see the package comment.
type component struct{}

// ValidateConfig checks the schema version and that every declared family both
// decodes and has a configurator registered, so a typo in a family name fails
// before any container starts.
func (c *component) ValidateConfig(componentConfig any) error {
	configs, err := Decode(componentConfig)
	if err != nil {
		return err
	}
	families := make([]string, 0, len(configs))
	for family := range configs {
		families = append(families, family)
	}
	sort.Strings(families)
	for _, family := range families {
		reg, err := chainreg.GetRegistry().Get(family)
		if err != nil {
			return fmt.Errorf("family %q: %w", family, err)
		}
		if reg.LocalNetworkConfigurator == nil {
			return fmt.Errorf("family %q has no local network configurator registered", family)
		}
	}
	return nil
}

// Decode converts the raw [local_networks] section into the per-family map that
// chainreg dispatches on. Returns nil when the section is absent.
func Decode(raw any) (map[string]*chainreg.LocalNetworkConfig, error) {
	table, err := devenvruntime.DecodeConfig[map[string]any](raw, Key)
	if err != nil {
		return nil, err
	}
	if len(table) == 0 {
		return nil, nil
	}

	version, ok := table[VersionKey]
	if !ok {
		return nil, fmt.Errorf("%s: missing %q key", Key, VersionKey)
	}
	declared, ok := version.(int64)
	if !ok {
		return nil, fmt.Errorf("%s: %q must be an integer, got %T", Key, VersionKey, version)
	}
	if err := devenvruntime.CheckConfigVersion(int(declared), Version); err != nil {
		return nil, fmt.Errorf("%s: %w", Key, err)
	}

	configs := make(map[string]*chainreg.LocalNetworkConfig, len(table)-1)
	for family, value := range table {
		if family == VersionKey {
			continue
		}
		cfg, err := devenvruntime.DecodeConfig[chainreg.LocalNetworkConfig](value, Key+"."+family)
		if err != nil {
			return nil, err
		}
		configs[family] = &cfg
	}
	return configs, nil
}

// Configure applies the [local_networks] section of globalConfig to outputs and
// returns the runtime output map to publish: the resolved per-family configs
// under Key, and the finalizers under FinalizersKey. It returns nil when the
// section is absent, so callers can merge unconditionally.
func Configure(
	ctx context.Context,
	globalConfig map[string]any,
	outputs []*blockchain.Output,
) (map[string]any, error) {
	configs, err := Decode(globalConfig[Key])
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}

	finalizers, err := chainreg.ConfigureLocalNetworks(ctx, configs, outputs)
	if err != nil {
		chainreg.FinalizeLocalNetworks(finalizers)
		return nil, fmt.Errorf("configuring local networks: %w", err)
	}
	return map[string]any{
		Key:           configs,
		FinalizersKey: finalizers,
	}, nil
}

// Finalize runs the finalizers the runtime accumulated under FinalizersKey and
// removes them, restoring the direct node endpoints in the blockchain outputs.
// Call it once every consumer has captured its network configuration and before
// the environment output is serialized. It is a no-op when no local networks
// were configured.
func Finalize(out map[string]any) {
	finalizers, ok := out[FinalizersKey].([]chainreg.LocalNetworkFinalizer)
	if !ok {
		return
	}
	chainreg.FinalizeLocalNetworks(finalizers)
	delete(out, FinalizersKey)
}
