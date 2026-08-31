package chainreg

import (
	"context"
	"fmt"
	"slices"
	"sort"

	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ConfigureLocalNetworks routes each family's opaque local network config to
// its registered configurator and records the returned output in place. Both
// environment orchestrators call it right after the blockchains come up and
// before any consumer reads a node URL, so services see whatever endpoints the
// family installed.
//
// The returned finalizers must run once every consumer has captured its network
// configuration and before the environment output is serialized. Pass them to
// FinalizeLocalNetworks.
func ConfigureLocalNetworks(
	ctx context.Context,
	configs map[string]*LocalNetworkConfig,
	outputs []*ctfblockchain.Output,
) ([]LocalNetworkFinalizer, error) {
	families := make([]string, 0, len(configs))
	for family := range configs {
		families = append(families, family)
	}
	sort.Strings(families)

	finalizers := make([]LocalNetworkFinalizer, 0, len(families))
	for _, family := range families {
		cfg := configs[family]
		if cfg == nil {
			return finalizers, fmt.Errorf("local network config for family %s is nil", family)
		}

		reg, err := GetRegistry().Get(family)
		if err != nil {
			return finalizers, fmt.Errorf("getting local network registration for family %s: %w", family, err)
		}
		if reg.LocalNetworkConfigurator == nil {
			return finalizers, fmt.Errorf("local network configurator for family %s is not registered", family)
		}

		familyOutputs := make([]*ctfblockchain.Output, 0, len(outputs))
		for _, output := range outputs {
			if output != nil && output.Family == family {
				familyOutputs = append(familyOutputs, output)
			}
		}
		if len(familyOutputs) == 0 {
			return finalizers, fmt.Errorf("local network config for family %s has no matching blockchains", family)
		}

		output, finalize, err := reg.LocalNetworkConfigurator(ctx, cfg.Input, familyOutputs)
		if err != nil {
			return finalizers, fmt.Errorf("configuring local networks for family %s: %w", family, err)
		}
		cfg.Output = output
		if finalize != nil {
			finalizers = append(finalizers, finalize)
		}
	}

	return finalizers, nil
}

// FinalizeLocalNetworks runs finalizers in reverse registration order.
func FinalizeLocalNetworks(finalizers []LocalNetworkFinalizer) {
	for _, finalize := range slices.Backward(finalizers) {
		finalize()
	}
}
