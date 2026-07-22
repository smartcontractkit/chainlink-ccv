package ccv

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func configureLocalNetworks(
	ctx context.Context,
	configs map[string]*chainreg.LocalNetworkConfig,
	outputs []*blockchain.Output,
) ([]chainreg.LocalNetworkFinalizer, error) {
	families := make([]string, 0, len(configs))
	for family := range configs {
		families = append(families, family)
	}
	sort.Strings(families)

	finalizers := make([]chainreg.LocalNetworkFinalizer, 0, len(families))
	for _, family := range families {
		cfg := configs[family]
		if cfg == nil {
			return finalizers, fmt.Errorf("local network config for family %s is nil", family)
		}

		reg, err := chainreg.GetRegistry().Get(family)
		if err != nil {
			return finalizers, fmt.Errorf("getting local network registration for family %s: %w", family, err)
		}
		if reg.LocalNetworkConfigurator == nil {
			return finalizers, fmt.Errorf("local network configurator for family %s is not registered", family)
		}

		familyOutputs := make([]*blockchain.Output, 0, len(outputs))
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

func finalizeLocalNetworks(finalizers []chainreg.LocalNetworkFinalizer) {
	for _, finalize := range slices.Backward(finalizers) {
		finalize()
	}
}
