package committeeccv

import (
	"context"
	"fmt"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
)

const configKey = "aggregator"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("committeeccv component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase4 reads the prepared *services.AggregatorInput pointers published by
// the legacy Phase 3 component (under "aggregators"), calls services.NewAggregator
// for each one, and sets agg.Out on the shared pointers. Mutations are visible to:
//   - the indexer Phase 4 component (which runs after this one, alphabetically), and
//   - runPhasedEnvironmentFinish (which collects AggregatorEndpoints from agg.Out).
func (c *component) RunPhase4(
	_ context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	aggregators, ok := priorOutputs["aggregators"].([]*services.AggregatorInput)
	if !ok {
		return map[string]any{}, nil, nil
	}

	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		out, err := services.NewAggregator(agg)
		if err != nil {
			return nil, nil, fmt.Errorf("starting aggregator %q: %w", agg.CommitteeName, err)
		}
		agg.Out = out
	}

	return map[string]any{}, nil, nil
}
