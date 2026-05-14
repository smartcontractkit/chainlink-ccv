package indexer

import (
	"context"
	"fmt"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
)

const configKey = "indexer"

// preparedIndexerInputsKey must match the constant in legacy_component.go.
const preparedIndexerInputsKey = "_prepared_indexer_inputs"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("indexer component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase4 launches one indexer container per prepared *services.IndexerInput.
// The inputs are fully configured (TLS, discoveries, secrets) by
// runPhasedEnvironmentSetup in the legacy component's Phase 3. Calling
// services.NewIndexer mutates idxIn.Out on the shared pointer; the legacy
// component's Phase 4 reads those Out fields via runPhasedEnvironmentFinish.
func (c *component) RunPhase4(
	_ context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	inputs, ok := priorOutputs[preparedIndexerInputsKey].([]*services.IndexerInput)
	if !ok {
		// No indexer inputs were prepared (env.toml omits [[indexer]]).
		return map[string]any{}, nil, nil
	}

	for _, idxIn := range inputs {
		if idxIn == nil {
			continue
		}
		out, err := services.NewIndexer(idxIn)
		if err != nil {
			return nil, nil, fmt.Errorf("starting indexer %q: %w", idxIn.ContainerName, err)
		}
		idxIn.Out = out
	}

	return map[string]any{}, nil, nil
}
