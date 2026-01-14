package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	aggconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/aggregator_config"
)

// GenerateAggregatorConfigInput contains the input for the aggregator config generation sequence.
type GenerateAggregatorConfigInput struct {
	ServiceIdentifier  string
	CommitteeQualifier string
	// ChainSelectors are the chains the aggregator will support (both as source and destination).
	ChainSelectors []uint64
}

// GenerateAggregatorConfigOutput contains the output of the aggregator config generation sequence.
type GenerateAggregatorConfigOutput struct {
	ServiceIdentifier string
	Committee         *aggconfig.Committee
}

// GenerateAggregatorConfigDeps contains the dependencies for the sequence.
type GenerateAggregatorConfigDeps struct {
	Env deployment.Environment
}

// GenerateAggregatorConfig is a sequence that generates the aggregator configuration
// by scanning on-chain CommitteeVerifier contracts.
var GenerateAggregatorConfig = operations.NewSequence(
	"generate-aggregator-config",
	semver.MustParse("1.0.0"),
	"Generates the aggregator committee configuration from on-chain state",
	func(b operations.Bundle, deps GenerateAggregatorConfigDeps, input GenerateAggregatorConfigInput) (GenerateAggregatorConfigOutput, error) {
		// Execute the build config operation
		result, err := operations.ExecuteOperation(b, aggconfig.BuildConfig, aggconfig.BuildConfigDeps{
			Env: deps.Env,
		}, aggconfig.BuildConfigInput{
			ServiceIdentifier:  input.ServiceIdentifier,
			CommitteeQualifier: input.CommitteeQualifier,
			ChainSelectors:     input.ChainSelectors,
		})
		if err != nil {
			return GenerateAggregatorConfigOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		return GenerateAggregatorConfigOutput{
			ServiceIdentifier: result.Output.ServiceIdentifier,
			Committee:         result.Output.Committee,
		}, nil
	},
)
