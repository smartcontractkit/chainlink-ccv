package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	idxconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/indexer_config"
)

// GenerateIndexerConfigInput contains the input for the indexer config generation sequence.
type GenerateIndexerConfigInput struct {
	// ServiceIdentifier is the identifier for this indexer service (e.g. "default-indexer")
	ServiceIdentifier string
	// CommitteeQualifiers are the committees to generate config for, in order matching [[Verifier]] entries
	CommitteeQualifiers []string
	// SourceChainSelectors are the source chains the indexer will monitor
	SourceChainSelectors []uint64
}

// GenerateIndexerConfigOutput contains the output of the indexer config generation sequence.
type GenerateIndexerConfigOutput struct {
	ServiceIdentifier string
	// Verifiers contains one entry per committee with all IssuerAddresses for that committee
	Verifiers []idxconfig.GeneratedVerifier
}

// GenerateIndexerConfigDeps contains the dependencies for the sequence.
type GenerateIndexerConfigDeps struct {
	Env deployment.Environment
}

// GenerateIndexerConfig is a sequence that generates the indexer configuration
// by scanning on-chain CommitteeVerifier contracts. It only generates the on-chain derived parts.
var GenerateIndexerConfig = operations.NewSequence(
	"generate-indexer-config",
	semver.MustParse("1.0.0"),
	"Generates the indexer verifier configuration from on-chain state",
	func(b operations.Bundle, deps GenerateIndexerConfigDeps, input GenerateIndexerConfigInput) (GenerateIndexerConfigOutput, error) {
		// Execute the build config operation
		result, err := operations.ExecuteOperation(b, idxconfig.BuildConfig, idxconfig.BuildConfigDeps{
			Env: deps.Env,
		}, idxconfig.BuildConfigInput{
			ServiceIdentifier:   input.ServiceIdentifier,
			CommitteeQualifiers: input.CommitteeQualifiers,
			ChainSelectors:      input.SourceChainSelectors,
		})
		if err != nil {
			return GenerateIndexerConfigOutput{}, fmt.Errorf("failed to build indexer config: %w", err)
		}

		return GenerateIndexerConfigOutput{
			ServiceIdentifier: result.Output.ServiceIdentifier,
			Verifiers:         result.Output.Verifiers,
		}, nil
	},
)
