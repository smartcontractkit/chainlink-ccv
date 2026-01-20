package verifier_config

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

// NOPJobSpecs maps NOP alias to a map of job spec ID to job spec content.
type NOPJobSpecs map[string]map[string]string

// BuildJobSpecsDeps contains the dependencies for building verifier job specs.
type BuildJobSpecsDeps struct {
	Topology *deployments.EnvironmentTopology
}

// BuildJobSpecsInput contains the input parameters for building verifier job specs.
type BuildJobSpecsInput struct {
	GeneratedConfig    *VerifierGeneratedConfig
	CommitteeQualifier string
	NOPAliases         []string
}

// BuildJobSpecsOutput contains the generated job specs and metadata for cleanup.
type BuildJobSpecsOutput struct {
	JobSpecs           NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExpectedNOPs       map[string]bool
	VerifierSuffix     string
}

// BuildJobSpecs is an operation that generates verifier job specs for the specified NOPs.
var BuildJobSpecs = operations.NewOperation(
	"build-verifier-job-specs",
	semver.MustParse("1.0.0"),
	"Builds verifier job specs from generated config and environment topology",
	func(b operations.Bundle, deps BuildJobSpecsDeps, input BuildJobSpecsInput) (BuildJobSpecsOutput, error) {
		committee, ok := deps.Topology.NOPTopology.Committees[input.CommitteeQualifier]
		if !ok {
			return BuildJobSpecsOutput{}, fmt.Errorf("committee %q not found in topology", input.CommitteeQualifier)
		}

		jobSpecs := make(NOPJobSpecs)
		expectedJobSpecIDs := make(map[string]bool)
		expectedNOPs := make(map[string]bool)
		verifierSuffix := fmt.Sprintf("-%s-verifier", committee.Qualifier)

		nopAliases := input.NOPAliases
		if len(nopAliases) == 0 {
			nopsForCommittee, err := deps.Topology.GetNOPsForCommittee(input.CommitteeQualifier)
			if err != nil {
				return BuildJobSpecsOutput{}, fmt.Errorf("failed to get NOPs for committee: %w", err)
			}
			nopAliases = nopsForCommittee
		}

		for _, nopAlias := range nopAliases {
			nop, ok := deps.Topology.NOPTopology.GetNOP(nopAlias)
			if !ok {
				return BuildJobSpecsOutput{}, fmt.Errorf("NOP %q not found in topology", nopAlias)
			}
			expectedNOPs[nopAlias] = true

			for _, agg := range committee.Aggregators {
				verifierID := fmt.Sprintf("%s-%s-verifier", agg.Name, committee.Qualifier)
				expectedJobSpecIDs[verifierID] = true

				verifierCfg := commit.Config{
					VerifierID:                     verifierID,
					AggregatorAddress:              agg.Address,
					InsecureAggregatorConnection:   agg.InsecureAggregatorConnection,
					SignerAddress:                  nop.SignerAddress,
					PyroscopeURL:                   deps.Topology.PyroscopeURL,
					CommitteeVerifierAddresses:     input.GeneratedConfig.CommitteeVerifierAddresses,
					OnRampAddresses:                input.GeneratedConfig.OnRampAddresses,
					DefaultExecutorOnRampAddresses: input.GeneratedConfig.DefaultExecutorOnRampAddresses,
					RMNRemoteAddresses:             input.GeneratedConfig.RMNRemoteAddresses,
					Monitoring:                     convertMonitoringConfig(deps.Topology.Monitoring),
				}

				configBytes, err := toml.Marshal(verifierCfg)
				if err != nil {
					return BuildJobSpecsOutput{}, fmt.Errorf("failed to marshal verifier config to TOML for NOP %q aggregator %q: %w", nopAlias, agg.Name, err)
				}

				jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvcommitteeverifier"
committeeVerifierConfig = """
%s"""
`, string(configBytes))

				if jobSpecs[nopAlias] == nil {
					jobSpecs[nopAlias] = make(map[string]string)
				}
				jobSpecs[nopAlias][verifierID] = jobSpec
			}
		}

		return BuildJobSpecsOutput{
			JobSpecs:           jobSpecs,
			ExpectedJobSpecIDs: expectedJobSpecIDs,
			ExpectedNOPs:       expectedNOPs,
			VerifierSuffix:     verifierSuffix,
		}, nil
	},
)

func convertMonitoringConfig(cfg deployments.MonitoringConfig) verifier.MonitoringConfig {
	return verifier.MonitoringConfig{
		Enabled: cfg.Enabled,
		Type:    cfg.Type,
		Beholder: verifier.BeholderConfig{
			InsecureConnection:       cfg.Beholder.InsecureConnection,
			CACertFile:               cfg.Beholder.CACertFile,
			OtelExporterGRPCEndpoint: cfg.Beholder.OtelExporterGRPCEndpoint,
			OtelExporterHTTPEndpoint: cfg.Beholder.OtelExporterHTTPEndpoint,
			LogStreamingEnabled:      cfg.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     cfg.Beholder.MetricReaderInterval,
			TraceSampleRatio:         cfg.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        cfg.Beholder.TraceBatchTimeout,
		},
	}
}
