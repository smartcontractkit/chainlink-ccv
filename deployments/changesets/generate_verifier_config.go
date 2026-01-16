package changesets

import (
	"fmt"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

// GenerateVerifierConfigCfg is the configuration for the generate verifier config changeset.
type GenerateVerifierConfigCfg struct {
	EnvConfigPath      string
	CommitteeQualifier string
	ExecutorQualifier  string
	ChainSelectors     []uint64
	NOPAliases         []string
}

// GenerateVerifierConfig creates a changeset that generates verifier configurations
// for NOPs that are part of committees. It iterates over specified NOPs (or all if empty)
// and generates a job spec for each (NOP, committee, aggregator) combination for HA support.
// The SignerAddress for each NOP is read from the NOPConfig in the EnvConfig.
func GenerateVerifierConfig() deployment.ChangeSetV2[GenerateVerifierConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateVerifierConfigCfg) error {
		if cfg.EnvConfigPath == "" {
			return fmt.Errorf("env config path is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}

		envCfg, err := deployments.LoadEnvConfig(cfg.EnvConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load env config: %w", err)
		}

		if _, ok := envCfg.NOPTopology.Committees[cfg.CommitteeQualifier]; !ok {
			return fmt.Errorf("committee %q not found in env config", cfg.CommitteeQualifier)
		}

		nopAliases := cfg.NOPAliases
		if len(nopAliases) == 0 {
			nopAliases, err = envCfg.GetNOPsForCommittee(cfg.CommitteeQualifier)
			if err != nil {
				return fmt.Errorf("failed to get NOPs for committee: %w", err)
			}
		}

		for _, alias := range nopAliases {
			nop, ok := envCfg.NOPTopology.NOPs[alias]
			if !ok {
				return fmt.Errorf("NOP alias %q not found in env config", alias)
			}
			if nop.SignerAddress == "" {
				return fmt.Errorf("NOP %q missing signer_address in env config", alias)
			}
		}

		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateVerifierConfigCfg) (deployment.ChangesetOutput, error) {
		envCfg, err := deployments.LoadEnvConfig(cfg.EnvConfigPath)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to load env config: %w", err)
		}

		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		deps := sequences.GenerateVerifierConfigDeps{
			Env: e,
		}

		input := sequences.GenerateVerifierConfigInput{
			CommitteeQualifier: cfg.CommitteeQualifier,
			ExecutorQualifier:  cfg.ExecutorQualifier,
			ChainSelectors:     selectors,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateVerifierConfig, deps, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate verifier config: %w", err)
		}

		committee := envCfg.NOPTopology.Committees[cfg.CommitteeQualifier]

		nopAliases := cfg.NOPAliases
		if len(nopAliases) == 0 {
			nopsForCommittee, err := envCfg.GetNOPsForCommittee(cfg.CommitteeQualifier)
			if err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to get NOPs for committee: %w", err)
			}
			nopAliases = nopsForCommittee
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		// Track expected NOPs and job spec IDs for cleanup
		expectedNOPs := make(map[string]bool)
		expectedJobSpecIDs := make(map[string]bool)
		verifierSuffix := fmt.Sprintf("-%s-verifier", committee.Qualifier)

		for _, nopAlias := range nopAliases {
			nop := envCfg.NOPTopology.NOPs[nopAlias]
			expectedNOPs[nopAlias] = true

			for _, agg := range committee.Aggregators {
				verifierID := fmt.Sprintf("%s-%s-verifier", agg.Name, committee.Qualifier)
				expectedJobSpecIDs[verifierID] = true

				verifierCfg := commit.Config{
					VerifierID:                     verifierID,
					AggregatorAddress:              agg.Address,
					InsecureAggregatorConnection:   agg.InsecureAggregatorConnection,
					SignerAddress:                  nop.SignerAddress,
					PyroscopeURL:                   envCfg.PyroscopeURL,
					CommitteeVerifierAddresses:     report.Output.Config.CommitteeVerifierAddresses,
					OnRampAddresses:                report.Output.Config.OnRampAddresses,
					DefaultExecutorOnRampAddresses: report.Output.Config.DefaultExecutorOnRampAddresses,
					RMNRemoteAddresses:             report.Output.Config.RMNRemoteAddresses,
					Monitoring:                     convertVerifierMonitoringConfig(envCfg.Monitoring),
				}

				configBytes, err := toml.Marshal(verifierCfg)
				if err != nil {
					return deployment.ChangesetOutput{
						Reports: report.ExecutionReports,
					}, fmt.Errorf("failed to marshal verifier config to TOML for NOP %q aggregator %q: %w", nopAlias, agg.Name, err)
				}

				jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvcommitteeverifier"
committeeVerifierConfig = """
%s"""
`, string(configBytes))

				if err := deployments.SaveNOPJobSpec(outputDS, nopAlias, verifierID, jobSpec); err != nil {
					return deployment.ChangesetOutput{
						Reports: report.ExecutionReports,
					}, fmt.Errorf("failed to save verifier job spec for NOP %q aggregator %q: %w", nopAlias, agg.Name, err)
				}
			}
		}

		// Clean up orphaned verifier job specs for this committee
		// When NOPAliases is explicitly set, only clean up those specific NOPs (scoped mode)
		// When NOPAliases is empty, clean up all NOPs in the datastore (full sync mode)
		scopedCleanup := len(cfg.NOPAliases) > 0
		scopedNOPs := make(map[string]bool)
		if scopedCleanup {
			for _, nopAlias := range cfg.NOPAliases {
				scopedNOPs[nopAlias] = true
			}
		}

		allNOPJobSpecs, err := deployments.GetAllNOPJobSpecs(outputDS.Seal())
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to get all NOP job specs for cleanup: %w", err)
		}

		for nopAlias, jobSpecs := range allNOPJobSpecs {
			// In scoped mode, only cleanup NOPs that were explicitly specified
			if scopedCleanup && !scopedNOPs[nopAlias] {
				continue
			}
			for jobSpecID := range jobSpecs {
				// Check if this job spec matches the pattern for this committee's verifier
				if !strings.HasSuffix(jobSpecID, verifierSuffix) {
					continue
				}
				// Delete if: 1) job spec ID is not expected, OR 2) NOP is not expected to have verifier jobs
				shouldDelete := !expectedJobSpecIDs[jobSpecID] || !expectedNOPs[nopAlias]
				if shouldDelete {
					if err := deployments.DeleteNOPJobSpec(outputDS, nopAlias, jobSpecID); err != nil {
						return deployment.ChangesetOutput{
							Reports: report.ExecutionReports,
						}, fmt.Errorf("failed to delete orphaned verifier job spec %q for NOP %q: %w", jobSpecID, nopAlias, err)
					}
				}
			}
		}

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func convertVerifierMonitoringConfig(cfg deployments.MonitoringConfig) verifier.MonitoringConfig {
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
