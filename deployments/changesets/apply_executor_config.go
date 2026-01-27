package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	executorconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/executor_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
)

type ApplyExecutorConfigCfg struct {
	Topology *deployments.EnvironmentTopology
	// ExecutorQualifier identifies which executor pool from topology to use
	ExecutorQualifier string
	// ChainSelectors limits which chains to configure. Defaults to all.
	ChainSelectors []uint64
	// TargetNOPs limits which NOPs to update. Defaults to all in pool.
	TargetNOPs []shared.NOPAlias
}

func ApplyExecutorConfig() deployment.ChangeSetV2[ApplyExecutorConfigCfg] {
	validate := func(e deployment.Environment, cfg ApplyExecutorConfigCfg) error {
		if cfg.Topology == nil {
			return fmt.Errorf("topology is required")
		}

		if cfg.ExecutorQualifier == "" {
			return fmt.Errorf("executor qualifier is required")
		}

		if cfg.Topology.IndexerAddress == "" {
			return fmt.Errorf("indexer address is required in topology")
		}

		pool, ok := cfg.Topology.ExecutorPools[cfg.ExecutorQualifier]
		if !ok {
			return fmt.Errorf("executor pool %q not found in topology", cfg.ExecutorQualifier)
		}

		if len(pool.NOPAliases) == 0 {
			return fmt.Errorf("executor pool %q has no NOPs", cfg.ExecutorQualifier)
		}

		poolNOPs := shared.ConvertStringToNopAliases(pool.NOPAliases)
		for _, alias := range cfg.TargetNOPs {
			if !slices.Contains(poolNOPs, alias) {
				return fmt.Errorf("NOP alias %q not found in executor pool %q", alias, cfg.ExecutorQualifier)
			}
		}

		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}

		if shared.IsProductionEnvironment(e.Name) {
			if cfg.Topology.PyroscopeURL != "" {
				return fmt.Errorf("pyroscope URL is not supported for production environments")
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg ApplyExecutorConfigCfg) (deployment.ChangesetOutput, error) {
		deployedChains := getExecutorDeployedChains(e.DataStore, cfg.ExecutorQualifier)

		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = deployedChains
		} else {
			selectors = filterChains(selectors, deployedChains)
		}

		pool := cfg.Topology.ExecutorPools[cfg.ExecutorQualifier]
		executorPool := convertTopologyExecutorPool(pool)
		monitoring := convertTopologyMonitoring(&cfg.Topology.Monitoring)
		nopModes := buildNOPModes(cfg.Topology.NOPTopology.NOPs)

		input := sequences.GenerateExecutorConfigInput{
			ExecutorQualifier: cfg.ExecutorQualifier,
			ChainSelectors:    selectors,
			TargetNOPs:        cfg.TargetNOPs,
			ExecutorPool:      executorPool,
			IndexerAddress:    cfg.Topology.IndexerAddress,
			PyroscopeURL:      cfg.Topology.PyroscopeURL,
			Monitoring:        monitoring,
			NOPModes:          nopModes,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateExecutorConfig, sequences.GenerateExecutorConfigDeps{Env: e}, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate executor config: %w", err)
		}

		manageReport, err := operations.ExecuteSequence(
			e.OperationsBundle,
			sequences.ManageJobProposals,
			sequences.ManageJobProposalsDeps{Env: e},
			sequences.ManageJobProposalsInput{
				JobSpecs:      report.Output.JobSpecs,
				AffectedScope: report.Output.AffectedScope,
				Labels: map[string]string{
					"job_type": "executor",
					"executor": cfg.ExecutorQualifier,
				},
				NOPs: sequences.NOPContext{
					Modes:      nopModes,
					TargetNOPs: cfg.TargetNOPs,
					AllNOPs:    getAllNOPAliases(cfg.Topology.NOPTopology.NOPs),
				},
			},
		)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to manage job proposals: %w", err)
		}

		e.Logger.Infow("Executor config applied",
			"jobsCount", len(manageReport.Output.Jobs),
			"revokedCount", len(manageReport.Output.RevokedJobs))

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: manageReport.Output.DataStore,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func convertTopologyExecutorPool(pool deployments.ExecutorPoolConfig) executorconfig.ExecutorPoolInput {
	return executorconfig.ExecutorPoolInput{
		NOPAliases:        shared.ConvertStringToNopAliases(pool.NOPAliases),
		ExecutionInterval: pool.ExecutionInterval,
		NtpServer:         pool.NtpServer,
		IndexerQueryLimit: pool.IndexerQueryLimit,
		BackoffDuration:   pool.BackoffDuration,
		LookbackWindow:    pool.LookbackWindow,
		ReaderCacheExpiry: pool.ReaderCacheExpiry,
		MaxRetryDuration:  pool.MaxRetryDuration,
		WorkerCount:       pool.WorkerCount,
	}
}
