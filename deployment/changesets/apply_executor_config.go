package changesets

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/executor"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_node_chain_support"
	"github.com/smartcontractkit/chainlink-ccv/deployment/sequences"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// ApplyExecutorConfigInput is the imperative input for the ApplyExecutorConfig
// changeset. It replaces the prior topology-driven input — callers describe the
// executor pool, the participating NOPs, and the indexer / monitoring settings
// directly, without supplying a *EnvironmentTopology.
type ApplyExecutorConfigInput struct {
	// ExecutorQualifier identifies the executor pool being published.
	ExecutorQualifier string
	// NOPs describes every NOP referenced by the pool. Only Mode and Alias are
	// consulted by this changeset (signer addresses are unused).
	NOPs []NOPInput
	// Pool is the per-pool description: per-chain NOP membership, execution
	// interval, and pool-wide tuning.
	Pool ExecutorPoolInput
	// IndexerAddress lists the indexer endpoints the executor connects to.
	IndexerAddress []string
	// PyroscopeURL is forwarded into the executor job spec for profiling. Must be
	// empty in production environments (validated below).
	PyroscopeURL string
	// Monitoring is forwarded into the executor job spec.
	Monitoring ccvdeployment.MonitoringConfig
	// TargetNOPs filters the publish set. Empty means "all NOPs in the pool".
	TargetNOPs []shared.NOPAlias
	// RevokeOrphanedJobs when true revokes and cleans up orphaned jobs; default false.
	RevokeOrphanedJobs bool
}

// ApplyExecutorConfig is the offchain-only single-entry product for §5.9 / §5.10:
// publish or refresh executor job specs for an executor pool. It writes new job
// specs via JD (CL-mode NOPs) and persists job metadata into the DataStore. No
// onchain state is touched and no MCMS coordination is required.
//
// The input is imperative — callers pass the pool description and the
// participating NOPs directly, with no *EnvironmentTopology.
func ApplyExecutorConfig(registry *adapters.Registry) deployment.ChangeSetV2[ApplyExecutorConfigInput] {
	validate := func(e deployment.Environment, cfg ApplyExecutorConfigInput) error {
		if cfg.ExecutorQualifier == "" {
			return fmt.Errorf("executor qualifier is required")
		}
		if len(cfg.NOPs) == 0 {
			return fmt.Errorf("at least one NOP is required")
		}
		if len(cfg.IndexerAddress) == 0 {
			return fmt.Errorf("indexer address is required")
		}
		if len(cfg.Pool.ChainConfigs) == 0 {
			return fmt.Errorf("executor pool %q requires non-empty ChainConfigs", cfg.ExecutorQualifier)
		}

		nopSet := make(map[shared.NOPAlias]bool, len(cfg.NOPs))
		for _, nop := range cfg.NOPs {
			if nop.Alias == "" {
				return fmt.Errorf("NOP alias is required")
			}
			if nopSet[nop.Alias] {
				return fmt.Errorf("duplicate NOP alias %q", nop.Alias)
			}
			nopSet[nop.Alias] = true
		}

		for chainSelector, chainCfg := range cfg.Pool.ChainConfigs {
			for _, alias := range chainCfg.NOPAliases {
				if !nopSet[alias] {
					return fmt.Errorf(
						"executor pool chain %d references unknown NOP alias %q",
						chainSelector, alias,
					)
				}
			}
		}

		poolNOPs := executorPoolNOPAliases(cfg.Pool)
		if len(poolNOPs) == 0 {
			return fmt.Errorf("executor pool %q has no NOPs", cfg.ExecutorQualifier)
		}
		for _, alias := range cfg.TargetNOPs {
			if !slices.Contains(poolNOPs, alias) {
				return fmt.Errorf("NOP alias %q not found in executor pool %q", alias, cfg.ExecutorQualifier)
			}
		}

		if shared.IsProductionEnvironment(e.Name) && cfg.PyroscopeURL != "" {
			return fmt.Errorf("pyroscope URL is not supported for production environments")
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg ApplyExecutorConfigInput) (deployment.ChangesetOutput, error) {
		selectors := registry.AllDeployedExecutorChains(e.DataStore, cfg.ExecutorQualifier)

		if len(selectors) == 0 {
			return runOrphanJobCleanup(
				e,
				cfg.RevokeOrphanedJobs,
				shared.ExecutorJobScope{ExecutorQualifier: cfg.ExecutorQualifier},
				map[string]string{"job_type": "executor", "executor": cfg.ExecutorQualifier},
				buildNOPModes(cfg.NOPs),
				cfg.TargetNOPs,
				allNOPAliases(cfg.NOPs),
				"No deployed chains found for executor pool, nothing to do",
				"No deployed chains for executor pool, running orphan cleanup only",
				"qualifier", cfg.ExecutorQualifier,
			)
		}

		nopsToValidate := cfg.TargetNOPs
		if len(nopsToValidate) == 0 {
			nopsToValidate = executorPoolNOPAliases(cfg.Pool)
		}

		clNOPs := filterCLModeNOPs(nopsToValidate, cfg.NOPs)
		if err := validateExecutorChainSupport(e, cfg.Pool, clNOPs, selectors); err != nil {
			return deployment.ChangesetOutput{}, err
		}

		chainConfigs, err := buildExecutorChainConfigs(registry, e.DataStore, selectors, cfg.ExecutorQualifier)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		nopModes := buildNOPModes(cfg.NOPs)

		jobSpecs, scope, err := buildExecutorJobSpecs(
			chainConfigs,
			cfg.ExecutorQualifier,
			cfg.TargetNOPs,
			cfg.Pool,
			cfg.IndexerAddress,
			cfg.PyroscopeURL,
			cfg.Monitoring,
		)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		manageReport, err := operations.ExecuteSequence(
			e.OperationsBundle,
			sequences.ManageJobProposals,
			sequences.ManageJobProposalsDeps{Env: e},
			sequences.ManageJobProposalsInput{
				JobSpecs:      jobSpecs,
				AffectedScope: scope,
				Labels: map[string]string{
					"job_type": "executor",
					"executor": cfg.ExecutorQualifier,
				},
				NOPs: sequences.NOPContext{
					Modes:      nopModes,
					TargetNOPs: cfg.TargetNOPs,
					AllNOPs:    allNOPAliases(cfg.NOPs),
				},
				RevokeOrphanedJobs: cfg.RevokeOrphanedJobs,
			},
		)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: manageReport.ExecutionReports,
			}, fmt.Errorf("failed to manage job proposals: %w", err)
		}

		e.Logger.Infow("Executor config applied",
			"jobsCount", len(manageReport.Output.Jobs),
			"revokedCount", len(manageReport.Output.RevokedJobs))

		return deployment.ChangesetOutput{
			Reports:   manageReport.ExecutionReports,
			DataStore: manageReport.Output.DataStore,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func buildExecutorChainConfigs(
	registry *adapters.Registry,
	ds datastore.DataStore,
	selectors []uint64,
	qualifier string,
) (map[string]executor.ChainConfiguration, error) {
	chainConfigs := make(map[string]executor.ChainConfiguration, len(selectors))
	for _, sel := range selectors {
		a, err := registry.GetByChain(sel)
		if err != nil {
			return nil, fmt.Errorf("no adapter for chain %d: %w", sel, err)
		}
		if a.Executor == nil {
			return nil, fmt.Errorf("no executor config adapter registered for chain %d", sel)
		}
		cfg, err := a.Executor.BuildChainConfig(ds, sel, qualifier)
		if err != nil {
			return nil, fmt.Errorf("failed to build config for chain %d: %w", sel, err)
		}
		chainConfigs[strconv.FormatUint(sel, 10)] = cfg
	}
	return chainConfigs, nil
}

// executorPoolNOPAliases returns the union of NOP aliases referenced by the pool's
// chain configs, sorted for deterministic ordering.
func executorPoolNOPAliases(pool ExecutorPoolInput) []shared.NOPAlias {
	aliasSet := make(map[shared.NOPAlias]struct{})
	for _, chainCfg := range pool.ChainConfigs {
		for _, alias := range chainCfg.NOPAliases {
			aliasSet[alias] = struct{}{}
		}
	}
	aliases := make([]shared.NOPAlias, 0, len(aliasSet))
	for alias := range aliasSet {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	return aliases
}

func validateExecutorChainSupport(
	e deployment.Environment,
	pool ExecutorPoolInput,
	nopsToValidate []shared.NOPAlias,
	deployedChains []uint64,
) error {
	if e.Offchain == nil {
		e.Logger.Debugw("Offchain client not available, skipping chain support validation")
		return nil
	}

	nopAliasStrings := shared.ConvertNopAliasToString(nopsToValidate)

	supportedChains, err := fetchNodeChainSupport(e, nopAliasStrings)
	if err != nil {
		return fmt.Errorf("failed to fetch node chain support: %w", err)
	}
	if supportedChains == nil {
		return nil
	}

	var validationResults []shared.ChainValidationResult
	for _, nopAlias := range nopsToValidate {
		requiredChains := requiredChainsForExecutorNOP(nopAlias, pool)
		result := shared.ValidateNOPChainSupport(
			string(nopAlias),
			requiredChains,
			supportedChains[string(nopAlias)],
		)
		if result != nil {
			validationResults = append(validationResults, *result)
		}
	}

	return shared.FormatChainValidationError(validationResults)
}

func requiredChainsForExecutorNOP(nopAlias shared.NOPAlias, pool ExecutorPoolInput) []uint64 {
	requiredChains := make([]uint64, 0, len(pool.ChainConfigs))
	for chainSelector, chainCfg := range pool.ChainConfigs {
		if slices.Contains(chainCfg.NOPAliases, nopAlias) {
			requiredChains = append(requiredChains, chainSelector)
		}
	}
	slices.Sort(requiredChains)
	return requiredChains
}

func fetchNodeChainSupport(e deployment.Environment, nopAliases []string) (shared.ChainSupportByNOP, error) {
	if len(nopAliases) == 0 {
		return nil, nil
	}

	report, err := operations.ExecuteOperation(
		e.OperationsBundle,
		fetch_node_chain_support.FetchNodeChainSupport,
		fetch_node_chain_support.FetchNodeChainSupportDeps{
			JDClient: e.Offchain,
			Logger:   e.Logger,
			NodeIDs:  e.NodeIDs,
		},
		fetch_node_chain_support.FetchNodeChainSupportInput{
			NOPAliases: nopAliases,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch node chain support from JD: %w", err)
	}

	return report.Output.SupportedChains, nil
}

func buildExecutorJobSpecs(
	adapterChainConfigs map[string]executor.ChainConfiguration,
	executorQualifier string,
	targetNOPs []shared.NOPAlias,
	pool ExecutorPoolInput,
	indexerAddress []string,
	pyroscopeURL string,
	monitoring ccvdeployment.MonitoringConfig,
) (shared.NOPJobSpecs, shared.ExecutorJobScope, error) {
	scope := shared.ExecutorJobScope{
		ExecutorQualifier: executorQualifier,
	}

	poolNOPs := executorPoolNOPAliases(pool)
	nopAliases := targetNOPs
	if len(nopAliases) == 0 {
		nopAliases = poolNOPs
	}

	jobSpecs := make(shared.NOPJobSpecs)

	for _, nopAlias := range nopAliases {
		chainCfgs := make(map[string]executor.ChainConfiguration)
		for chainSelectorStr, adapterCfg := range adapterChainConfigs {
			chainSelector, err := strconv.ParseUint(chainSelectorStr, 10, 64)
			if err != nil {
				return nil, scope, fmt.Errorf("internal: adapter chain key %q is not a valid chain selector: %w", chainSelectorStr, err)
			}
			chainCfg, ok := pool.ChainConfigs[chainSelector]
			if !ok {
				continue
			}
			sortedPool := slices.Clone(chainCfg.NOPAliases)
			slices.Sort(sortedPool)
			sortedPoolStrs := shared.ConvertNopAliasToString(sortedPool)
			chainCfgs[chainSelectorStr] = executor.ChainConfiguration{
				DestinationChainConfig: chainaccess.DestinationChainConfig{
					OffRampAddress: adapterCfg.OffRampAddress,
					RmnAddress:     adapterCfg.RmnAddress,
				},
				DefaultExecutorAddress: adapterCfg.DefaultExecutorAddress,
				ExecutorPool:           sortedPoolStrs,
				ExecutionInterval:      chainCfg.ExecutionInterval,
			}
		}

		jobSpecID := shared.NewExecutorJobID(nopAlias, scope)

		executorCfg := executor.Configuration{
			IndexerAddress:     indexerAddress,
			ExecutorID:         jobSpecID.GetExecutorID(),
			PyroscopeURL:       pyroscopeURL,
			NtpServer:          pool.NtpServer,
			IndexerQueryLimit:  pool.IndexerQueryLimit,
			BackoffDuration:    pool.BackoffDuration,
			LookbackWindow:     pool.LookbackWindow,
			ReaderCacheExpiry:  pool.ReaderCacheExpiry,
			MaxRetryDuration:   pool.MaxRetryDuration,
			WorkerCount:        pool.WorkerCount,
			Monitoring:         monitoring,
			ChainConfiguration: chainCfgs,
		}

		configBytes, err := toml.Marshal(executorCfg)
		if err != nil {
			return nil, scope, fmt.Errorf("failed to marshal executor config for NOP %q: %w", nopAlias, err)
		}

		jobID := jobSpecID.ToJobID()
		jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvexecutor"
name = "%s"
externalJobID = "%s"
executorConfig = '''
%s'''
`, string(jobID), jobID.ToExternalJobID(), string(configBytes))

		if jobSpecs[nopAlias] == nil {
			jobSpecs[nopAlias] = make(map[shared.JobID]string)
		}
		jobSpecs[nopAlias][jobID] = jobSpec
	}

	return jobSpecs, scope, nil
}
