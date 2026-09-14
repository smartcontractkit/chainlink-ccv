// Package preflight holds read-only checks that run before a lane is configured.
//
// The lane changesets in chainlink-ccip validate the topology and the on-chain state they
// are about to write. They cannot see whether the off-chain components that serve a lane
// exist, because the job state lives in this module's env metadata. These checks close
// that gap: they answer "are the verifier and executor jobs for this chain deployed and
// approved" before a lane is wired up.
package preflight

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccipoffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

var (
	// ErrNoVerifierJob means a committee NOP has no verifier job for a lane chain's committee.
	ErrNoVerifierJob = errors.New("committee NOP has no verifier job")
	// ErrNoExecutorJob means a pool NOP has no executor job for a lane chain's executor pool.
	ErrNoExecutorJob = errors.New("executor pool NOP has no executor job")
	// ErrJobNotApproved means a job exists but its latest proposal is not approved.
	ErrJobNotApproved = errors.New("job proposal is not approved")
	// ErrJobMissingChain means a deployed job spec does not reference the lane chain, so the
	// job predates the chain being added to the topology.
	ErrJobMissingChain = errors.New("deployed job spec does not cover chain")
)

// CheckLaneOffchainReadiness reports whether the off-chain components serving the given
// lane chains are deployed and approved.
//
// For each chain it walks the committees and executor pools that cover it in the topology
// and, for every member NOP, requires a job that is approved and whose deployed spec
// references the chain selector. A spec that does not mention the chain means the job was
// generated before the chain joined the topology and has not been re-applied.
//
// Chains absent from every committee and pool are skipped: that is the lane changeset's
// topology coverage check, and reporting it here would only duplicate the error.
func CheckLaneOffchainReadiness(
	ds datastore.DataStore,
	topology *ccipoffchain.EnvironmentTopology,
	chainSelectors []uint64,
) error {
	if topology == nil || topology.NOPTopology == nil {
		return errors.New("topology is required")
	}

	// An environment that has never had CCV metadata written has no jobs, which the
	// per-NOP checks below report as the missing jobs they are.
	jobs, err := ccvdeployment.GetAllJobs(ds)
	if err != nil && !errors.Is(err, datastore.ErrEnvMetadataNotSet) {
		return fmt.Errorf("failed to read job state: %w", err)
	}

	for _, selector := range chainSelectors {
		chainKey := strconv.FormatUint(selector, 10)

		for _, qualifier := range committeeQualifiersCovering(topology, chainKey) {
			committee := topology.NOPTopology.Committees[qualifier]
			chainCommittee := committee.ChainConfigs[chainKey]
			for _, alias := range chainCommittee.NOPAliases {
				err := requireVerifierJob(jobs, shared.NOPAlias(alias), qualifier, committee.Aggregators, chainKey)
				if err != nil {
					return fmt.Errorf("chain %s committee %q: %w", chainKey, qualifier, err)
				}
			}
		}

		for _, poolName := range executorPoolsCovering(topology, chainKey) {
			chainPool := topology.ExecutorPools[poolName].ChainConfigs[chainKey]
			for _, alias := range chainPool.NOPAliases {
				jobID := shared.NewExecutorJobID(
					shared.NOPAlias(alias),
					shared.ExecutorJobScope{ExecutorQualifier: poolName},
				).ToJobID()
				err := requireJob(jobs, shared.NOPAlias(alias), jobID, chainKey, ErrNoExecutorJob)
				if err != nil {
					return fmt.Errorf("chain %s executor pool %q: %w", chainKey, poolName, err)
				}
			}
		}
	}

	return nil
}

// requireVerifierJob checks the NOP has an approved verifier job covering the chain.
//
// A committee either runs one consolidated job per NOP (writing to every aggregator) or one
// job per aggregator. The consolidated job is preferred when present; otherwise every
// per-aggregator job must be present and approved. Matching on the exact IDs avoids the
// nondeterminism of scanning the job map, where a stale or rejected entry could otherwise
// mask a missing or unapproved aggregator job.
func requireVerifierJob(
	jobs shared.NOPJobs,
	alias shared.NOPAlias,
	qualifier string,
	aggregators []ccipoffchain.AggregatorConfig,
	chainKey string,
) error {
	scope := shared.VerifierJobScope{CommitteeQualifier: qualifier}
	consolidated := shared.NewConsolidatedVerifierJobID(alias, scope).ToJobID()
	if _, ok := jobs[alias][consolidated]; ok {
		return requireJob(jobs, alias, consolidated, chainKey, ErrNoVerifierJob)
	}
	if len(aggregators) == 0 {
		return requireJob(jobs, alias, consolidated, chainKey, ErrNoVerifierJob)
	}
	for _, aggregator := range aggregators {
		jobID := shared.NewVerifierJobID(alias, aggregator.Name, scope).ToJobID()
		if err := requireJob(jobs, alias, jobID, chainKey, ErrNoVerifierJob); err != nil {
			return err
		}
	}
	return nil
}

// requireJob checks the NOP's job with the given ID is approved and covers the chain.
func requireJob(
	jobs shared.NOPJobs,
	alias shared.NOPAlias,
	jobID shared.JobID,
	chainKey string,
	errMissing error,
) error {
	info, ok := jobs[alias][jobID]
	if !ok {
		return fmt.Errorf("NOP %q: %w", alias, errMissing)
	}
	if !info.IsRunning() || info.LatestStatus() != shared.JobProposalStatusApproved {
		return fmt.Errorf("NOP %q job %q status %q: %w",
			alias, info.JobID, info.LatestStatus(), ErrJobNotApproved)
	}
	if !strings.Contains(info.Spec, chainKey) {
		return fmt.Errorf("NOP %q job %q: %w", alias, info.JobID, ErrJobMissingChain)
	}
	return nil
}

// committeeQualifiersCovering returns, sorted, the committees whose chain_configs include the chain.
func committeeQualifiersCovering(topology *ccipoffchain.EnvironmentTopology, chainKey string) []string {
	var qualifiers []string
	for qualifier, committee := range topology.NOPTopology.Committees {
		if _, ok := committee.ChainConfigs[chainKey]; ok {
			qualifiers = append(qualifiers, qualifier)
		}
	}
	slices.Sort(qualifiers)
	return qualifiers
}

// executorPoolsCovering returns, sorted, the executor pools whose chain_configs include the chain.
func executorPoolsCovering(topology *ccipoffchain.EnvironmentTopology, chainKey string) []string {
	var pools []string
	for poolName, pool := range topology.ExecutorPools {
		if _, ok := pool.ChainConfigs[chainKey]; ok {
			pools = append(pools, poolName)
		}
	}
	slices.Sort(pools)
	return pools
}
