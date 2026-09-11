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
			chainCommittee := topology.NOPTopology.Committees[qualifier].ChainConfigs[chainKey]
			for _, alias := range chainCommittee.NOPAliases {
				err := requireJob(jobs, shared.NOPAlias(alias), jobSuffixVerifier, qualifier, chainKey, ErrNoVerifierJob)
				if err != nil {
					return fmt.Errorf("chain %s committee %q: %w", chainKey, qualifier, err)
				}
			}
		}

		for _, poolName := range executorPoolsCovering(topology, chainKey) {
			chainPool := topology.ExecutorPools[poolName].ChainConfigs[chainKey]
			for _, alias := range chainPool.NOPAliases {
				err := requireJob(jobs, shared.NOPAlias(alias), jobSuffixExecutor, poolName, chainKey, ErrNoExecutorJob)
				if err != nil {
					return fmt.Errorf("chain %s executor pool %q: %w", chainKey, poolName, err)
				}
			}
		}
	}

	return nil
}

const (
	jobSuffixVerifier = "verifier"
	jobSuffixExecutor = "executor"
)

// requireJob finds the NOP's job for a qualifier and checks it is approved and covers the
// chain. Job IDs are "<nop>-<qualifier>-<kind>", with an optional aggregator name in the
// middle for per-aggregator verifier jobs, so they are matched on their parts rather than
// reconstructed.
func requireJob(
	jobs shared.NOPJobs,
	alias shared.NOPAlias,
	kind string,
	qualifier string,
	chainKey string,
	errMissing error,
) error {
	var found *shared.JobInfo
	for jobID, info := range jobs[alias] {
		if jobMatches(string(jobID), kind, qualifier) {
			found = &info
			break
		}
	}
	if found == nil {
		return fmt.Errorf("NOP %q: %w", alias, errMissing)
	}
	if !found.IsRunning() || found.LatestStatus() != shared.JobProposalStatusApproved {
		return fmt.Errorf("NOP %q job %q status %q: %w",
			alias, found.JobID, found.LatestStatus(), ErrJobNotApproved)
	}
	if !strings.Contains(found.Spec, chainKey) {
		return fmt.Errorf("NOP %q job %q: %w", alias, found.JobID, ErrJobMissingChain)
	}
	return nil
}

// jobMatches reports whether a job ID belongs to the given kind and qualifier.
func jobMatches(jobID, kind, qualifier string) bool {
	return strings.HasSuffix(jobID, "-"+kind) && strings.Contains(jobID, "-"+qualifier+"-")
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
