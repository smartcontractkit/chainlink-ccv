package preflight_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccipoffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/preflight"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	laneChain   = uint64(6898391096552792247) // ethereum-testnet-sepolia-zksync-1
	remoteChain = uint64(3478487238524512106) // ethereum-testnet-sepolia-arbitrum-1
	nopAlias    = shared.NOPAlias("nop-1")
	committeeQ  = "default"
	executorQ   = "default"
)

// verifierSpecFor builds a job spec that references the given chain selectors, which is
// how a deployed verifier spec records the chains it serves.
func verifierSpecFor(selectors ...uint64) string {
	var spec strings.Builder
	spec.WriteString("[verifier]\n")
	for _, selector := range selectors {
		fmt.Fprintf(&spec, "[verifier.chains.%d]\nenabled = true\n", selector)
	}
	return spec.String()
}

func jobInfo(jobID shared.JobID, spec string, status shared.JobProposalStatus) shared.JobInfo {
	info := shared.JobInfo{
		JobID:    jobID,
		NOPAlias: nopAlias,
		Spec:     spec,
	}
	if status != "" {
		info.ActiveProposalID = "proposal-1"
		info.Proposals = map[string]shared.ProposalRevision{
			"proposal-1": {ProposalID: "proposal-1", Revision: 1, Status: status},
		}
	}
	return info
}

// topologyFor covers both lane chains in one committee and one executor pool.
func topologyFor() *ccipoffchain.EnvironmentTopology {
	chainCommittee := map[string]ccipoffchain.ChainCommitteeConfig{
		fmt.Sprintf("%d", laneChain):   {NOPAliases: []string{string(nopAlias)}, Threshold: 1},
		fmt.Sprintf("%d", remoteChain): {NOPAliases: []string{string(nopAlias)}, Threshold: 1},
	}
	chainPool := map[string]ccipoffchain.ChainExecutorPoolConfig{
		fmt.Sprintf("%d", laneChain):   {NOPAliases: []string{string(nopAlias)}},
		fmt.Sprintf("%d", remoteChain): {NOPAliases: []string{string(nopAlias)}},
	}
	return &ccipoffchain.EnvironmentTopology{
		NOPTopology: &ccipoffchain.NOPTopology{
			NOPs: []ccipoffchain.NOPConfig{{Alias: string(nopAlias), Name: "nop-1-name"}},
			Committees: map[string]ccipoffchain.CommitteeConfig{
				committeeQ: {Qualifier: committeeQ, ChainConfigs: chainCommittee},
			},
		},
		ExecutorPools: map[string]ccipoffchain.ExecutorPoolConfig{
			executorQ: {ChainConfigs: chainPool},
		},
	}
}

func dataStoreWithJobs(t *testing.T, jobs ...shared.JobInfo) datastore.DataStore {
	t.Helper()
	ds := datastore.NewMemoryDataStore()
	if len(jobs) > 0 {
		require.NoError(t, ccvdeployment.SaveJobs(ds, jobs))
	}
	return ds.Seal()
}

// The zkSync <-> Arbitrum lane was configured on chain while zkSync had no committee
// verifier or executor jobs deployed, so messages were never verified.
func TestCheckLaneOffchainReadiness(t *testing.T) {
	verifierJob := shared.JobID(fmt.Sprintf("%s-%s-verifier", nopAlias, committeeQ))
	executorJob := shared.JobID(fmt.Sprintf("%s-%s-executor", nopAlias, executorQ))
	bothChains := verifierSpecFor(laneChain, remoteChain)

	tests := []struct {
		name    string
		jobs    []shared.JobInfo
		wantErr error
	}{
		{
			name: "Success - verifier and executor jobs approved and cover the chain",
			jobs: []shared.JobInfo{
				jobInfo(verifierJob, bothChains, shared.JobProposalStatusApproved),
				jobInfo(executorJob, bothChains, shared.JobProposalStatusApproved),
			},
		},
		{
			name:    "Failure - no jobs deployed at all",
			jobs:    nil,
			wantErr: preflight.ErrNoVerifierJob,
		},
		{
			name: "Failure - verifier job missing for the committee",
			jobs: []shared.JobInfo{
				jobInfo(executorJob, bothChains, shared.JobProposalStatusApproved),
			},
			wantErr: preflight.ErrNoVerifierJob,
		},
		{
			name: "Failure - verifier job still pending approval",
			jobs: []shared.JobInfo{
				jobInfo(verifierJob, bothChains, shared.JobProposalStatusPending),
				jobInfo(executorJob, bothChains, shared.JobProposalStatusApproved),
			},
			wantErr: preflight.ErrJobNotApproved,
		},
		{
			name: "Failure - verifier job rejected",
			jobs: []shared.JobInfo{
				jobInfo(verifierJob, bothChains, shared.JobProposalStatusRejected),
				jobInfo(executorJob, bothChains, shared.JobProposalStatusApproved),
			},
			wantErr: preflight.ErrJobNotApproved,
		},
		{
			name: "Failure - verifier spec does not cover the lane chain",
			jobs: []shared.JobInfo{
				jobInfo(verifierJob, verifierSpecFor(remoteChain), shared.JobProposalStatusApproved),
				jobInfo(executorJob, bothChains, shared.JobProposalStatusApproved),
			},
			wantErr: preflight.ErrJobMissingChain,
		},
		{
			name: "Failure - executor job missing for the pool",
			jobs: []shared.JobInfo{
				jobInfo(verifierJob, bothChains, shared.JobProposalStatusApproved),
			},
			wantErr: preflight.ErrNoExecutorJob,
		},
		{
			name: "Failure - executor spec does not cover the lane chain",
			jobs: []shared.JobInfo{
				jobInfo(verifierJob, bothChains, shared.JobProposalStatusApproved),
				jobInfo(executorJob, verifierSpecFor(remoteChain), shared.JobProposalStatusApproved),
			},
			wantErr: preflight.ErrJobMissingChain,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := preflight.CheckLaneOffchainReadiness(
				dataStoreWithJobs(t, tc.jobs...), topologyFor(), []uint64{laneChain},
			)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Contains(t, err.Error(), fmt.Sprintf("%d", laneChain))
				return
			}
			require.NoError(t, err)
		})
	}
}

// A chain outside every committee and pool is the lane topology check's job, not this
// one, so readiness passes rather than reporting a missing job for it.
func TestCheckLaneOffchainReadiness_ChainNotInTopology(t *testing.T) {
	ds := dataStoreWithJobs(t)
	err := preflight.CheckLaneOffchainReadiness(ds, topologyFor(), []uint64{99})
	require.NoError(t, err)
}
