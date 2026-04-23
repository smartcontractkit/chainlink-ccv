package changesets

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/sequences"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// runOrphanJobCleanup is the shared implementation used by changesets when there are
// no chains to apply for the targeted scope. If revokeOrphanedJobs is false, it
// simply returns the merged datastore unchanged. Otherwise it invokes the manage-
// job-proposals sequence with empty JobSpecs to revoke any orphaned jobs.
func runOrphanJobCleanup(
	e deployment.Environment,
	revokeOrphanedJobs bool,
	scope shared.JobScope,
	labels map[string]string,
	nopModes map[shared.NOPAlias]shared.NOPMode,
	targetNOPs []shared.NOPAlias,
	allNOPs []shared.NOPAlias,
	noopMessage string,
	cleanupMessage string,
	logKeysAndValues ...any,
) (deployment.ChangesetOutput, error) {
	if !revokeOrphanedJobs {
		e.Logger.Infow(noopMessage, logKeysAndValues...)
		ds := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := ds.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge datastore: %w", err)
			}
		}
		return deployment.ChangesetOutput{DataStore: ds}, nil
	}

	e.Logger.Infow(cleanupMessage, logKeysAndValues...)
	manageReport, err := operations.ExecuteSequence(
		e.OperationsBundle,
		sequences.ManageJobProposals,
		sequences.ManageJobProposalsDeps{Env: e},
		sequences.ManageJobProposalsInput{
			JobSpecs:      nil,
			AffectedScope: scope,
			Labels:        labels,
			NOPs: sequences.NOPContext{
				Modes:      nopModes,
				TargetNOPs: targetNOPs,
				AllNOPs:    allNOPs,
			},
			RevokeOrphanedJobs: true,
		},
	)
	if err != nil {
		return deployment.ChangesetOutput{Reports: manageReport.ExecutionReports},
			fmt.Errorf("failed to manage job proposals (orphan cleanup): %w", err)
	}
	return deployment.ChangesetOutput{
		Reports:   manageReport.ExecutionReports,
		DataStore: manageReport.Output.DataStore,
	}, nil
}
