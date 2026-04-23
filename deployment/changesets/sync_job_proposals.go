package changesets

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	syncjobproposals "github.com/smartcontractkit/chainlink-ccv/deployment/operations/sync_job_proposals"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type SyncJobProposalsInput struct {
	NOPAliases []shared.NOPAlias
}

func SyncJobProposals() deployment.ChangeSetV2[SyncJobProposalsInput] {
	validate := func(e deployment.Environment, cfg SyncJobProposalsInput) error {
		if e.Offchain == nil {
			return fmt.Errorf("offchain client (JD) is required for syncing job proposals")
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg SyncJobProposalsInput) (deployment.ChangesetOutput, error) {
		report, err := operations.ExecuteOperation(
			e.OperationsBundle,
			syncjobproposals.SyncJobProposals,
			syncjobproposals.SyncJobProposalsDeps{Env: e},
			syncjobproposals.SyncJobProposalsInput{NOPAliases: cfg.NOPAliases},
		)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to sync job proposals: %w", err)
		}

		e.Logger.Infow("Job proposals synced",
			"statusChanges", len(report.Output.StatusChanges),
			"specDrifts", len(report.Output.SpecDrifts),
			"errors", len(report.Output.Errors))

		if len(report.Output.SpecDrifts) > 0 {
			e.Logger.Warnw("Spec drift detected between local and JD",
				"driftCount", len(report.Output.SpecDrifts))
			for _, drift := range report.Output.SpecDrifts {
				e.Logger.Warnw("Spec drift detail",
					"nopAlias", drift.NOPAlias,
					"jobId", drift.JobID,
					"localSpec", drift.LocalSpec,
					"jdSpec", drift.JDSpec,
				)
			}
		}

		return deployment.ChangesetOutput{
			DataStore: report.Output.DataStore,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
