package sequences

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/propose_jobs"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/revoke_jobs"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type NOPContext struct {
	Modes      map[shared.NOPAlias]shared.NOPMode
	TargetNOPs []shared.NOPAlias
	AllNOPs    []shared.NOPAlias
}

type ManageJobProposalsInput struct {
	JobSpecs      shared.NOPJobSpecs
	AffectedScope shared.JobScope
	Labels        map[string]string
	NOPs          NOPContext
	// StandaloneExecutorNodeIDs routes standalone executor jobs by JD node ID, not NOP name.
	StandaloneExecutorNodeIDs map[shared.JobID]string
	// RevokeOrphanedJobs when true runs orphan collection, JD revoke, and datastore cleanup; default false.
	RevokeOrphanedJobs bool
	// AllowMissingJD permits running without a Job Distributor (e.Offchain == nil): the generated job
	// specs are persisted to the datastore so callers can read them (e.g. devenv delivers them to
	// services as mounted files in the no-JD local mode), and proposing/revoking — which require JD —
	// are skipped. When false (default), a nil offchain client is an error, as job proposal is the
	// sequence's purpose.
	AllowMissingJD bool
}

type ManageJobProposalsOutput struct {
	Jobs        []shared.JobInfo
	RevokedJobs []shared.JobInfo
	DataStore   datastore.MutableDataStore
}

type ManageJobProposalsDeps struct {
	Env deployment.Environment
}

var ManageJobProposals = operations.NewSequence(
	"manage-job-proposals",
	semver.MustParse("1.0.0"),
	"Manages job proposals by proposing new jobs and optionally revoking orphaned ones via JD when RevokeOrphanedJobs is enabled",
	func(b operations.Bundle, deps ManageJobProposalsDeps, input ManageJobProposalsInput) (ManageJobProposalsOutput, error) {
		e := deps.Env

		ds := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := ds.Merge(e.DataStore); err != nil {
				return ManageJobProposalsOutput{}, fmt.Errorf("failed to merge datastore: %w", err)
			}
		}

		existingJobs, err := ccvdeployment.GetAllJobs(ds.Seal())
		if err != nil {
			e.Logger.Warnw("Failed to load existing jobs, will propose all jobs", "error", err)
			existingJobs = nil
		}

		jobs := buildJobsFromJobSpecs(input.JobSpecs, input.NOPs.Modes)
		carryForwardExistingJobMetadata(jobs, existingJobs)

		if e.Offchain == nil {
			if !input.AllowMissingJD {
				return ManageJobProposalsOutput{}, fmt.Errorf("NOPs require JD but e.Offchain is nil")
			}
			// No Job Distributor (local mode): persist the generated job specs so callers can read
			// them (devenv delivers them to services as mounted files), and skip proposing/revoking,
			// which require JD.
			e.Logger.Infow("manage-job-proposals: no offchain (JD) client; saving job specs without proposing (AllowMissingJD)", "jobs", len(jobs))
			if err := ccvdeployment.SaveJobs(ds, jobs); err != nil {
				return ManageJobProposalsOutput{}, fmt.Errorf("failed to save jobs: %w", err)
			}
			return ManageJobProposalsOutput{Jobs: jobs, DataStore: ds}, nil
		}

		if _, err := ccvdeployment.SyncJDNodes(b.GetContext(), ds, e.Offchain, "ccv", e.Name); err != nil {
			return ManageJobProposalsOutput{}, fmt.Errorf("failed to sync JD node inventory: %w", err)
		}

		superseded, err := retargetJobs(b.GetContext(), e.Offchain, jobs, input.StandaloneExecutorNodeIDs)
		if err != nil {
			return ManageJobProposalsOutput{}, err
		}
		if err := refreshJobsFromJD(b.GetContext(), e.Offchain, jobs); err != nil {
			return ManageJobProposalsOutput{}, err
		}

		changedJobs := filterChangedJobs(jobs, existingJobs, input.StandaloneExecutorNodeIDs)
		if len(changedJobs) < len(jobs) {
			e.Logger.Infow("Skipping unchanged jobs", "total", len(jobs), "changed", len(changedJobs), "skipped", len(jobs)-len(changedJobs))
		}

		jobSpecs := make([]propose_jobs.JobSpecInput, 0)
		for _, job := range changedJobs {
			jobSpecs = append(jobSpecs, propose_jobs.JobSpecInput{
				NOPAlias:      job.NOPAlias,
				InternalJobID: job.JobID,
				Spec:          job.Spec,
				NodeID:        input.StandaloneExecutorNodeIDs[job.JobID],
			})
		}

		proposeReport, err := operations.ExecuteOperation(
			b,
			propose_jobs.ProposeJobs,
			propose_jobs.ProposeJobsDeps{
				JDClient: e.Offchain,
				Logger:   e.Logger,
				NodeIDs:  e.NodeIDs,
			},
			propose_jobs.ProposeJobsInput{
				JobSpecs: jobSpecs,
				Labels:   input.Labels,
			},
		)
		if err != nil {
			return ManageJobProposalsOutput{}, fmt.Errorf("failed to propose jobs: %w", err)
		}

		superseded = append(superseded, updateJobsWithJDResponse(jobs, proposeReport.Output.ProposedJobs)...)
		for _, old := range superseded {
			e.Logger.Warnw("Job moved to a new JD job; the previous JD job is no longer tracked and was left in JD",
				"jobId", old.JobID,
				"nopAlias", old.NOPAlias,
				"previousJdJobId", old.JDJobID,
				"previousNodeId", old.NodeID)
		}

		if err := ccvdeployment.SaveJobs(ds, jobs); err != nil {
			return ManageJobProposalsOutput{}, fmt.Errorf("failed to save jobs: %w", err)
		}

		var revokedJobs []shared.JobInfo

		if !input.RevokeOrphanedJobs {
			e.Logger.Debugw("Skipping orphan job revocation (RevokeOrphanedJobs=false)")
		} else {
			expectedJobsByNOP := extractExpectedJobsByNOP(jobs)

			orphanedJobs, err := ccvdeployment.CollectOrphanedJobs(
				ds.Seal(),
				input.AffectedScope,
				expectedJobsByNOP,
				shared.NOPAliasSliceToSet(input.NOPs.TargetNOPs),
				shared.NOPAliasSliceToSet(input.NOPs.AllNOPs),
			)
			if err != nil {
				e.Logger.Warnw("Failed to collect orphaned jobs", "error", err)
				orphanedJobs = nil
			}

			if len(orphanedJobs) > 0 {
				jobsNeedingRevoke := filterNonRevokedJobs(orphanedJobs)
				if len(jobsNeedingRevoke) > 0 {
					revokeReport, revokeErr := operations.ExecuteOperation(
						b,
						revoke_jobs.RevokeJobs,
						revoke_jobs.RevokeJobsDeps{
							JDClient: e.Offchain,
							Logger:   e.Logger,
							NodeIDs:  e.NodeIDs,
						},
						revoke_jobs.RevokeJobsInput{
							Jobs: jobsNeedingRevoke,
						},
					)
					if revokeErr != nil {
						return ManageJobProposalsOutput{
							Jobs:      jobs,
							DataStore: ds,
						}, fmt.Errorf("failed to revoke orphaned jobs: %w", revokeErr)
					}
					e.Logger.Infow("Revoked orphaned jobs", "count", len(revokeReport.Output.RevokedJobs))
				}

				if cleanupErr := ccvdeployment.CleanupOrphanedJobs(ds, orphanedJobs); cleanupErr != nil {
					return ManageJobProposalsOutput{
						Jobs:      jobs,
						DataStore: ds,
					}, fmt.Errorf("failed to cleanup orphaned jobs: %w", cleanupErr)
				}
				revokedJobs = orphanedJobs
			}
		}

		return ManageJobProposalsOutput{
			Jobs:        jobs,
			RevokedJobs: revokedJobs,
			DataStore:   ds,
		}, nil
	},
)

func buildJobsFromJobSpecs(jobSpecs shared.NOPJobSpecs, nopModes map[shared.NOPAlias]shared.NOPMode) []shared.JobInfo {
	totalJobs := 0
	for _, jobSpecsByID := range jobSpecs {
		totalJobs += len(jobSpecsByID)
	}
	jobs := make([]shared.JobInfo, 0, totalJobs)

	for nopAlias, jobSpecsByID := range jobSpecs {
		mode := nopModes[nopAlias]
		if mode == "" {
			mode = shared.NOPModeCL
		}

		for jobID, spec := range jobSpecsByID {
			job := shared.JobInfo{
				Spec:          spec,
				ExternalJobID: jobID.ToExternalJobID(),
				JobID:         jobID,
				NOPAlias:      nopAlias,
				Mode:          mode,
				Proposals:     make(map[string]shared.ProposalRevision),
			}
			jobs = append(jobs, job)
		}
	}

	return jobs
}

// updateJobsWithJDResponse records each proposal and returns the jobs whose JD job was replaced.
// A new JD job (for example on a different node) starts a fresh proposal history.
func updateJobsWithJDResponse(jobs []shared.JobInfo, proposedJobs []propose_jobs.ProposedJob) []shared.JobInfo {
	proposedJobMap := make(map[shared.JobID]propose_jobs.ProposedJob, len(proposedJobs))
	for _, pj := range proposedJobs {
		proposedJobMap[pj.InternalJobID] = pj
	}

	var superseded []shared.JobInfo
	for i := range jobs {
		pj, ok := proposedJobMap[jobs[i].JobID]
		if !ok {
			continue
		}
		if jobs[i].JDJobID != pj.JobID {
			if jobs[i].JDJobID != "" {
				superseded = append(superseded, jobs[i])
			}
			jobs[i].Proposals = nil
			jobs[i].ActiveProposalID = ""
		}
		jobs[i].JDJobID = pj.JobID
		jobs[i].NodeID = pj.NodeID
		jobs[i].AddProposal(shared.ProposalRevision{
			ProposalID: pj.ProposalID,
			Revision:   pj.Revision,
			Status:     shared.JobProposalStatusPending,
			Spec:       pj.Spec,
		})
	}
	return superseded
}

// jdJobLister lists JD jobs; offchain.Client satisfies it.
type jdJobLister interface {
	ListJobs(ctx context.Context, in *jobv1.ListJobsRequest, opts ...grpc.CallOption) (*jobv1.ListJobsResponse, error)
}

// retargetJobs points each job routed to a different node at that node's live JD job for it, if any,
// and returns the jobs whose recorded JD job was left behind. An adopted job is compared, not re-proposed.
func retargetJobs(ctx context.Context, jd jdJobLister, jobs []shared.JobInfo, targets map[shared.JobID]string) ([]shared.JobInfo, error) {
	var superseded []shared.JobInfo
	for i := range jobs {
		target := targets[jobs[i].JobID]
		if target == "" || target == jobs[i].NodeID {
			continue
		}
		jdJobID, err := liveJDJobOnNode(ctx, jd, target, jobs[i].ExternalJobID)
		if err != nil {
			return nil, fmt.Errorf("job %s: %w", jobs[i].JobID, err)
		}
		if jobs[i].JDJobID != "" && jobs[i].JDJobID != jdJobID {
			superseded = append(superseded, jobs[i])
		}
		jobs[i].JDJobID = jdJobID
		jobs[i].NodeID = target
		jobs[i].Proposals = nil
		jobs[i].ActiveProposalID = ""
	}
	return superseded, nil
}

// liveJDJobOnNode returns the undeleted JD job on nodeID with the given external job ID, or "".
func liveJDJobOnNode(ctx context.Context, jd jdJobLister, nodeID, externalJobID string) (string, error) {
	resp, err := jd.ListJobs(ctx, &jobv1.ListJobsRequest{Filter: &jobv1.ListJobsRequest_Filter{NodeIds: []string{nodeID}}})
	if err != nil {
		return "", fmt.Errorf("failed to list JD jobs on node %s: %w", nodeID, err)
	}
	var found []string
	for _, job := range resp.GetJobs() {
		if job.GetNodeId() == nodeID && job.GetUuid() == externalJobID && job.GetDeletedAt() == nil {
			found = append(found, job.GetId())
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("node %s has %d live JD jobs with external job ID %s", nodeID, len(found), externalJobID)
	}
}

// refreshJobsFromJD replaces each recorded JD job's proposals with JD's current view.
// A recorded JD job that JD no longer has is cleared, so it is proposed again.
func refreshJobsFromJD(ctx context.Context, jd shared.JDClient, jobs []shared.JobInfo) error {
	for i := range jobs {
		if jobs[i].JDJobID == "" {
			continue
		}
		resp, err := jd.ListProposals(ctx, &jobv1.ListProposalsRequest{
			Filter: &jobv1.ListProposalsRequest_Filter{JobIds: []string{jobs[i].JDJobID}},
		})
		if err != nil {
			return fmt.Errorf("failed to list JD proposals for job %s (JD job %s): %w", jobs[i].JobID, jobs[i].JDJobID, err)
		}
		jobs[i].SetProposalsFromJD(resp.GetProposals())
		if len(jobs[i].Proposals) == 0 {
			jobs[i].JDJobID = ""
		}
	}
	return nil
}

func extractExpectedJobsByNOP(jobs []shared.JobInfo) map[shared.NOPAlias]map[shared.JobID]bool {
	result := make(map[shared.NOPAlias]map[shared.JobID]bool)
	for _, job := range jobs {
		if result[job.NOPAlias] == nil {
			result[job.NOPAlias] = make(map[shared.JobID]bool)
		}
		result[job.NOPAlias][job.JobID] = true
	}
	return result
}

func carryForwardExistingJobMetadata(jobs []shared.JobInfo, existingJobs shared.NOPJobs) {
	if existingJobs == nil {
		return
	}
	for i := range jobs {
		nopJobs, ok := existingJobs[jobs[i].NOPAlias]
		if !ok {
			continue
		}
		existing, ok := nopJobs[jobs[i].JobID]
		if !ok {
			continue
		}
		jobs[i].JDJobID = existing.JDJobID
		jobs[i].NodeID = existing.NodeID
		jobs[i].ActiveProposalID = existing.ActiveProposalID
		jobs[i].Proposals = existing.Proposals
	}
}

func filterNonRevokedJobs(jobs []shared.JobInfo) []shared.JobInfo {
	result := make([]shared.JobInfo, 0, len(jobs))
	for _, j := range jobs {
		if j.LatestStatus() != shared.JobProposalStatusRevoked {
			result = append(result, j)
		}
	}
	return result
}

// filterChangedJobs returns the jobs whose desired spec or node differs from JD's latest proposal.
// Jobs carry JD metadata refreshed from JD; the stored record is used only when JD's spec is unknown.
func filterChangedJobs(jobs []shared.JobInfo, existingJobs shared.NOPJobs, targetNodeIDs map[shared.JobID]string) []shared.JobInfo {
	changed := make([]shared.JobInfo, 0, len(jobs))
	for _, job := range jobs {
		existing, exists := existingJobs[job.NOPAlias][job.JobID]
		latest := job.LatestProposal()
		targetNodeID := targetNodeIDs[job.JobID]
		switch {
		case job.JDJobID == "", latest == nil:
			changed = append(changed, job)
		case targetNodeID != "" && targetNodeID != job.NodeID:
			changed = append(changed, job)
		case latest.Spec != "":
			if latest.Spec != job.Spec {
				changed = append(changed, job)
			}
		case !exists, existing.Mode != job.Mode, existing.Spec != job.Spec:
			changed = append(changed, job)
		}
	}
	return changed
}
