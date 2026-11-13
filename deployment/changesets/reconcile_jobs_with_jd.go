package changesets

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// ReconcileJobsWithJDInput lists standalone executor jobs to adopt from JD.
type ReconcileJobsWithJDInput struct {
	Jobs []ReconcileJobWithJD `json:"jobs" yaml:"jobs"`
}

// ReconcileJobWithJD identifies an approved standalone executor job and its spec.
type ReconcileJobWithJD struct {
	NOPAlias    shared.NOPAlias `json:"nop_alias"    yaml:"nop_alias"`
	JobspecPath string          `json:"jobspec_path" yaml:"jobspec_path"`
	NodeID      string          `json:"node_id"      yaml:"node_id"`
}

type reconcileJobRequest struct {
	nopAlias      shared.NOPAlias
	jobspecPath   string
	nodeID        string
	jobID         shared.JobID
	externalJobID string
	spec          string
	jdJob         *jobv1.Job
}

type executorJobSpecEnvelope struct {
	SchemaVersion  int    `toml:"schemaVersion"`
	Type           string `toml:"type"`
	Name           string `toml:"name"`
	ExternalJobID  string `toml:"externalJobID"`
	AppConfig      string `toml:"appConfig"`
	ExecutorConfig string `toml:"executorConfig"`
}

// ReconcileJobsWithJD adopts approved standalone executor jobs without modifying JD.
func ReconcileJobsWithJD() deployment.ChangeSetV2[ReconcileJobsWithJDInput] {
	return deployment.CreateChangeSet(reconcileJobsWithJD, verifyReconcileJobsWithJDPreconditions)
}

func verifyReconcileJobsWithJDPreconditions(e deployment.Environment, input ReconcileJobsWithJDInput) error {
	if e.Offchain == nil {
		return errors.New("offchain client (JD) is required")
	}
	if len(input.Jobs) == 0 {
		return errors.New("no jobs provided in input")
	}

	allowedNodeIDs := make(map[string]struct{}, len(e.NodeIDs))
	for _, nodeID := range e.NodeIDs {
		allowedNodeIDs[nodeID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(input.Jobs))
	for i, job := range input.Jobs {
		if strings.TrimSpace(string(job.NOPAlias)) == "" {
			return fmt.Errorf("jobs[%d]: nop_alias is required", i)
		}
		if strings.TrimSpace(job.JobspecPath) == "" {
			return fmt.Errorf("jobs[%d]: jobspec_path is required", i)
		}
		if strings.TrimSpace(job.NodeID) == "" {
			return fmt.Errorf("jobs[%d]: node_id is required", i)
		}
		if _, ok := allowedNodeIDs[job.NodeID]; !ok {
			return fmt.Errorf("jobs[%d]: node_id %q is not in the environment node list", i, job.NodeID)
		}
		key := string(job.NOPAlias) + "\x00" + job.JobspecPath
		if _, ok := seen[key]; ok {
			return fmt.Errorf("jobs[%d]: duplicate nop_alias and jobspec_path", i)
		}
		seen[key] = struct{}{}
	}

	return nil
}

func reconcileJobsWithJD(e deployment.Environment, input ReconcileJobsWithJDInput) (deployment.ChangesetOutput, error) {
	if err := verifyReconcileJobsWithJDPreconditions(e, input); err != nil {
		return deployment.ChangesetOutput{}, err
	}

	requests := make([]reconcileJobRequest, 0, len(input.Jobs))
	nodeIDs := make([]string, 0, len(input.Jobs))
	seenNodes := make(map[string]struct{}, len(input.Jobs))
	seenJobIDs := make(map[string]struct{}, len(input.Jobs))
	for i, job := range input.Jobs {
		req, err := readStandaloneExecutorJob(job)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("jobs[%d]: %w", i, err)
		}
		key := string(req.nopAlias) + "\x00" + string(req.jobID)
		if _, ok := seenJobIDs[key]; ok {
			return deployment.ChangesetOutput{}, fmt.Errorf("jobs[%d]: duplicate job %q for NOP %q", i, req.jobID, req.nopAlias)
		}
		seenJobIDs[key] = struct{}{}
		if _, ok := seenNodes[req.nodeID]; !ok {
			nodeIDs = append(nodeIDs, req.nodeID)
			seenNodes[req.nodeID] = struct{}{}
		}
		requests = append(requests, req)
	}

	ctx := e.GetContext()
	jobsResp, err := e.Offchain.ListJobs(ctx, &jobv1.ListJobsRequest{
		Filter: &jobv1.ListJobsRequest_Filter{NodeIds: nodeIDs},
	})
	if err != nil {
		return deployment.ChangesetOutput{}, fmt.Errorf("failed to list JD jobs: %w", err)
	}

	for i := range requests {
		req := &requests[i]
		var matches []*jobv1.Job
		for _, job := range jobsResp.GetJobs() {
			if job.GetNodeId() == req.nodeID && job.GetUuid() == req.externalJobID && job.GetDeletedAt() == nil {
				matches = append(matches, job)
			}
		}
		if len(matches) != 1 {
			return deployment.ChangesetOutput{}, fmt.Errorf(
				"job %q: expected exactly one JD job on node %q with external job ID %q, found %d",
				req.jobID, req.nodeID, req.externalJobID, len(matches),
			)
		}
		req.jdJob = matches[0]
	}

	reconciledJobs := make([]shared.JobInfo, 0, len(requests))
	for i := range requests {
		req := &requests[i]
		proposalsResp, err := e.Offchain.ListProposals(ctx, &jobv1.ListProposalsRequest{
			Filter: &jobv1.ListProposalsRequest_Filter{JobIds: []string{req.jdJob.GetId()}},
		})
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("job %q: failed to list proposals for JD job %q: %w", req.jobID, req.jdJob.GetId(), err)
		}

		var proposals []*jobv1.Proposal
		for _, proposal := range proposalsResp.GetProposals() {
			if proposal.GetJobId() == req.jdJob.GetId() {
				proposals = append(proposals, proposal)
			}
		}
		if len(proposals) == 0 {
			return deployment.ChangesetOutput{}, fmt.Errorf("job %q: JD job %q has no proposals", req.jobID, req.jdJob.GetId())
		}

		latest := proposals[0]
		for _, proposal := range proposals[1:] {
			if proposal.GetRevision() > latest.GetRevision() {
				latest = proposal
			}
		}
		if latest.GetStatus() != jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED {
			return deployment.ChangesetOutput{}, fmt.Errorf(
				"job %q: latest proposal %q at revision %d is not approved (status %s)",
				req.jobID, latest.GetId(), latest.GetRevision(), latest.GetStatus().String(),
			)
		}
		if latest.GetSpec() != req.spec {
			return deployment.ChangesetOutput{}, fmt.Errorf(
				"job %q: latest approved proposal %q does not match jobspec %q",
				req.jobID, latest.GetId(), req.jobspecPath,
			)
		}

		for _, proposal := range proposals {
			if proposal.GetId() == "" {
				return deployment.ChangesetOutput{}, fmt.Errorf("job %q: JD returned a proposal with an empty ID", req.jobID)
			}
		}
		info := shared.JobInfo{
			JobID:         req.jobID,
			JDJobID:       req.jdJob.GetId(),
			ExternalJobID: req.externalJobID,
			NOPAlias:      req.nopAlias,
			NodeID:        req.nodeID,
			Mode:          shared.NOPModeStandalone,
			Spec:          latest.GetSpec(),
		}
		info.SetProposalsFromJD(proposals)
		reconciledJobs = append(reconciledJobs, info)
	}

	ds := datastore.NewMemoryDataStore()
	if e.DataStore != nil {
		if err := ds.Merge(e.DataStore); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to clone datastore: %w", err)
		}
	}
	if err := ccvdeployment.SaveJobs(ds, reconciledJobs); err != nil {
		return deployment.ChangesetOutput{}, fmt.Errorf("failed to save reconciled jobs: %w", err)
	}

	for _, job := range reconciledJobs {
		e.Logger.Infow("Reconciled standalone executor job from JD",
			"nopAlias", job.NOPAlias,
			"jobId", job.JobID,
			"jdJobId", job.JDJobID,
			"nodeId", job.NodeID,
			"activeProposalId", job.ActiveProposalID,
		)
	}

	return deployment.ChangesetOutput{DataStore: ds}, nil
}

func readStandaloneExecutorJob(input ReconcileJobWithJD) (reconcileJobRequest, error) {
	req := reconcileJobRequest{
		nopAlias:    input.NOPAlias,
		jobspecPath: input.JobspecPath,
		nodeID:      input.NodeID,
	}

	specBytes, err := os.ReadFile(input.JobspecPath)
	if err != nil {
		return req, fmt.Errorf("failed to read jobspec %q: %w", input.JobspecPath, err)
	}
	req.spec = string(specBytes)

	var envelope executorJobSpecEnvelope
	if _, err := toml.Decode(req.spec, &envelope); err != nil {
		return req, fmt.Errorf("failed to parse jobspec %q: %w", input.JobspecPath, err)
	}
	if envelope.SchemaVersion != 1 {
		return req, fmt.Errorf("jobspec %q has schemaVersion %d, want 1", input.JobspecPath, envelope.SchemaVersion)
	}
	if envelope.Type != executorJobType {
		return req, fmt.Errorf("jobspec %q has type %q, want %s", input.JobspecPath, envelope.Type, executorJobType)
	}
	if envelope.AppConfig == "" || envelope.ExecutorConfig != "" {
		return req, fmt.Errorf("jobspec %q must contain appConfig and no executorConfig for a standalone executor", input.JobspecPath)
	}
	if !strings.HasPrefix(envelope.Name, string(input.NOPAlias)+"-") || !strings.HasSuffix(envelope.Name, "-executor") {
		return req, fmt.Errorf("jobspec %q name %q is not an executor job for NOP %q", input.JobspecPath, envelope.Name, input.NOPAlias)
	}

	var appConfig struct {
		ExecutorID string `toml:"executor_id"`
	}
	if _, err := toml.Decode(envelope.AppConfig, &appConfig); err != nil {
		return req, fmt.Errorf("failed to parse appConfig in jobspec %q: %w", input.JobspecPath, err)
	}
	if appConfig.ExecutorID != string(input.NOPAlias) {
		return req, fmt.Errorf("jobspec %q executor_id %q does not match NOP %q", input.JobspecPath, appConfig.ExecutorID, input.NOPAlias)
	}

	req.jobID = shared.JobID(envelope.Name)
	req.externalJobID = envelope.ExternalJobID
	if expected := req.jobID.ToExternalJobID(); envelope.ExternalJobID != expected {
		return req, fmt.Errorf("jobspec %q externalJobID %q does not match job name %q (expected %q)", input.JobspecPath, envelope.ExternalJobID, envelope.Name, expected)
	}

	return req, nil
}
