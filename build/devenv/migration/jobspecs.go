package migration

import (
	"context"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobspec"
)

// standaloneConfigField is the job spec envelope field a standalone bootstrapper reads. CL-mode
// specs carry the same inner config under committeeVerifierConfig or executorConfig, which the
// bootstrapper's JobSpec does not decode.
const standaloneConfigField = "appConfig"

// RetargetVerifierJobSpec converts a CL-mode committee verifier job spec into the standalone shape.
//
// Only the envelope field changes; the inner config, the job name, and crucially the externalJobID
// are preserved. That last part is what makes this a migration rather than a re-deployment: JD sees
// a new revision of the job the operator already runs, so the job keeps its identity and history
// instead of appearing alongside a second one.
//
// A spec that is already in the standalone shape converts to itself.
func RetargetVerifierJobSpec(spec string) (string, error) {
	parsed, err := jobspec.ParseVerifierBootstrapJobSpec(spec)
	if err != nil {
		return "", fmt.Errorf("failed to parse committee verifier job spec: %w", err)
	}
	return retarget(parsed), nil
}

// RetargetExecutorJobSpec converts a CL-mode executor job spec into the standalone shape. See
// RetargetVerifierJobSpec for what is and is not preserved.
func RetargetExecutorJobSpec(spec string) (string, error) {
	parsed, err := jobspec.ParseExecutorBootstrapJobSpec(spec)
	if err != nil {
		return "", fmt.Errorf("failed to parse executor job spec: %w", err)
	}
	return retarget(parsed), nil
}

// retarget re-emits a parsed spec under the standalone envelope, carrying the inner config across as
// text.
//
// Moving the text rather than decoding and re-marshaling it is deliberate. The migration's promise
// is that the operator's job runs the same configuration after the cutover as before, and a round
// trip through a Go struct cannot keep it: a key the struct does not declare is dropped silently,
// and a key whose type has changed since the spec was written fails the whole cutover. Neither is
// acceptable for config that is already running. The envelope field is the one thing that has to
// change, so it is the only thing that does.
//
// Nothing validates the inner config here for the same reason. It is running on the node today, and
// the standalone process validates it at startup; rejecting it midway through a cutover, against a
// schema the operator never opted into, would strand the migration between two modes.
func retarget(parsed bootstrap.JobSpec) string {
	inner := parsed.AppConfig
	// The closing delimiter has to start its own line, which the inner config's own trailing newline
	// normally provides. A spec written without one would otherwise produce ...last_key = "v"''' .
	if !strings.HasSuffix(inner, "\n") {
		inner += "\n"
	}
	return fmt.Sprintf(`schemaVersion = %d
type = "%s"
name = "%s"
externalJobID = "%s"
%s = '''
%s'''
`, parsed.SchemaVersion, parsed.Type, parsed.Name, parsed.ExternalJobID, standaloneConfigField, inner)
}

// JobTypeVerifier and JobTypeExecutor are the JD job spec types this migration handles.
const (
	JobTypeVerifier = "ccvcommitteeverifier"
	JobTypeExecutor = "ccvexecutor"
)

// RetargetJobSpec converts a job spec to the standalone envelope, dispatching on its declared type.
// A type this migration does not handle is an error rather than a pass-through, so an unexpected
// job on a migrating node is surfaced instead of being proposed unchanged to a process that cannot
// run it.
func RetargetJobSpec(spec string) (string, error) {
	jobType, err := JobSpecType(spec)
	if err != nil {
		return "", err
	}
	switch jobType {
	case JobTypeVerifier:
		return RetargetVerifierJobSpec(spec)
	case JobTypeExecutor:
		return RetargetExecutorJobSpec(spec)
	default:
		return "", fmt.Errorf("job spec type %q is not part of the CL-to-standalone migration", jobType)
	}
}

// JobSpecType reads the declared type of a job spec. Callers route on this rather than searching
// the spec text, which would match a type name appearing anywhere in the embedded config.
func JobSpecType(spec string) (string, error) {
	var envelope struct {
		Type string `toml:"type"`
	}
	if _, err := toml.Decode(spec, &envelope); err != nil {
		return "", fmt.Errorf("failed to read job spec type: %w", err)
	}
	return envelope.Type, nil
}

// NodeJobSpec is a job currently assigned to a JD node, with the spec of its latest proposal.
type NodeJobSpec struct {
	// JobID is JD's identifier for the job, stable across proposal revisions.
	JobID string
	// Spec is the latest proposal's spec, in whatever envelope it was proposed with.
	Spec string
}

// FetchNodeJobSpecs returns the jobs JD has assigned to a node, each with its highest-revision
// proposal spec.
//
// The cutover reads the operator's existing CL-mode specs from JD rather than regenerating them
// from the topology. Regenerating would produce a spec derived from current deployment inputs,
// which is not necessarily the spec the operator is running; retargeting what JD already holds
// changes exactly one thing, the envelope field, and leaves everything the operator's jobs are
// actually configured with untouched.
func FetchNodeJobSpecs(ctx context.Context, jdClient offchain.Client, nodeID string) ([]NodeJobSpec, error) {
	if jdClient == nil {
		return nil, fmt.Errorf("JD client is required to fetch job specs")
	}
	if nodeID == "" {
		return nil, fmt.Errorf("node ID is required to fetch job specs")
	}

	jobsResp, err := jdClient.ListJobs(ctx, &jobv1.ListJobsRequest{
		Filter: &jobv1.ListJobsRequest_Filter{NodeIds: []string{nodeID}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list JD jobs for node %s: %w", nodeID, err)
	}
	jobIDs := make([]string, 0, len(jobsResp.GetJobs()))
	for _, job := range jobsResp.GetJobs() {
		jobIDs = append(jobIDs, job.GetId())
	}
	if len(jobIDs) == 0 {
		return nil, nil
	}

	proposalsResp, err := jdClient.ListProposals(ctx, &jobv1.ListProposalsRequest{
		Filter: &jobv1.ListProposalsRequest_Filter{JobIds: jobIDs},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list JD proposals for node %s: %w", nodeID, err)
	}

	// Keep the highest revision per job: a job that has been re-proposed carries several, and only
	// the newest describes what the node is running.
	latest := make(map[string]*jobv1.Proposal, len(jobIDs))
	for _, proposal := range proposalsResp.GetProposals() {
		current, ok := latest[proposal.GetJobId()]
		if !ok || proposal.GetRevision() > current.GetRevision() {
			latest[proposal.GetJobId()] = proposal
		}
	}

	specs := make([]NodeJobSpec, 0, len(latest))
	for _, jobID := range jobIDs {
		proposal, ok := latest[jobID]
		if !ok || proposal.GetSpec() == "" {
			continue
		}
		specs = append(specs, NodeJobSpec{JobID: jobID, Spec: proposal.GetSpec()})
	}
	return specs, nil
}

// JobProposal is one retargeted spec and the JD node that should receive it.
type JobProposal struct {
	// NodeID is the JD node record the spec is proposed to: the adopted record for a verifier job,
	// the newly registered executor record for an executor job.
	NodeID string
	// Spec is the standalone-shaped job spec.
	Spec string
	// Label names the job in error messages.
	Label string
}

// ProposeJobs sends each retargeted spec to its node.
//
// No approval step follows. A CL node holds a proposal until an operator accepts it, but a
// standalone bootstrapper's lifecycle manager approves and starts what JD sends it, so proposing is
// the whole handover.
func ProposeJobs(ctx context.Context, jdClient offchain.Client, proposals []JobProposal) error {
	if jdClient == nil {
		return fmt.Errorf("JD client is required to propose jobs")
	}
	for _, proposal := range proposals {
		if proposal.NodeID == "" {
			return fmt.Errorf("job %s has no target JD node", proposal.Label)
		}
		if _, err := jdClient.ProposeJob(ctx, &jobv1.ProposeJobRequest{
			NodeId: proposal.NodeID,
			Spec:   proposal.Spec,
		}); err != nil {
			return fmt.Errorf("failed to propose job %s to JD node %s: %w", proposal.Label, proposal.NodeID, err)
		}
	}
	return nil
}
