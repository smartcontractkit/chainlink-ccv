package shared

import (
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
)

// ProposalStatusFromJD maps a JD proposal status onto the local status set.
func ProposalStatusFromJD(status jobv1.ProposalStatus) JobProposalStatus {
	switch status {
	case jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED:
		return JobProposalStatusApproved
	case jobv1.ProposalStatus_PROPOSAL_STATUS_REJECTED:
		return JobProposalStatusRejected
	case jobv1.ProposalStatus_PROPOSAL_STATUS_REVOKED, jobv1.ProposalStatus_PROPOSAL_STATUS_CANCELLED:
		return JobProposalStatusRevoked
	default:
		return JobProposalStatusPending
	}
}

// SetProposalsFromJD replaces the job's proposals with JD's proposals for its JD job.
// The active proposal becomes the highest approved revision, or none.
func (j *JobInfo) SetProposalsFromJD(proposals []*jobv1.Proposal) {
	j.Proposals = make(map[string]ProposalRevision, len(proposals))
	j.ActiveProposalID = ""
	var activeRevision int64
	for _, p := range proposals {
		if p.GetId() == "" || (p.GetJobId() != "" && p.GetJobId() != j.JDJobID) {
			continue
		}
		status := ProposalStatusFromJD(p.GetStatus())
		j.Proposals[p.GetId()] = ProposalRevision{
			ProposalID: p.GetId(),
			Revision:   p.GetRevision(),
			Status:     status,
			Spec:       p.GetSpec(),
		}
		if status == JobProposalStatusApproved && (j.ActiveProposalID == "" || p.GetRevision() > activeRevision) {
			j.ActiveProposalID = p.GetId()
			activeRevision = p.GetRevision()
		}
	}
}
