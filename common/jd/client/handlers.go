package client

import (
	"context"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// handlers implements the NodeServiceServer interface for receiving job proposals from JD.
type handlers struct {
	jobProposalCh chan<- *pb.ProposeJobRequest
	deleteJobCh   chan<- *pb.DeleteJobRequest
	revokeJobCh   chan<- *pb.RevokeJobRequest
	lggr          logger.Logger
}

// Ensure handlers implements NodeServiceServer.
var _ pb.NodeServiceServer = (*handlers)(nil)

// newHandlers creates a new handlers instance.
func newHandlers(
	jobProposalCh chan<- *pb.ProposeJobRequest,
	deleteJobCh chan<- *pb.DeleteJobRequest,
	revokeJobCh chan<- *pb.RevokeJobRequest,
	lggr logger.Logger,
) *handlers {
	return &handlers{
		jobProposalCh: jobProposalCh,
		deleteJobCh:   deleteJobCh,
		revokeJobCh:   revokeJobCh,
		lggr:          lggr,
	}
}

// ProposeJob handles incoming job proposals from the Job Distributor.
func (h *handlers) ProposeJob(ctx context.Context, req *pb.ProposeJobRequest) (*pb.ProposeJobResponse, error) {
	h.lggr.Infow("Received job proposal",
		"id", req.Id,
		"version", req.Version,
		"specLength", len(req.Spec),
	)

	// Send the proposal to the channel for processing
	select {
	case h.jobProposalCh <- req:
		h.lggr.Infow("Job proposal queued", "id", req.Id)
	case <-ctx.Done():
		h.lggr.Warnw("Context cancelled while queueing job proposal", "id", req.Id)
		return nil, ctx.Err()
	}

	return &pb.ProposeJobResponse{}, nil
}

// DeleteJob handles job deletion requests from the Job Distributor.
func (h *handlers) DeleteJob(ctx context.Context, req *pb.DeleteJobRequest) (*pb.DeleteJobResponse, error) {
	h.lggr.Infow("Received delete job request", "id", req.Id)

	// Send the delete request to the channel for processing
	select {
	case h.deleteJobCh <- req:
		h.lggr.Infow("Delete job request queued", "id", req.Id)
	case <-ctx.Done():
		h.lggr.Warnw("Context cancelled while queueing delete job request", "id", req.Id)
		return nil, ctx.Err()
	}

	return &pb.DeleteJobResponse{}, nil
}

// RevokeJob handles job revocation requests from the Job Distributor.
func (h *handlers) RevokeJob(ctx context.Context, req *pb.RevokeJobRequest) (*pb.RevokeJobResponse, error) {
	h.lggr.Infow("Received revoke job request", "id", req.Id)

	// Send the revoke request to the channel for processing
	select {
	case h.revokeJobCh <- req:
		h.lggr.Infow("Revoke job request queued", "id", req.Id)
	case <-ctx.Done():
		h.lggr.Warnw("Context cancelled while queueing revoke job request", "id", req.Id)
		return nil, ctx.Err()
	}

	return &pb.RevokeJobResponse{}, nil
}

// GetJobRuns returns job run information.
// For standalone, we don't track individual job runs.
func (h *handlers) GetJobRuns(ctx context.Context, req *pb.GetJobRunsRequest) (*pb.GetJobRunsResponse, error) {
	h.lggr.Debugw("Received get job runs request", "id", req.Id)
	// Return empty list - standalone don't track job runs
	return &pb.GetJobRunsResponse{
		Runs: []*pb.JobRunSummary{},
	}, nil
}
