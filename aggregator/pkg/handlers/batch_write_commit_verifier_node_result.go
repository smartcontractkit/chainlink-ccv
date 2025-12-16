package handlers

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	grpcstatus "google.golang.org/grpc/status"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

// BatchWriteCommitVerifierNodeResultHandler handles requests to write commit verification records.
type BatchWriteCommitVerifierNodeResultHandler struct {
	handler *WriteCommitVerifierNodeResultHandler
}

func (h *BatchWriteCommitVerifierNodeResultHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.handler.l)
}

// Handle processes the write request and saves the commit verification record.
func (h *BatchWriteCommitVerifierNodeResultHandler) Handle(ctx context.Context, req *committeepb.BatchWriteCommitteeVerifierNodeResultRequest) (*committeepb.BatchWriteCommitteeVerifierNodeResultResponse, error) {
	requests := req.GetRequests()
	responses := make([]*committeepb.WriteCommitteeVerifierNodeResultResponse, len(requests))
	errors := NewBatchErrorArray(len(requests))

	wg := sync.WaitGroup{}

	for i, r := range requests {
		wg.Add(1)
		go func(i int, r *committeepb.WriteCommitteeVerifierNodeResultRequest) {
			defer wg.Done()
			resp, err := h.handler.Handle(ctx, r)
			if err != nil {
				statusErr, ok := grpcstatus.FromError(err)
				if !ok {
					h.logger(ctx).Errorf("unexpected error type: %v", err)
					SetBatchError(errors, i, codes.Unknown, "unexpected error")
				} else {
					h.logger(ctx).Errorw("failed to write commit CCV node data", "error", statusErr)
					errors[i] = statusErr.Proto()
				}
			} else {
				SetBatchSuccess(errors, i)
			}
			responses[i] = resp
		}(i, r)
	}

	wg.Wait()
	return &committeepb.BatchWriteCommitteeVerifierNodeResultResponse{
		Responses: responses,
		Errors:    errors,
	}, nil
}

// NewBatchWriteCommitVerifierNodeResultHandler creates a new instance of BatchWriteCommitCCVNodeDataHandler.
func NewBatchWriteCommitVerifierNodeResultHandler(handler *WriteCommitVerifierNodeResultHandler) *BatchWriteCommitVerifierNodeResultHandler {
	return &BatchWriteCommitVerifierNodeResultHandler{
		handler: handler,
	}
}
