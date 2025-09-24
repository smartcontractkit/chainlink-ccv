package handlers

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	aggregator "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// WriteCommitCCVNodeDataHandler handles requests to write commit verification records.
type BatchWriteCommitCCVNodeDataHandler struct {
	handler *WriteCommitCCVNodeDataHandler
}

func (h *BatchWriteCommitCCVNodeDataHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.handler.l)
}

// Handle processes the write request and saves the commit verification record.
func (h *BatchWriteCommitCCVNodeDataHandler) Handle(ctx context.Context, req *aggregator.BatchWriteCommitCCVNodeDataRequest) (*aggregator.BatchWriteCommitCCVNodeDataResponse, error) {
	requests := req.GetRequests()
	responses := make([]*aggregator.WriteCommitCCVNodeDataResponse, len(requests))
	errors := make([]error, len(requests))

	wg := sync.WaitGroup{}

	for i, r := range requests {
		wg.Add(1)
		go func(i int, r *aggregator.WriteCommitCCVNodeDataRequest) {
			defer wg.Done()
			resp, err := h.handler.Handle(ctx, r)
			if err != nil {
				statusErr, ok := status.FromError(err)
				if !ok {
					h.logger(ctx).Errorf("unexpected error type: %v", err)
					errors[i] = status.Error(codes.Unknown, "unexpected error")
				}
				errors[i] = statusErr.Err()
			}
			responses[i] = resp
		}(i, r)
	}

	wg.Wait()
	return &aggregator.BatchWriteCommitCCVNodeDataResponse{
		Responses: responses,
	}, nil
}

// NewBatchWriteCommitCCVNodeDataHandler creates a new instance of BatchWriteCommitCCVNodeDataHandler.
func NewBatchWriteCommitCCVNodeDataHandler(handler *WriteCommitCCVNodeDataHandler) *BatchWriteCommitCCVNodeDataHandler {
	return &BatchWriteCommitCCVNodeDataHandler{
		handler: handler,
	}
}
