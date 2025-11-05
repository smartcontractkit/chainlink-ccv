package handlers

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1" //nolint:gci
	grpcstatus "google.golang.org/grpc/status"                            //nolint:gci
)

// WriteCommitCCVNodeDataHandler handles requests to write commit verification records.
type BatchWriteCommitCCVNodeDataHandler struct {
	handler *WriteCommitCCVNodeDataHandler
}

func (h *BatchWriteCommitCCVNodeDataHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.handler.l)
}

// Handle processes the write request and saves the commit verification record.
func (h *BatchWriteCommitCCVNodeDataHandler) Handle(ctx context.Context, req *pb.BatchWriteCommitCCVNodeDataRequest) (*pb.BatchWriteCommitCCVNodeDataResponse, error) {
	requests := req.GetRequests()
	responses := make([]*pb.WriteCommitCCVNodeDataResponse, len(requests))
	errors := NewBatchErrorArray(len(requests))

	wg := sync.WaitGroup{}

	for i, r := range requests {
		wg.Add(1)
		go func(i int, r *pb.WriteCommitCCVNodeDataRequest) {
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
	return &pb.BatchWriteCommitCCVNodeDataResponse{
		Responses: responses,
		Errors:    errors,
	}, nil
}

// NewBatchWriteCommitCCVNodeDataHandler creates a new instance of BatchWriteCommitCCVNodeDataHandler.
func NewBatchWriteCommitCCVNodeDataHandler(handler *WriteCommitCCVNodeDataHandler) *BatchWriteCommitCCVNodeDataHandler {
	return &BatchWriteCommitCCVNodeDataHandler{
		handler: handler,
	}
}
