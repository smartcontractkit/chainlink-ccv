package handlers

import (
	"context"
	"fmt"
	"sync"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

// BatchWriteCommitVerifierNodeResultHandler handles requests to write commit verification records.
type BatchWriteCommitVerifierNodeResultHandler struct {
	handler                                     *WriteCommitVerifierNodeResultHandler
	maxCommitVerifierNodeResultRequestsPerBatch int
}

func (h *BatchWriteCommitVerifierNodeResultHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.handler.l)
}

func (h *BatchWriteCommitVerifierNodeResultHandler) handleBatchItemError(ctx context.Context, errors []*rpcstatus.Status, i int, err error) {
	statusErr, ok := grpcstatus.FromError(err)
	if !ok {
		if ctx.Err() == nil {
			h.logger(ctx).Errorw("unexpected error type", "error", err)
		}
		SetBatchError(errors, i, codes.Unknown, "internal error")
		return
	}
	code := statusErr.Code()
	if code != codes.Canceled && code != codes.DeadlineExceeded {
		h.logger(ctx).Errorw("failed to write commit verification node result", "error", statusErr)
	}
	errors[i] = statusErr.Proto()
}

// Handle processes the write request and saves the commit verification record.
// The parent context includes a timeout from RequestTimeoutMiddleware to prevent goroutine leaks.
func (h *BatchWriteCommitVerifierNodeResultHandler) Handle(ctx context.Context, req *committeepb.BatchWriteCommitteeVerifierNodeResultRequest) (*committeepb.BatchWriteCommitteeVerifierNodeResultResponse, error) {
	requests := req.GetRequests()

	// Validate batch size limits
	if len(requests) == 0 {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "requests cannot be empty")
	}
	if len(requests) > h.maxCommitVerifierNodeResultRequestsPerBatch {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "too many requests: %d, maximum allowed: %d", len(requests), h.maxCommitVerifierNodeResultRequestsPerBatch)
	}

	responses := make([]*committeepb.WriteCommitteeVerifierNodeResultResponse, len(requests))
	errors := NewBatchErrorArray(len(requests))

	wg := sync.WaitGroup{}

	for i, r := range requests {
		wg.Add(1)
		go func(i int, r *committeepb.WriteCommitteeVerifierNodeResultRequest) {
			defer wg.Done()
			if r == nil {
				SetBatchError(errors, i, codes.InvalidArgument, fmt.Sprintf("nil request at index %d", i))
				responses[i] = &committeepb.WriteCommitteeVerifierNodeResultResponse{
					Status: committeepb.WriteStatus_FAILED,
				}
				return
			}
			resp, err := h.handler.Handle(ctx, r)
			if err == nil {
				SetBatchSuccess(errors, i)
				responses[i] = resp
				return
			}
			h.handleBatchItemError(ctx, errors, i, err)
			responses[i] = resp
		}(i, r)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return &committeepb.BatchWriteCommitteeVerifierNodeResultResponse{
			Responses: responses,
			Errors:    errors,
		}, nil
	case <-ctx.Done():
		code := codes.DeadlineExceeded
		if ctx.Err() == context.Canceled {
			code = codes.Canceled
		}
		return nil, grpcstatus.Error(code, "request cancelled")
	}
}

// NewBatchWriteCommitVerifierNodeResultHandler creates a new instance of BatchWriteCommitCCVNodeDataHandler.
func NewBatchWriteCommitVerifierNodeResultHandler(handler *WriteCommitVerifierNodeResultHandler, maxCommitVerifierNodeResultRequestsPerBatch int) *BatchWriteCommitVerifierNodeResultHandler {
	return &BatchWriteCommitVerifierNodeResultHandler{
		handler: handler,
		maxCommitVerifierNodeResultRequestsPerBatch: maxCommitVerifierNodeResultRequestsPerBatch,
	}
}
