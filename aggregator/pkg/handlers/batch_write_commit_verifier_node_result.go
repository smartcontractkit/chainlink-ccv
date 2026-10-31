package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	commontracing "github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	grpcstatus "google.golang.org/grpc/status"

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
	batchErrors := NewBatchErrorArray(len(requests))

	// One traceparent per request, in order (see ItemTraceParentMetadataHeader) -
	// otelgrpc's own extraction only covers the RPC as a whole, not each item.
	var itemTraceParents []string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		itemTraceParents = md.Get(commontracing.ItemTraceParentMetadataHeader)
	}

	prepared := make([]*preparedWrite, len(requests))
	wg := sync.WaitGroup{}

	for i, r := range requests {
		wg.Add(1)
		go func(i int, r *committeepb.WriteCommitteeVerifierNodeResultRequest) {
			defer wg.Done()
			responses[i] = &committeepb.WriteCommitteeVerifierNodeResultResponse{
				Status: committeepb.WriteStatus_FAILED,
			}
			if r == nil {
				SetBatchError(batchErrors, i, codes.InvalidArgument, fmt.Sprintf("nil request at index %d", i))
				return
			}
			itemCtx := ctx
			if i < len(itemTraceParents) && itemTraceParents[i] != "" {
				carrier := propagation.MapCarrier{"traceparent": itemTraceParents[i]}
				itemCtx = otel.GetTextMapPropagator().Extract(ctx, carrier)
			}
			p, err := h.handler.prepare(itemCtx, r)
			if err != nil {
				statusErr, ok := grpcstatus.FromError(err)
				if !ok {
					h.logger(ctx).Errorw("unexpected error type", "error", err)
					SetBatchError(batchErrors, i, codes.Unknown, "internal error")
				} else {
					h.logger(ctx).Errorw("failed to write commit verification node result", "error", statusErr)
					batchErrors[i] = statusErr.Proto()
				}
				return
			}
			prepared[i] = p
		}(i, r)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
		h.persist(ctx, prepared, responses, batchErrors)
	}()

	select {
	case <-done:
		return &committeepb.BatchWriteCommitteeVerifierNodeResultResponse{
			Responses: responses,
			Errors:    batchErrors,
		}, nil
	case <-ctx.Done():
		code := codes.DeadlineExceeded
		if ctx.Err() == context.Canceled {
			code = codes.Canceled
		}
		return nil, grpcstatus.Error(code, "request cancelled")
	}
}

// persist inserts every prepared record in one statement, then triggers one aggregation check per
// unique (message ID, aggregation key, channel key).
func (h *BatchWriteCommitVerifierNodeResultHandler) persist(ctx context.Context, prepared []*preparedWrite, responses []*committeepb.WriteCommitteeVerifierNodeResultResponse, batchErrors []*status.Status) {
	validIndexes := make([]int, 0, len(prepared))
	writes := make([]model.CommitVerificationWrite, 0, len(prepared))
	for i, p := range prepared {
		if p == nil {
			continue
		}
		validIndexes = append(validIndexes, i)
		writes = append(writes, model.CommitVerificationWrite{Record: p.record, AggregationKey: p.aggregationKey})
	}
	defer func() {
		for _, i := range validIndexes {
			prepared[i].span.End()
		}
	}()
	if len(writes) == 0 {
		return
	}

	if err := h.handler.storage.SaveCommitVerification(ctx, writes); err != nil {
		h.logger(ctx).Errorw("failed to save commit verification records", "error", err, "count", len(writes))
		for _, i := range validIndexes {
			prepared[i].span.RecordError(err)
			SetBatchError(batchErrors, i, codes.Internal, "failed to save verification record")
		}
		return
	}

	for _, i := range validIndexes {
		h.handler.recordSaved(prepared[i])
	}

	type aggregationGroup struct {
		representative *preparedWrite
		indexes        []int
	}
	groups := make(map[string]*aggregationGroup)
	order := make([]string, 0, len(validIndexes))
	for _, i := range validIndexes {
		p := prepared[i]
		key := string(p.record.MessageID) + "\x00" + p.aggregationKey + "\x00" + string(p.channelKey())
		g, ok := groups[key]
		if !ok {
			g = &aggregationGroup{representative: p}
			groups[key] = g
			order = append(order, key)
		}
		g.indexes = append(g.indexes, i)
	}

	for _, key := range order {
		g := groups[key]
		p := g.representative
		channelKey := p.channelKey()
		err := h.handler.aggregator.CheckAggregation(p.ctx, p.record.MessageID, p.aggregationKey, channelKey)
		if err != nil {
			code := codes.Internal
			message := "failed to trigger aggregation"
			if errors.Is(err, common.ErrAggregationChannelFull) {
				code = codes.ResourceExhausted
				message = "service temporarily unavailable: aggregation queue full"
			}
			h.logger(p.ctx).Errorw("failed to trigger aggregation", "error", err)
			for _, i := range g.indexes {
				prepared[i].span.RecordError(err)
				SetBatchError(batchErrors, i, code, message)
			}
			continue
		}
		for _, i := range g.indexes {
			prepared[i].span.AddEvent(monitoring.EventAggregationEnqueued, oteltrace.WithAttributes(attribute.String(commontracing.ChannelKeyKey, string(channelKey))))
			responses[i] = &committeepb.WriteCommitteeVerifierNodeResultResponse{
				Status: committeepb.WriteStatus_SUCCESS,
			}
			SetBatchSuccess(batchErrors, i)
		}
	}
}

// NewBatchWriteCommitVerifierNodeResultHandler creates a new instance of BatchWriteCommitCCVNodeDataHandler.
func NewBatchWriteCommitVerifierNodeResultHandler(handler *WriteCommitVerifierNodeResultHandler, maxCommitVerifierNodeResultRequestsPerBatch int) *BatchWriteCommitVerifierNodeResultHandler {
	return &BatchWriteCommitVerifierNodeResultHandler{
		handler: handler,
		maxCommitVerifierNodeResultRequestsPerBatch: maxCommitVerifierNodeResultRequestsPerBatch,
	}
}
