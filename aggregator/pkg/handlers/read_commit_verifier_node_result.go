// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

// ReadCommitVerifierNodeResultHandler handles requests to read commit verification records.
type ReadCommitVerifierNodeResultHandler struct {
	storage common.CommitVerificationStore
	l       logger.SugaredLogger
}

func (h *ReadCommitVerifierNodeResultHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the read request and retrieves the corresponding commit verification record.
func (h *ReadCommitVerifierNodeResultHandler) Handle(ctx context.Context, req *committeepb.ReadCommitteeVerifierNodeResultRequest) (*committeepb.ReadCommitteeVerifierNodeResultResponse, error) {
	if err := validateReadRequest(req); err != nil {
		h.logger(ctx).Warnw("validation error", "error", err)
		return &committeepb.ReadCommitteeVerifierNodeResultResponse{}, status.Error(codes.InvalidArgument, "invalid request parameters")
	}
	ctx = scope.WithMessageID(ctx, req.GetMessageId())

	id := model.CommitVerificationRecordIdentifier{
		Address:   protocol.ByteSlice(req.GetAddress()),
		MessageID: req.GetMessageId(),
	}

	record, err := h.storage.GetCommitVerification(ctx, id)
	if err != nil {
		h.logger(ctx).Errorw("failed to get commit verification record", "address", id.Address, "error", err)
		return nil, status.Error(codes.NotFound, "verification record not found")
	}

	protoRecord, err := model.CommitVerificationRecordToProto(record)
	if err != nil {
		h.logger(ctx).Errorw("failed to convert record to proto", "error", err)
		return nil, status.Errorf(codes.Internal, "failed to convert record to proto: %v", err)
	}

	return &committeepb.ReadCommitteeVerifierNodeResultResponse{
		CommitteeVerifierNodeResult: protoRecord,
	}, nil
}

// NewReadCommitVerifierNodeResultHandler creates a new instance of ReadCommitCCVNodeDataHandler.
func NewReadCommitVerifierNodeResultHandler(store common.CommitVerificationStore, l logger.SugaredLogger) *ReadCommitVerifierNodeResultHandler {
	return &ReadCommitVerifierNodeResultHandler{
		storage: store,
		l:       l,
	}
}
