// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ReadCommitCCVNodeDataHandler handles requests to read commit verification records.
type ReadCommitCCVNodeDataHandler struct {
	storage common.CommitVerificationStore
	l       logger.SugaredLogger
}

func (h *ReadCommitCCVNodeDataHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the read request and retrieves the corresponding commit verification record.
func (h *ReadCommitCCVNodeDataHandler) Handle(ctx context.Context, req *pb.ReadCommitteeVerifierNodeResultRequest) (*pb.ReadCommitteeVerifierNodeResultResponse, error) {
	if err := validateReadRequest(req); err != nil {
		h.logger(ctx).Errorw("validation error", "error", err)
		return &pb.ReadCommitteeVerifierNodeResultResponse{}, status.Errorf(codes.InvalidArgument, "validation error: %v", err)
	}
	ctx = scope.WithMessageID(ctx, req.GetMessageId())

	h.logger(ctx).Infof("Received ReadCommitCCVNodeDataRequest")

	id := model.CommitVerificationRecordIdentifier{
		Address:   req.GetAddress(),
		MessageID: req.GetMessageId(),
	}

	record, err := h.storage.GetCommitVerification(ctx, id)
	if err != nil {
		h.logger(ctx).Errorw("failed to get commit verification record", "address", id.Address, "error", err)
		return nil, err
	}

	protoRecord := model.CommitVerificationRecordToProto(record)

	return &pb.ReadCommitteeVerifierNodeResultResponse{
		CommitteeVerifierNodeResult: protoRecord,
	}, nil
}

// NewReadCommitCCVNodeDataHandler creates a new instance of ReadCommitCCVNodeDataHandler.
func NewReadCommitCCVNodeDataHandler(store common.CommitVerificationStore, l logger.SugaredLogger) *ReadCommitCCVNodeDataHandler {
	return &ReadCommitCCVNodeDataHandler{
		storage: store,
		l:       l,
	}
}
