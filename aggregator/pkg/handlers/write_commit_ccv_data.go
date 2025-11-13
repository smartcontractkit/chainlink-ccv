package handlers

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type SignatureValidator interface {
	// ValidateSignature validates a signature for a CommitVerificationRecord and returns the signers.
	ValidateSignature(ctx context.Context, record *model.CommitVerificationRecord) ([]*model.IdentifierSigner, *model.QuorumConfig, error)
	// DeriveAggregationKey produce the key on which this verification record should be aggregated on
	DeriveAggregationKey(ctx context.Context, record *model.CommitVerificationRecord) (model.AggregationKey, error)
}

// AggregationTriggerer defines an interface for triggering aggregation checks.
type AggregationTriggerer interface {
	// CheckAggregation triggers the aggregation process for the specified aggregation key.
	CheckAggregation(model.MessageID, model.AggregationKey) error
}

// WriteCommitCCVNodeDataHandler handles requests to write commit verification records.
type WriteCommitCCVNodeDataHandler struct {
	storage            common.CommitVerificationStore
	aggregator         AggregationTriggerer
	l                  logger.SugaredLogger
	signatureValidator SignatureValidator
}

func (h *WriteCommitCCVNodeDataHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitCCVNodeDataHandler) Handle(ctx context.Context, req *pb.WriteCommitCCVNodeDataRequest) (*pb.WriteCommitCCVNodeDataResponse, error) {
	reqLogger := h.logger(ctx)
	reqLogger.Infof("Received WriteCommitCCVNodeDataRequest")
	if err := validateWriteRequest(req); err != nil {
		reqLogger.Errorw("validation error", "error", err)
		return &pb.WriteCommitCCVNodeDataResponse{
			Status: pb.WriteStatus_FAILED,
		}, status.Errorf(codes.InvalidArgument, "validation error: %v", err)
	}
	// After successful validation, CcvNodeData is guaranteed non-nil
	ctx = scope.WithMessageID(ctx, req.CcvNodeData.MessageId)
	reqLogger = h.logger(ctx)

	record := model.CommitVerificationRecordFromProto(req.GetCcvNodeData())
	signers, _, err := h.signatureValidator.ValidateSignature(ctx, record)
	if err != nil {
		reqLogger.Errorw("signature validation failed", "error", err)
		return &pb.WriteCommitCCVNodeDataResponse{
			Status: pb.WriteStatus_FAILED,
		}, status.Errorf(codes.Internal, "signature validation failed: %v", err)
	}

	reqLogger = reqLogger.With("NumSigners", len(signers))
	reqLogger.Infof("Signature validated successfully")

	aggregationKey, err := h.signatureValidator.DeriveAggregationKey(ctx, record)
	if err != nil {
		reqLogger.Errorw("failed to derive aggregation key", err)
		return &pb.WriteCommitCCVNodeDataResponse{
			Status: pb.WriteStatus_FAILED,
		}, status.Errorf(codes.Internal, "failed to derive aggregation key: %v", err)
	}
	ctx = scope.WithAggregationKey(ctx, aggregationKey)

	for _, signer := range signers {
		signerCtx := scope.WithAddress(ctx, signer.Address)
		signerCtx = scope.WithParticipantID(signerCtx, signer.ParticipantID)

		// Parse the idempotency key as UUID
		idempotencyUUID, err := uuid.Parse(req.GetIdempotencyKey())
		if err != nil {
			h.logger(signerCtx).Errorw("invalid idempotency key format", "error", err)
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, status.Errorf(codes.InvalidArgument, "invalid idempotency key format: %v", err)
		}

		record := model.CommitVerificationRecordFromProto(req.GetCcvNodeData())
		record.IdentifierSigner = signer
		record.IdempotencyKey = idempotencyUUID

		err = h.storage.SaveCommitVerification(signerCtx, record, aggregationKey)
		if err != nil {
			h.logger(signerCtx).Errorw("failed to save commit verification record", "error", err)
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, status.Errorf(codes.Internal, "failed to save commit verification record: %v", err)
		}
		h.logger(signerCtx).Infof("Successfully saved commit verification record")
	}

	if err := h.aggregator.CheckAggregation(record.MessageID, aggregationKey); err != nil {
		if err == common.ErrAggregationChannelFull {
			reqLogger.Errorf("Aggregation channel is full")
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, status.Errorf(codes.ResourceExhausted, "aggregation channel is full")
		}

		reqLogger.Errorw("failed to trigger aggregation", "error", err)
		return &pb.WriteCommitCCVNodeDataResponse{
			Status: pb.WriteStatus_FAILED,
		}, status.Errorf(codes.Internal, "failed to trigger aggregation: %v", err)
	}
	reqLogger.Infof("Triggered aggregation check")

	return &pb.WriteCommitCCVNodeDataResponse{
		Status: pb.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitCCVNodeDataHandler creates a new instance of WriteCommitCCVNodeDataHandler.
func NewWriteCommitCCVNodeDataHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.SugaredLogger, signatureValidator SignatureValidator) *WriteCommitCCVNodeDataHandler {
	return &WriteCommitCCVNodeDataHandler{
		storage:            store,
		aggregator:         aggregator,
		l:                  l,
		signatureValidator: signatureValidator,
	}
}
