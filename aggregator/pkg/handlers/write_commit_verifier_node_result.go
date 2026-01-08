package handlers

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

type SignatureValidator interface {
	// ValidateSignature validates a signature and returns the validation result.
	ValidateSignature(ctx context.Context, record *model.CommitVerificationRecord) (*model.SignatureValidationResult, error)
	// DeriveAggregationKey derives the aggregation key for grouping verification records.
	DeriveAggregationKey(ctx context.Context, record *model.CommitVerificationRecord) (model.AggregationKey, error)
}

// AggregationTriggerer defines an interface for triggering aggregation checks.
type AggregationTriggerer interface {
	// CheckAggregation triggers the aggregation process for the specified aggregation key.
	CheckAggregation(model.MessageID, model.AggregationKey, model.ChannelKey, time.Duration) error
}

// WriteCommitVerifierNodeResultHandler handles requests to write commit verification records.
type WriteCommitVerifierNodeResultHandler struct {
	storage                 common.CommitVerificationStore
	aggregator              AggregationTriggerer
	l                       logger.SugaredLogger
	signatureValidator      SignatureValidator
	checkAggregationTimeout time.Duration
}

func (h *WriteCommitVerifierNodeResultHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitVerifierNodeResultHandler) Handle(ctx context.Context, req *committeepb.WriteCommitteeVerifierNodeResultRequest) (*committeepb.WriteCommitteeVerifierNodeResultResponse, error) {
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.Unauthenticated, "unauthenticated: no caller identity in context")
	}
	reqLogger := h.logger(ctx)
	if err := validateWriteRequest(req); err != nil {
		reqLogger.Warnw("validation error", "error", err)
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.InvalidArgument, "validation failed: invalid request format")
	}

	record, err := model.CommitVerificationRecordFromProto(req.GetCommitteeVerifierNodeResult())
	if err != nil {
		reqLogger.Errorw("Failed to convert proto to domain model", "error", err)
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.InvalidArgument, "invalid request format")
	}
	ctx = scope.WithMessageID(ctx, record.MessageID)
	reqLogger = h.logger(ctx)

	validationResult, err := h.signatureValidator.ValidateSignature(ctx, record)
	if err != nil {
		reqLogger.Errorw("signature validation failed", "error", err)
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.InvalidArgument, "signature validation failed")
	}

	reqLogger.Infof("Signature validated successfully")

	aggregationKey, err := h.signatureValidator.DeriveAggregationKey(ctx, record)
	if err != nil {
		reqLogger.Errorw("failed to derive aggregation key", "error", err)
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.Internal, "failed to process verification record")
	}
	ctx = scope.WithAggregationKey(ctx, aggregationKey)

	signerCtx := scope.WithAddress(ctx, validationResult.Signer.Identifier)

	record.SignerIdentifier = validationResult.Signer

	err = h.storage.SaveCommitVerification(signerCtx, record, aggregationKey)
	if err != nil {
		h.logger(signerCtx).Errorw("failed to save commit verification record", "error", err)
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.Internal, "failed to save verification record")
	}
	h.logger(signerCtx).Infof("Successfully saved commit verification record")

	if err := h.aggregator.CheckAggregation(record.MessageID, aggregationKey, model.ChannelKey(identity.CallerID), h.checkAggregationTimeout); err != nil {
		if err == common.ErrAggregationChannelFull {
			reqLogger.Errorf("Aggregation channel is full")
			return &committeepb.WriteCommitteeVerifierNodeResultResponse{
				Status: committeepb.WriteStatus_FAILED,
			}, status.Error(codes.ResourceExhausted, "service temporarily unavailable: aggregation queue full")
		}

		reqLogger.Errorw("failed to trigger aggregation", "error", err)
		return &committeepb.WriteCommitteeVerifierNodeResultResponse{
			Status: committeepb.WriteStatus_FAILED,
		}, status.Error(codes.Internal, "failed to trigger aggregation")
	}
	reqLogger.Infof("Triggered aggregation check")

	return &committeepb.WriteCommitteeVerifierNodeResultResponse{
		Status: committeepb.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitCCVNodeDataHandler creates a new instance of WriteCommitCCVNodeDataHandler.
func NewWriteCommitCCVNodeDataHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.SugaredLogger, signatureValidator SignatureValidator, checkAggregationTimeout time.Duration) *WriteCommitVerifierNodeResultHandler {
	return &WriteCommitVerifierNodeResultHandler{
		storage:                 store,
		aggregator:              aggregator,
		l:                       l,
		signatureValidator:      signatureValidator,
		checkAggregationTimeout: checkAggregationTimeout,
	}
}
