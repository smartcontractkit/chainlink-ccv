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
	// ValidateSignature validates a signature for a MessageWithCCVNodeData and returns the signers.
	ValidateSignature(ctx context.Context, report *pb.MessageWithCCVNodeData) ([]*model.IdentifierSigner, *model.QuorumConfig, error)
}

// AggregationTriggerer defines an interface for triggering aggregation checks.
type AggregationTriggerer interface {
	// CheckAggregation triggers the aggregation process for the specified message ID.
	CheckAggregation(model.MessageID, model.CommitteeID) error
}

// WriteCommitCCVNodeDataHandler handles requests to write commit verification records.
type WriteCommitCCVNodeDataHandler struct {
	storage            common.CommitVerificationStore
	aggregator         AggregationTriggerer
	l                  logger.SugaredLogger
	signatureValidator SignatureValidator
	disableValidation  bool
}

func (h *WriteCommitCCVNodeDataHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitCCVNodeDataHandler) Handle(ctx context.Context, req *pb.WriteCommitCCVNodeDataRequest) (*pb.WriteCommitCCVNodeDataResponse, error) {
	ctx = scope.WithMessageID(ctx, req.CcvNodeData.MessageId)
	reqLogger := h.logger(ctx)
	reqLogger.Infof("Received WriteCommitCCVNodeDataRequest")
	if !h.disableValidation {
		if err := validateWriteRequest(req); err != nil {
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, status.Errorf(codes.InvalidArgument, "validation error: %v", err)
		}
	} else {
		reqLogger.Warnf("Request validation is disabled")
	}

	signers, _, err := h.signatureValidator.ValidateSignature(ctx, req.GetCcvNodeData())
	if err != nil {
		return &pb.WriteCommitCCVNodeDataResponse{
			Status: pb.WriteStatus_FAILED,
		}, err
	}

	reqLogger = reqLogger.With("NumSigners", len(signers))
	reqLogger.Infof("Signature validated successfully")

	for _, signer := range signers {
		signerCtx := scope.WithAddress(ctx, signer.Address)
		signerCtx = scope.WithParticipantID(signerCtx, signer.ParticipantID)
		signerCtx = scope.WithCommitteeID(signerCtx, signer.CommitteeID)

		// Parse the idempotency key as UUID
		idempotencyUUID, err := uuid.Parse(req.GetIdempotencyKey())
		if err != nil {
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, status.Errorf(codes.InvalidArgument, "invalid idempotency key format: %v", err)
		}

		record := model.CommitVerificationRecord{
			MessageWithCCVNodeData: *req.GetCcvNodeData(),
			IdentifierSigner:       signer,
			CommitteeID:            signer.CommitteeID,
			IdempotencyKey:         idempotencyUUID,
		}
		err = h.storage.SaveCommitVerification(signerCtx, &record)
		if err != nil {
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, err
		}
		h.logger(signerCtx).Infof("Successfully saved commit verification record")
	}

	if err := h.aggregator.CheckAggregation(req.CcvNodeData.GetMessageId(), signers[0].CommitteeID); err != nil {
		if err == common.ErrAggregationChannelFull {
			reqLogger.Errorf("Aggregation channel is full")
			return &pb.WriteCommitCCVNodeDataResponse{
				Status: pb.WriteStatus_FAILED,
			}, status.Errorf(codes.ResourceExhausted, "aggregation channel is full")
		}

		return &pb.WriteCommitCCVNodeDataResponse{
			Status: pb.WriteStatus_FAILED,
		}, err
	}
	reqLogger.Infof("Triggered aggregation check")

	return &pb.WriteCommitCCVNodeDataResponse{
		Status: pb.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitCCVNodeDataHandler creates a new instance of WriteCommitCCVNodeDataHandler.
func NewWriteCommitCCVNodeDataHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.SugaredLogger, disableValidation bool, signatureValidator SignatureValidator) *WriteCommitCCVNodeDataHandler {
	return &WriteCommitCCVNodeDataHandler{
		storage:            store,
		aggregator:         aggregator,
		l:                  l,
		disableValidation:  disableValidation,
		signatureValidator: signatureValidator,
	}
}
