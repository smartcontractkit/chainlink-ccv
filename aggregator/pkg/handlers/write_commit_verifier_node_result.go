package handlers

import (
	"context"
	"errors"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	messagerules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	commontracing "github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
	CheckAggregation(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey, channelKey model.ChannelKey) error
}

// WriteCommitVerifierNodeResultHandler handles requests to write commit verification records.
type WriteCommitVerifierNodeResultHandler struct {
	storage            common.CommitVerificationStore
	aggregator         AggregationTriggerer
	m                  common.AggregatorMonitoring
	l                  logger.SugaredLogger
	signatureValidator SignatureValidator
	disablementChecker messagerules.Checker
}

func (h *WriteCommitVerifierNodeResultHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// preparedWrite is a request that passed every pre-storage check and is ready to be inserted.
// The caller owns span and must end it.
type preparedWrite struct {
	ctx            context.Context
	signerCtx      context.Context
	span           oteltrace.Span
	record         *model.CommitVerificationRecord
	aggregationKey model.AggregationKey
	callerID       string
}

func (p *preparedWrite) channelKey() model.ChannelKey {
	return model.ChannelKey(p.callerID)
}

// prepare runs every check up to and including aggregation-key derivation. On error it ends any span
// it started and returns a gRPC status error.
func (h *WriteCommitVerifierNodeResultHandler) prepare(ctx context.Context, req *committeepb.WriteCommitteeVerifierNodeResultRequest) (*preparedWrite, error) {
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated: no caller identity in context")
	}
	reqLogger := h.logger(ctx)
	if err := validateWriteRequest(req); err != nil {
		reqLogger.Warnw("validation error", "error", err)
		return nil, status.Error(codes.InvalidArgument, "validation failed: invalid request format")
	}

	record, err := model.CommitVerificationRecordFromProto(req.GetCommitteeVerifierNodeResult())
	if err != nil {
		reqLogger.Errorw("Failed to convert proto to domain model", "error", err)
		return nil, status.Error(codes.InvalidArgument, "invalid request format")
	}
	ctx = scope.WithMessageID(ctx, record.MessageID)
	reqLogger = h.logger(ctx)

	ctx, span := h.m.Tracing().StartMessageSpan(ctx, monitoring.WriteSpanName, monitoring.MessageIDToBytes32(record.MessageID),
		commontracing.AlwaysSampled(),
		commontracing.WithAttributes(commontracing.CallerIDKey, identity.CallerID),
	)

	if h.disablementChecker.IsDisabled(record) {
		reqLogger.Infow("Rejected write: message matched a disablement rule")
		span.AddEvent(monitoring.EventDisablementRejected)
		span.End()
		return nil, status.Error(codes.FailedPrecondition, "message processing is disabled")
	}

	validationResult, err := h.signatureValidator.ValidateSignature(ctx, record)
	if err != nil {
		reqLogger.Errorw("signature validation failed", "error", err)
		span.RecordError(err)
		span.End()
		return nil, status.Error(codes.InvalidArgument, "signature validation failed")
	}
	span.AddEvent(monitoring.EventSignatureValidated)

	reqLogger.Debugf("Signature validated successfully")

	aggregationKey, err := h.signatureValidator.DeriveAggregationKey(ctx, record)
	if err != nil {
		reqLogger.Errorw("failed to derive aggregation key", "error", err)
		span.RecordError(err)
		span.End()
		return nil, status.Error(codes.Internal, "failed to process verification record")
	}
	ctx = scope.WithAggregationKey(ctx, aggregationKey)
	span.SetAttributes(attribute.String(commontracing.AggregationKeyKey, aggregationKey))

	record.SignerIdentifier = validationResult.Signer

	return &preparedWrite{
		ctx:            ctx,
		signerCtx:      scope.WithAddress(ctx, validationResult.Signer.Identifier),
		span:           span,
		record:         record,
		aggregationKey: aggregationKey,
		callerID:       identity.CallerID,
	}, nil
}

// recordSaved emits the per-item logging and metrics that follow a successful insert.
func (h *WriteCommitVerifierNodeResultHandler) recordSaved(p *preparedWrite) {
	p.span.AddEvent(monitoring.EventVerificationSaved)
	// PER-MESSAGE LOG (status): one per verifier node; quorum may not be met yet.
	h.logger(p.signerCtx).Infow("Verification received", protocol.LogTypeKey, protocol.LogTypeMessageStatus, protocol.LogKeyMessageID, protocol.ByteSlice(p.record.MessageID).String(), "callerID", p.callerID)

	h.m.Metrics().With(
		"caller_id", p.callerID,
		"chain_selector", strconv.FormatUint(uint64(p.record.Message.SourceChainSelector), 10),
		"chain_name", p.record.Message.SourceChainSelector.ChainName(),
	).IncrementVerificationsTotal(p.ctx)
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitVerifierNodeResultHandler) Handle(ctx context.Context, req *committeepb.WriteCommitteeVerifierNodeResultRequest) (*committeepb.WriteCommitteeVerifierNodeResultResponse, error) {
	failed := &committeepb.WriteCommitteeVerifierNodeResultResponse{Status: committeepb.WriteStatus_FAILED}

	p, err := h.prepare(ctx, req)
	if err != nil {
		return failed, err
	}
	defer p.span.End()

	writes := []model.CommitVerificationWrite{{Record: p.record, AggregationKey: p.aggregationKey}}
	if err := h.storage.SaveCommitVerification(p.signerCtx, writes); err != nil {
		h.logger(p.signerCtx).Errorw("failed to save commit verification record", "error", err)
		p.span.RecordError(err)
		return failed, status.Error(codes.Internal, "failed to save verification record")
	}
	h.recordSaved(p)

	reqLogger := h.logger(p.ctx)
	channelKey := p.channelKey()
	if err := h.aggregator.CheckAggregation(p.ctx, p.record.MessageID, p.aggregationKey, channelKey); err != nil {
		p.span.RecordError(err)
		if errors.Is(err, common.ErrAggregationChannelFull) {
			reqLogger.Errorf("Aggregation channel is full")
			return failed, status.Error(codes.ResourceExhausted, "service temporarily unavailable: aggregation queue full")
		}

		reqLogger.Errorw("failed to trigger aggregation", "error", err)
		return failed, status.Error(codes.Internal, "failed to trigger aggregation")
	}
	p.span.AddEvent(monitoring.EventAggregationEnqueued, oteltrace.WithAttributes(attribute.String(commontracing.ChannelKeyKey, string(channelKey))))
	reqLogger.Debugf("Triggered aggregation check")

	return &committeepb.WriteCommitteeVerifierNodeResultResponse{
		Status: committeepb.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitCCVNodeDataHandler creates a new instance of WriteCommitCCVNodeDataHandler.
func NewWriteCommitCCVNodeDataHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, m common.AggregatorMonitoring, l logger.SugaredLogger, signatureValidator SignatureValidator, disablementChecker messagerules.Checker) *WriteCommitVerifierNodeResultHandler {
	if disablementChecker == nil {
		disablementChecker = messagerules.NoopChecker{}
	}
	return &WriteCommitVerifierNodeResultHandler{
		storage:            store,
		aggregator:         aggregator,
		m:                  m,
		l:                  l,
		signatureValidator: signatureValidator,
		disablementChecker: disablementChecker,
	}
}
