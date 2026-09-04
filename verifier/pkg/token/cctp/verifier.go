package cctp

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Verifier is responsible for verifying CCTP messages by fetching their attestations
// and preparing VerifierNodeResult for storage. Retries are handled by the upper-layer processor,
// but Verifier indicates whether an error is retriable or not.
type Verifier struct {
	lggr       logger.Logger
	monitoring verifier.Monitoring
	verifierID string

	attestationService AttestationService

	attestationNotReadyRetry time.Duration
	anyErrorRetry            time.Duration
	maxAttestationFetchers   int
}

func NewVerifier(
	lggr logger.Logger,
	monitoring verifier.Monitoring,
	verifierID string,
	attestationService AttestationService,
	cfg CCTPConfig,
) verifier.Verifier {
	return NewVerifierWithConfig(
		lggr,
		monitoring,
		verifierID,
		attestationService,
		cfg.AttestationNotReadyRetry,
		cfg.AttestationGenericErrorRetry,
		cfg.AttestationConcurrentFetchers,
	)
}

func NewVerifierWithConfig(
	lggr logger.Logger,
	monitoring verifier.Monitoring,
	verifierID string,
	attestationService AttestationService,
	attestationNotReadyRetry time.Duration,
	anyErrorRetry time.Duration,
	maxAttestationFetchers int,
) verifier.Verifier {
	return &Verifier{
		lggr:                     lggr,
		monitoring:               monitoring,
		verifierID:               verifierID,
		attestationService:       attestationService,
		attestationNotReadyRetry: attestationNotReadyRetry,
		anyErrorRetry:            anyErrorRetry,
		maxAttestationFetchers:   maxAttestationFetchers,
	}
}

func (v *Verifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
) []verifier.VerificationResult {
	jobResults := make(chan verifier.VerificationResult, len(tasks))
	jobs := make(chan verifier.VerificationTask, len(tasks))

	for _, task := range tasks {
		jobs <- task
	}
	defer close(jobs)

	workers := min(len(tasks), v.maxAttestationFetchers)
	for range workers {
		go func() {
			for job := range jobs {
				jobResults <- v.processVerificationTask(ctx, job)
			}
		}()
	}

	results := make([]verifier.VerificationResult, 0, len(tasks))
	for range tasks {
		results = append(results, <-jobResults)
	}

	return results
}

func (v *Verifier) processVerificationTask(ctx context.Context, task verifier.VerificationTask) verifier.VerificationResult {
	lggr := logger.With(v.lggr, protocol.LogKeyMessageID, task.MessageID, "txHash", task.TxHash)
	lggr.Debugw("Verifying CCTP task")

	// Open a child span under the task-verifier attempt span so this attestation
	// fetch extends the base message trace opened by the source reader. The attempt
	// span is carried by the task's TraceContext (the batch ctx passed to
	// VerifyMessages carries no live span), so parent off that span context. But
	// task.TraceContext is derived from context.WithoutCancel, so inject the attempt
	// span context into ctx to keep its deadline/cancellation for the actual fetch.
	parentCtx := ctx
	if task.TraceContext != nil {
		if attemptSC := oteltrace.SpanContextFromContext(task.TraceContext); attemptSC.IsValid() {
			parentCtx = oteltrace.ContextWithSpanContext(ctx, attemptSC)
		}
	}
	messageID, _ := protocol.NewBytes32FromString(task.MessageID)
	fetchCtx, span := v.monitoring.Tracing().StartMessageSpan(
		parentCtx,
		monitoring.TokenAttestationSpanName(v.verifierID),
		messageID,
		attribute.String(tracing.ProviderKey, provider),
		attribute.String(tracing.TxHashKey, task.TxHash.String()),
		attribute.String(tracing.SourceChainSelectorKey, task.Message.SourceChainSelector.String()),
		attribute.String(tracing.SourceChainNameKey, task.Message.SourceChainSelector.ChainName()),
	)
	defer span.End()
	fetchStartedAt := time.Now()
	recordOutcome := func(outcome string) {
		v.monitoring.Metrics().IncrementTokenAttestationFetch(fetchCtx, provider, outcome)
		v.monitoring.Metrics().RecordTokenAttestationDuration(fetchCtx, provider, time.Since(fetchStartedAt))
	}

	// 1. Fetch attestation. Run under the attestation span so any HTTP request
	// spans emitted by the client are its children.
	attestation, err := v.attestationService.Fetch(fetchCtx, task.TxHash, task.Message)
	if err != nil {
		lggr.Warnw("Failed to fetch attestation", "err", err)
		span.AddEvent(monitoring.EventAttestationFetchFailed, oteltrace.WithAttributes(attribute.String(tracing.ProviderKey, provider)))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	if !attestation.IsReady() {
		lggr.Debugw("Attestation not ready for message")
		span.AddEvent(monitoring.EventAttestationNotReady, oteltrace.WithAttributes(attribute.String(tracing.AttestationStatusKey, string(attestation.status))))
		recordOutcome(monitoring.TokenAttestationFetchOutcomeNotReady)
		verificationError := v.attestationErrorRetry(
			fmt.Errorf("attestation not ready for message ID: %s", task.MessageID),
			task,
		)
		return verifier.VerificationResult{Error: &verificationError}
	}

	verifierFormat, err := attestation.ToVerifierFormat()
	if err != nil {
		lggr.Errorw("Failed to decode attestation data", "err", err)
		span.AddEvent(monitoring.EventAttestationFetchFailed, oteltrace.WithAttributes(attribute.String(tracing.ProviderKey, provider)))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	lggr.Debugw(
		"Attestation fetched and decoded successfully",
		"status", attestation.status,
		"attestation", attestation.attestation,
		"encodedCCTPMessage", attestation.encodedCCTPMessage,
		"verifierFormat", verifierFormat,
	)

	span.AddEvent(monitoring.EventAttestationFetchSucceeded, oteltrace.WithAttributes(attribute.String(tracing.AttestationStatusKey, string(attestation.status))))
	recordOutcome(monitoring.TokenAttestationFetchOutcomeSuccess)

	// 2. Create VerifierNodeResult
	result, err := commit.CreateVerifierNodeResult(
		&task,
		verifierFormat,
		attestation.verifierVersion,
	)
	if err != nil {
		lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	span.SetStatus(codes.Ok, "")

	// 3. Return successful result
	// PER-MESSAGE LOG (status): signing complete; storage write is the terminal success.
	lggr.Infow("VerifierResults: Successfully verified message", protocol.LogTypeKey, protocol.LogTypeMessageStatus, "signature", result.Signature)
	return verifier.VerificationResult{Result: result}
}

func (v *Verifier) attestationErrorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.attestationNotReadyRetry)
}

func (v *Verifier) errorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.anyErrorRetry)
}
