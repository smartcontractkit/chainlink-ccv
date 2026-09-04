package lombard

import (
	"context"
	"fmt"
	"time"

	chainsel "github.com/smartcontractkit/chain-selectors"

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

// There is a distinction for attestation not being ready and networking/any other errors.
// Usually, if attestation is not ready on first attempt then it doesn't make sense to retry immediately.
const (
	attestationNotReadyRetry = 30 * time.Second
	anyErrorRetry            = 5 * time.Second
)

// Verifier is responsible for verifying Lombard messages by fetching their attestations
// and preparing VerifierNodeResult for storage. Retries are handled by the upper-layer processor,
// but Verifier indicates whether an error is retriable or not.
type Verifier struct {
	lggr       logger.Logger
	monitoring verifier.Monitoring
	verifierID string

	attestationService AttestationService
	ccvVerifierVersion protocol.ByteSlice

	attestationNotReadyRetry time.Duration
	anyErrorRetry            time.Duration
}

func NewVerifier(
	lggr logger.Logger,
	monitoring verifier.Monitoring,
	verifierID string,
	config LombardConfig,
	attestationService AttestationService,
) (verifier.Verifier, error) {
	return NewVerifierWithConfig(
		lggr,
		monitoring,
		verifierID,
		attestationService,
		config.VerifierVersion,
		attestationNotReadyRetry,
		anyErrorRetry,
	), nil
}

func NewVerifierWithConfig(
	lggr logger.Logger,
	monitoring verifier.Monitoring,
	verifierID string,
	attestationService AttestationService,
	ccvVerifierVersion protocol.ByteSlice,
	attestationNotReadyRetry time.Duration,
	anyErrorRetry time.Duration,
) verifier.Verifier {
	return &Verifier{
		lggr:                     lggr,
		monitoring:               monitoring,
		verifierID:               verifierID,
		attestationService:       attestationService,
		ccvVerifierVersion:       ccvVerifierVersion,
		attestationNotReadyRetry: attestationNotReadyRetry,
		anyErrorRetry:            anyErrorRetry,
	}
}

func (v *Verifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
) []verifier.VerificationResult {
	// 1. Fetch attestations in batch
	attestations, err := v.attestationService.Fetch(ctx, tasks)
	if err != nil {
		// Mark all tasks as retriable errors if fetching attestations failed
		results := make([]verifier.VerificationResult, 0, len(tasks))
		for _, task := range tasks {
			v.monitoring.Metrics().IncrementTokenAttestationFetch(ctx, provider, monitoring.TokenAttestationFetchOutcomeError)
			verificationError := v.errorRetry(err, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
		}
		return results
	}

	// 2. Process each task, iterate and match from response
	results := make([]verifier.VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		lggr := logger.With(v.lggr, protocol.LogKeyMessageID, task.MessageID, "txHash", task.TxHash)
		lggr.Debugw("Verifying Lombard task")

		// Open a child span under the task-verifier attempt span so this
		// attestation fetch extends the base message trace opened by the source reader.
		messageID, _ := protocol.NewBytes32FromString(task.MessageID)
		fetchCtx, span := v.monitoring.Tracing().StartMessageSpan(
			ctx,
			monitoring.TokenAttestationSpanName(v.verifierID),
			messageID,
			attribute.String(tracing.ProviderKey, provider),
			attribute.String(tracing.SourceChainSelectorKey, task.Message.SourceChainSelector.String()),
			attribute.String(tracing.SourceChainNameKey, task.Message.SourceChainSelector.ChainName()),
		)
		fetchStartedAt := time.Now()
		// spans must be recorded against the span-started context, not the raw ctx
		recordOutcome := func(outcome string) {
			v.monitoring.Metrics().IncrementTokenAttestationFetch(fetchCtx, provider, outcome)
			v.monitoring.Metrics().RecordTokenAttestationDuration(fetchCtx, provider, time.Since(fetchStartedAt))
		}

		attestation, exists := attestations[task.MessageID]
		if !exists {
			lggr.Debugw("Attestation not found for message")
			span.AddEvent(monitoring.EventAttestationNotFound, oteltrace.WithAttributes(attribute.String(tracing.ProviderKey, provider)))
			span.RecordError(fmt.Errorf("attestation not found"))
			span.SetStatus(codes.Error, "attestation not found")
			span.End()
			recordOutcome(monitoring.TokenAttestationFetchOutcomeNotFound)
			verificationError := v.attestationErrorRetry(
				fmt.Errorf("attestation not found for message ID: %s", task.MessageID),
				task,
			)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		if !attestation.IsReady() {
			lggr.Debugw("Attestation not ready for message")
			span.AddEvent(monitoring.EventAttestationNotReady, oteltrace.WithAttributes(attribute.String(tracing.AttestationStatusKey, string(attestation.status))))
			span.End()
			recordOutcome(monitoring.TokenAttestationFetchOutcomeNotReady)
			verificationError := v.attestationErrorRetry(
				fmt.Errorf("attestation not ready for message ID: %s", task.MessageID),
				task,
			)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		destFamily, err := chainsel.GetSelectorFamily(uint64(task.Message.DestChainSelector))
		if err != nil {
			lggr.Errorw("Failed to determine destination chain family", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.End()
			recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
			verificationError := v.errorRetry(err, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}
		var verifierFormat protocol.ByteSlice
		if destFamily == chainsel.FamilySolana {
			// Solana only requires the payloadHash, the protocol itself delivers the payload to the mailbox
			// and verifies the proofs out of bound
			verifierFormat, err = attestation.PayloadHash()
		} else {
			verifierFormat, err = attestation.ToVerifierFormat()
		}
		if err != nil {
			lggr.Errorw("Failed to decode attestation data", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.End()
			recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
			verificationError := v.errorRetry(err, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		lggr.Debugw("Attestation fetched and decoded successfully",
			"status", attestation.status,
			"attestation", attestation.attestation,
			"verifierFormat", verifierFormat,
		)

		span.AddEvent(monitoring.EventAttestationFetchSucceeded, oteltrace.WithAttributes(attribute.String(tracing.AttestationStatusKey, string(attestation.status))))
		span.SetStatus(codes.Ok, "")
		span.End()
		recordOutcome(monitoring.TokenAttestationFetchOutcomeSuccess)

		result, err1 := commit.CreateVerifierNodeResult(
			&task,
			verifierFormat,
			v.ccvVerifierVersion,
		)
		if err1 != nil {
			lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
			recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
			verificationError := v.errorRetry(err1, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		// 2.1 Return successful result
		// PER-MESSAGE LOG (status): signing complete; storage write is the terminal success.
		lggr.Infow("VerifierResults: Successfully verified message", protocol.LogTypeKey, protocol.LogTypeMessageStatus, "signature", result.Signature)
		results = append(results, verifier.VerificationResult{Result: result})
	}

	return results
}

func (v *Verifier) attestationErrorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.attestationNotReadyRetry)
}

func (v *Verifier) errorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.anyErrorRetry)
}
