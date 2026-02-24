package lombard

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
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
	lggr logger.Logger

	attestationService AttestationService
	ccvVerifierVersion protocol.ByteSlice

	attestationNotReadyRetry time.Duration
	anyErrorRetry            time.Duration
}

func NewVerifier(
	lggr logger.Logger,
	config LombardConfig,
	attestationService AttestationService,
) (verifier.Verifier, error) {
	return NewVerifierWithConfig(
		lggr,
		attestationService,
		config.VerifierVersion,
		attestationNotReadyRetry,
		anyErrorRetry,
	), nil
}

func NewVerifierWithConfig(
	lggr logger.Logger,
	attestationService AttestationService,
	ccvVerifierVersion protocol.ByteSlice,
	attestationNotReadyRetry time.Duration,
	anyErrorRetry time.Duration,
) verifier.Verifier {
	return &Verifier{
		lggr:                     lggr,
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
	messages := make([]protocol.Message, 0, len(tasks))
	for _, task := range tasks {
		messages = append(messages, task.Message)
	}

	// 1. Fetch attestations in batch
	attestations, err := v.attestationService.Fetch(ctx, messages)
	if err != nil {
		// Mark all tasks as retriable errors if fetching attestations failed
		results := make([]verifier.VerificationResult, 0, len(tasks))
		for _, task := range tasks {
			verificationError := v.errorRetry(err, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
		}
		return results
	}

	// 2. Process each task, iterate and match from response
	results := make([]verifier.VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		lggr := logger.With(v.lggr, "messageID", task.MessageID, "txHash", task.TxHash)
		lggr.Infow("Verifying Lombard task")

		attestation, exists := attestations[task.MessageID]
		if !exists {
			lggr.Debugw("Attestation not found for message")
			verificationError := v.attestationErrorRetry(
				fmt.Errorf("attestation not found for message ID: %s", task.MessageID),
				task,
			)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		if !attestation.IsReady() {
			lggr.Debugw("Attestation not ready for message")
			verificationError := v.attestationErrorRetry(
				fmt.Errorf("attestation not ready for message ID: %s", task.MessageID),
				task,
			)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		verifierFormat, err := attestation.ToVerifierFormat()
		if err != nil {
			lggr.Errorw("Failed to decode attestation data", "err", err)
			verificationError := v.errorRetry(err, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		lggr.Infow("Attestation fetched and decoded successfully",
			"status", attestation.status,
			"attestation", attestation.attestation,
			"verifierFormat", verifierFormat,
		)

		result, err1 := commit.CreateVerifierNodeResult(
			&task,
			verifierFormat,
			v.ccvVerifierVersion,
		)
		if err1 != nil {
			lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
			verificationError := v.errorRetry(err1, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		// 2.1 Return successful result
		lggr.Infow("VerifierResults: Successfully verified message", "signature", result.Signature)
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
