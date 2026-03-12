package cctp

import (
	"context"
	"fmt"
	"time"

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

// Verifier is responsible for verifying CCTP messages by fetching their attestations
// and preparing VerifierNodeResult for storage. Retries are handled by the upper-layer processor,
// but Verifier indicates whether an error is retriable or not.
type Verifier struct {
	lggr               logger.Logger
	attestationService AttestationService

	attestationNotReadyRetry time.Duration
	anyErrorRetry            time.Duration
}

func NewVerifier(
	lggr logger.Logger,
	attestationService AttestationService,
) verifier.Verifier {
	return NewVerifierWithConfig(
		lggr,
		attestationService,
		attestationNotReadyRetry,
		anyErrorRetry,
	)
}

func NewVerifierWithConfig(
	lggr logger.Logger,
	attestationService AttestationService,
	attestationNotReadyRetry time.Duration,
	anyErrorRetry time.Duration,
) verifier.Verifier {
	return &Verifier{
		lggr:                     lggr,
		attestationService:       attestationService,
		attestationNotReadyRetry: attestationNotReadyRetry,
		anyErrorRetry:            anyErrorRetry,
	}
}

func (v *Verifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
) []verifier.VerificationResult {
	results := make([]verifier.VerificationResult, 0, len(tasks))

	// TODO: `attestationService.Fetch` is an IO-bound operation and can be parallelized. Large number of tasks
	//  may lead to performance bottlenecks. Consider using a worker pool or goroutines with a semaphore to limit
	//  concurrency.
	for _, task := range tasks {
		lggr := logger.With(v.lggr, "messageID", task.MessageID, "txHash", task.TxHash)
		lggr.Infow("Verifying CCTP task")

		// 1. Fetch attestation
		attestation, err := v.attestationService.Fetch(ctx, task.TxHash, task.Message)
		if err != nil {
			lggr.Warnw("Failed to fetch attestation", "err", err)
			verificationError := v.errorRetry(err, task)
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
			"encodedCCTPMessage", attestation.encodedCCTPMessage,
			"verifierFormat", verifierFormat,
		)

		// 2. Create VerifierNodeResult
		result, err := commit.CreateVerifierNodeResult(
			&task,
			verifierFormat,
			attestation.verifierVersion,
		)
		if err != nil {
			lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
			verificationError := v.errorRetry(err, task)
			results = append(results, verifier.VerificationResult{Error: &verificationError})
			continue
		}

		// 3. Return successful result
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
