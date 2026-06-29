package cctp

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// There is a distinction for attestation not being ready and networking/any other errors.
// Usually, if attestation is not ready on first attempt then it doesn't make sense to retry immediately.
const (
	attestationNotReadyRetry = 30 * time.Second
	anyErrorRetry            = 5 * time.Second
	// Max number of concurrent workers to fetch attestations to verify.
	maxAttestationFetchers = 10
)

// Verifier is responsible for verifying CCTP messages by fetching their attestations
// and preparing VerifierNodeResult for storage. Retries are handled by the upper-layer processor,
// but Verifier indicates whether an error is retriable or not.
type Verifier struct {
	lggr               logger.Logger
	attestationService AttestationService

	attestationNotReadyRetry time.Duration
	anyErrorRetry            time.Duration
	maxAttestationFetchers   int
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
		maxAttestationFetchers,
	)
}

func NewVerifierWithConfig(
	lggr logger.Logger,
	attestationService AttestationService,
	attestationNotReadyRetry time.Duration,
	anyErrorRetry time.Duration,
	maxAttestationFetchers int,
) verifier.Verifier {
	return &Verifier{
		lggr:                     lggr,
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

	// 1. Fetch attestation
	attestation, err := v.attestationService.Fetch(ctx, task.TxHash, task.Message)
	if err != nil {
		lggr.Warnw("Failed to fetch attestation", "err", err)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	if !attestation.IsReady() {
		lggr.Debugw("Attestation not ready for message")
		verificationError := v.attestationErrorRetry(
			fmt.Errorf("attestation not ready for message ID: %s", task.MessageID),
			task,
		)
		return verifier.VerificationResult{Error: &verificationError}
	}

	verifierFormat, err := attestation.ToVerifierFormat()
	if err != nil {
		lggr.Errorw("Failed to decode attestation data", "err", err)
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

	// 2. Create VerifierNodeResult
	result, err := commit.CreateVerifierNodeResult(
		&task,
		verifierFormat,
		attestation.verifierVersion,
	)
	if err != nil {
		lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

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
