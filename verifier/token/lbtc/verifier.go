package lbtc

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
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

// Verifier is responsible for verifying LBTC messages by fetching their attestations
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
	attestationService AttestationService,
) verifier.Verifier {
	return NewVerifierWithConfig(
		lggr,
		attestationService,
		CCVVerifierVersion,
		attestationNotReadyRetry,
		anyErrorRetry,
	)
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
	ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult],
) batcher.BatchResult[verifier.VerificationError] {
	messages := make([]protocol.Message, 0, len(tasks))
	for _, task := range tasks {
		messages = append(messages, task.Message)
	}

	// 1. Fetch attestations in batch
	attestations, err := v.attestationService.Fetch(ctx, messages)
	if err != nil {
		// Mark all tasks as retriable errors if fetching attestations failed
		errs := make([]verifier.VerificationError, 0, len(tasks))
		for _, task := range tasks {
			errs = append(errs, v.errorRetry(err, task))
		}
		return batcher.BatchResult[verifier.VerificationError]{Items: errs}
	}

	// 2. Process each task, iterate and match from response
	var errors []verifier.VerificationError
	for _, task := range tasks {
		lggr := logger.With(v.lggr, "messageID", task.MessageID, "txHash", task.TxHash)
		lggr.Infow("Verifying Lombard task")

		attestation, exists := attestations[task.MessageID]
		if !exists {
			lggr.Debugw("Attestation not found for message")
			errors = append(errors, v.attestationErrorRetry(
				fmt.Errorf("attestation not found for message ID: %s", task.MessageID),
				task,
			))
			continue
		}

		if !attestation.IsReady() {
			lggr.Debugw("Attestation not ready for message")
			errors = append(errors, v.attestationErrorRetry(
				fmt.Errorf("attestation not ready for message ID: %s", task.MessageID),
				task,
			))
			continue
		}

		attestationPayload, err := attestation.ToVerifierFormat()
		if err != nil {
			lggr.Errorw("Failed to decode attestation data", "err", err)
			errors = append(errors, v.errorRetry(err, task))
			continue
		}

		result, err1 := commit.CreateVerifierNodeResult(
			&task,
			attestationPayload,
			v.ccvVerifierVersion,
		)
		if err1 != nil {
			lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
			errors = append(errors, v.errorRetry(err1, task))
			continue
		}

		// 2.1 Add to batcher one by one
		if err = ccvDataBatcher.Add(*result); err != nil {
			lggr.Errorw("VerifierResult: Failed to add to batcher", "err", err)
			errors = append(errors, v.errorRetry(err, task))
			continue
		}
		lggr.Infow("VerifierResult: Successfully added to the batcher", "signature", result.Signature)
	}

	return batcher.BatchResult[verifier.VerificationError]{
		Items: errors,
		Error: nil,
	}
}

func (v *Verifier) attestationErrorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.anyErrorRetry)
}

func (v *Verifier) errorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.anyErrorRetry)
}
