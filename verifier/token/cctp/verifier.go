package cctp

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
	return NewVerifierWithConfig(lggr, attestationService, attestationNotReadyRetry, anyErrorRetry)
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
	ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult],
) batcher.BatchResult[verifier.VerificationError] {
	var errors []verifier.VerificationError
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
			errors = append(errors, v.errorRetry(err, task))
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

		// 2. Create VerifierNodeResult
		result, err := commit.CreateVerifierNodeResult(
			&task,
			attestationPayload,
			attestation.ccvVerifierVersion,
		)
		if err != nil {
			lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
			errors = append(errors, v.errorRetry(err, task))
			continue
		}

		// 3. Add to batcher
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
	return verifier.NewRetriableVerificationError(err, task, v.attestationNotReadyRetry)
}

func (v *Verifier) errorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.anyErrorRetry)
}
