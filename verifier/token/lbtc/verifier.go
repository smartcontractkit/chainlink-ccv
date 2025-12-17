package lbtc

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Verifier struct {
	lggr logger.Logger

	attestationService AttestationService
	ccvVerifierVersion protocol.ByteSlice
}

func NewVerifier(
	lggr logger.Logger,
	attestationService AttestationService,
) verifier.Verifier {
	return &Verifier{
		lggr:               lggr,
		attestationService: attestationService,
		ccvVerifierVersion: CCVVerifierVersion,
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
		return batcher.BatchResult[verifier.VerificationError]{Error: err}
	}

	// 2. Process each task, iterate and match from response
	var errors []verifier.VerificationError
	for _, task := range tasks {
		lggr := logger.With(v.lggr, "messageID", task.MessageID, "txHash", task.TxHash)
		lggr.Infow("Verifying Lombard task")

		attestation, exists := attestations[task.MessageID]
		if !exists {
			lggr.Debugw("Attestation not found for message")
			errors = append(errors, verifier.NewVerificationError(
				fmt.Errorf("attestation not found for message ID: %s", task.MessageID),
				task,
			))
			continue
		}

		if !attestation.IsReady() {
			lggr.Debugw("Attestation not ready for message")
			errors = append(errors, verifier.NewVerificationError(
				fmt.Errorf("attestation not ready for message ID: %s", task.MessageID),
				task,
			))
			continue
		}

		attestationPayload, err := attestation.ToVerifierFormat()
		if err != nil {
			lggr.Errorw("Failed to decode attestation data", "err", err)
			errors = append(errors, verifier.NewVerificationError(err, task))
			continue
		}

		result, err1 := commit.CreateVerifierNodeResult(
			&task,
			attestationPayload,
			v.ccvVerifierVersion,
		)
		if err1 != nil {
			lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
			errors = append(errors, verifier.NewVerificationError(err1, task))
			continue
		}

		// 2.1 Add to batcher one by one
		if err = ccvDataBatcher.Add(*result); err != nil {
			lggr.Errorw("VerifierResult: Failed to add to batcher", "err", err)
			errors = append(errors, verifier.NewVerificationError(err, task))
			continue
		}
		lggr.Infow("VerifierResult: Successfully added to the batcher", "signature", result.Signature)
	}

	return batcher.BatchResult[verifier.VerificationError]{
		Items: errors,
		Error: nil,
	}
}
