package cctp

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Verifier struct {
	lggr               logger.Logger
	attestationService AttestationService
}

func NewVerifier(lggr logger.Logger, attestationService AttestationService) Verifier {
	return Verifier{
		lggr:               lggr,
		attestationService: attestationService,
	}
}

func (v Verifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
	ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult],
) batcher.BatchResult[verifier.VerificationError] {
	var errors []verifier.VerificationError
	for _, task := range tasks {
		lggr := logger.With(v.lggr, "messageID", task.MessageID, "txHash", task.TxHash)
		lggr.Infow("Verifying CCTP task")
		attestation, err := v.attestationService.Fetch(ctx, task.TxHash, task.Message)
		if err != nil {
			v.lggr.Warnw("Failed to fetch attestation", "err", err)
			errors = append(errors, verifier.VerificationError{
				Timestamp: time.Now(),
				Error:     err,
				Task:      task,
			})
			continue
		}
		result := protocol.VerifierNodeResult{
			Message:         task.Message,
			MessageID:       task.Message.MustMessageID(),
			CCVVersion:      attestation.ccvVerifierVersion,
			CCVAddresses:    []protocol.UnknownAddress{attestation.ccvAddress}, // what does go here? all ccv addresses involved in the message? or only dest/source?
			ExecutorAddress: nil,                                               // how do I get that? Is it needed at this stage?
			Signature:       attestation.ToVerifierFormat(),
		}

		if err = ccvDataBatcher.Add(result); err != nil {
			v.lggr.Errorw("VerifierResult: Failed to add to batcher", "err", err)
			errors = append(errors, verifier.VerificationError{
				Timestamp: time.Now(),
				Error:     err,
				Task:      task,
			})
			continue
		}
		v.lggr.Infow("VerifierResult: Successfully added to the batcher", "signature", result.Signature)
	}

	return batcher.BatchResult[verifier.VerificationError]{
		Items: errors,
		Error: nil,
	}
}
