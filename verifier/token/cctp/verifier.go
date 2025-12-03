package cctp

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

type Verifier struct {
	attestationService AttestationService
}

func NewVerifier(attestationService AttestationService) Verifier {
	return Verifier{
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
		attestation, err := v.attestationService.Fetch(ctx, task.TxHash, task.Message)
		if err != nil {
			errors = append(errors, verifier.VerificationError{
				Timestamp: time.Now(),
				Error:     err,
				Task:      task,
			})
			continue
		}

		// build a payload for destination
		// <4 byte verifier version><encoded CCTP message><attestation>
		destPayload := attestation

		err = ccvDataBatcher.Add(protocol.VerifierNodeResult{
			Message:         task.Message,
			MessageID:       task.Message.MustMessageID(),
			CCVVersion:      nil, // how do I get that
			CCVAddresses:    nil, // how do I get that
			ExecutorAddress: nil, // how do I get that
			Signature:       destPayload,
		})
		if err != nil {
			errors = append(errors, verifier.VerificationError{
				Timestamp: time.Now(),
				Error:     err,
				Task:      task,
			})
			continue
		}
	}

	return batcher.BatchResult[verifier.VerificationError]{
		Items: errors,
		Error: nil,
	}
}
