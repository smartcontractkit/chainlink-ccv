package lbtc

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
	messages := make([]protocol.Message, 0, len(tasks))
	for _, task := range tasks {
		messages = append(messages, task.Message)
	}

	attestations, err := v.attestationService.Fetch(ctx, messages)
	if err != nil {
		return batcher.BatchResult[verifier.VerificationError]{Error: err}
	}

	var errors []verifier.VerificationError
	for i, attestation := range attestations {
		task := tasks[i]
		err1 := ccvDataBatcher.Add(protocol.VerifierNodeResult{
			Message:         task.Message,
			MessageID:       task.Message.MustMessageID(),
			CCVVersion:      nil, // how do I get that
			CCVAddresses:    nil, // how do I get that
			ExecutorAddress: nil, // how do I get that
			Signature:       attestation,
		})
		if err1 != nil {
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
