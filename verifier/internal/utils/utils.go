package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// SendVerificationError sends a verification error to the error channel.
func SendVerificationError(ctx context.Context, task verifier.VerificationTask, err error, verificationErrorCh chan<- verifier.VerificationError, lggr logger.Logger) {
	verificationError := verifier.VerificationError{
		Task:      task,
		Error:     err,
		Timestamp: time.Now(),
	}

	select {
	case verificationErrorCh <- verificationError:
		lggr.Errorw("Verification error sent to error channel", "error", err)
	case <-ctx.Done():
		lggr.Debugw("Context cancelled while sending verification error", "error", err)
	}
}

// FindVerifierIndexBySourceAddress finds the index of the source verifier address in the ReceiptBlobs array.
func FindVerifierIndexBySourceAddress(verificationTask *verifier.VerificationTask, sourceVerifierAddress types.UnknownAddress) (int, error) {
	for i, receipt := range verificationTask.ReceiptBlobs {
		if receipt.Issuer.String() == sourceVerifierAddress.String() {
			return i, nil
		}
	}

	return -1, fmt.Errorf("source verifier address %s not found in ReceiptBlobs", sourceVerifierAddress.String())
}
