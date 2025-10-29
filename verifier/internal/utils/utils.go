package utils

import (
	"context"
	"time"

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
