package utils

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// SendVerificationError sends a verification error to the error channel
func SendVerificationError(ctx context.Context, task types.VerificationTask, err error, verificationErrorCh chan<- types.VerificationError, lggr logger.Logger) {
	verificationError := types.VerificationError{
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
