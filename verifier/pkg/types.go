package verifier

import (
	"time"

	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// Type aliases - the actual definitions live in verifier/pkg/vtypes.
type (
	VerificationTask  = vtypes.VerificationTask
	VerificationError = vtypes.VerificationError
	SourceConfig      = vtypes.SourceConfig
	CoordinatorConfig = vtypes.CoordinatorConfig
)

// NewRetriableVerificationError creates a retryable VerificationError.
func NewRetriableVerificationError(err error, task VerificationTask, delay time.Duration) VerificationError {
	return vtypes.NewRetriableVerificationError(err, task, delay)
}

// NewVerificationError creates a non-retryable VerificationError.
func NewVerificationError(err error, task VerificationTask) VerificationError {
	return vtypes.NewVerificationError(err, task)
}
