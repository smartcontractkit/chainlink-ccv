package verifier

import "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"

// Constant re-exports - the actual values live in verifier/pkg/vtypes.
const (
	ConfirmationDepth               = vtypes.ConfirmationDepth
	DefaultJobQueueOperationTimeout = vtypes.DefaultJobQueueOperationTimeout
	TaskVerifierJobsTableName       = vtypes.TaskVerifierJobsTableName
	StorageWriterJobsTableName      = vtypes.StorageWriterJobsTableName
)
