package verifier

import vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"

// Constant re-exports - the actual values live in verifier/pkg/vtypes.
const (
	DefaultConfigFile               = vtypes.DefaultConfigFile
	ConfirmationDepth               = vtypes.ConfirmationDepth
	DefaultJobQueueOperationTimeout = vtypes.DefaultJobQueueOperationTimeout
	TaskVerifierJobsTableName       = vtypes.TaskVerifierJobsTableName
	StorageWriterJobsTableName      = vtypes.StorageWriterJobsTableName
)
