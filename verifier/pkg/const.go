package verifier

import "time"

const (
	DefaultConfigFile = "/etc/config.toml"
	// ConfirmationDepth is the number of blocks to wait before considering a block finalized.
	// This is used for calculating finalized blocks as: (latest - ConfirmationDepth)
	// when running standalone mode. In CL node it's HeadTracker configuration.
	ConfirmationDepth = 15
	// DefaultJobQueueOperationTimeout is the timeout for job queue operations across verifier components.
	// Used by task_verifier and storage_writer for Consume, Complete, Retry, Fail, Cleanup operations.
	DefaultJobQueueOperationTimeout = 10 * time.Second
)

const (
	// TaskVerifierJobsTableName is the name of the table storing verification tasks.
	TaskVerifierJobsTableName = "ccv_task_verifier_jobs"
	// StorageWriterJobsTableName is the name of the table storing verification results for storage writing.
	StorageWriterJobsTableName = "ccv_storage_writer_jobs"
)
