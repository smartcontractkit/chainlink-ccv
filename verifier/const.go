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
