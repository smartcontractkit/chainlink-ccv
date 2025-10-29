package verifier

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// VerificationTask represents the complete CCIPMessageSent event data from the onRamp/proxy.
type VerificationTask struct {
	// TODO: Rename ReceiptBlobs to VerifierBlobs to match with onchain code.
	ReceiptBlobs []protocol.ReceiptWithBlob `json:"receipt_blobs"`
	Message      protocol.Message           `json:"message"`
	BlockNumber  uint64                     `json:"block_number"` // Block number when the message was included
	CreatedAt    time.Time                  `json:"created_at"`   // When message first entered the system (for E2E latency)
	QueuedAt     time.Time                  `json:"queued_at"`    // When added to finality queue (for finality wait duration)
}

// SourceConfig contains configuration for a single source chain.
type SourceConfig struct {
	VerifierAddress        protocol.UnknownAddress `json:"verifier_address"`
	DefaultExecutorAddress protocol.UnknownAddress `json:"default_executor_address"`
	ChainSelector          protocol.ChainSelector  `json:"chain_selector"`
	PollInterval           time.Duration           `json:"poll_interval"`
}

// CoordinatorConfig contains configuration for the verification coordinator.
type CoordinatorConfig struct {
	SourceConfigs       map[protocol.ChainSelector]SourceConfig `json:"source_configs"`
	VerifierID          string                                  `json:"verifier_id"`
	StorageBatchSize    int                                     `json:"storage_batch_size"`    // Maximum number of CCVData items to batch before writing to storage (default: 50)
	StorageBatchTimeout time.Duration                           `json:"storage_batch_timeout"` // Maximum duration to wait before flushing incomplete storage batch (default: 100ms)
}

// VerificationError represents an error that occurred during message verification.
type VerificationError struct {
	Timestamp time.Time
	Error     error
	Task      VerificationTask
}
