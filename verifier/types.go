package verifier

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// VerificationTask represents the complete CCIPMessageSent event data from the onRamp/proxy.
type VerificationTask struct {
	// TODO: Rename ReceiptBlobs to VerifierBlobs to match with onchain code.
	ReceiptBlobs []protocol.ReceiptWithBlob `json:"receipt_blobs"`
	MessageID    string                     `json:"message_id"`
	Message      protocol.Message           `json:"message"`
	TxHash       protocol.ByteSlice         `json:"tx_hash"`
	BlockNumber  uint64                     `json:"block_number"`  // Block number when the message was included
	FirstSeenAt  time.Time                  `json:"first_seen_at"` // When message first entered the system (for E2E latency)
	QueuedAt     time.Time                  `json:"queued_at"`     // When added to finality queue (for finality wait duration)
}

// SourceConfig contains configuration for a single source chain.
type SourceConfig struct {
	VerifierAddress        protocol.UnknownAddress `json:"verifier_address"`
	DefaultExecutorAddress protocol.UnknownAddress `json:"default_executor_address"`
	ChainSelector          protocol.ChainSelector  `json:"chain_selector"`
	PollInterval           time.Duration           `json:"poll_interval"`
	PollTimeout            time.Duration           `json:"poll_timeout"`       // Maximum duration to wait for a block to be fetched (default: 10s)
	BatchSize              int                     `json:"batch_size"`         // Maximum number of verification tasks to batch before sending to verifier (default: 20)
	BatchTimeout           time.Duration           `json:"batch_timeout"`      // Maximum duration to wait before flushing incomplete verifier batch (default: 100ms)
	RMNRemoteAddress       protocol.UnknownAddress `json:"rmn_remote_address"` // RMN Remote contract address for curse detection
	MaxBlockRange          uint64                  `json:"max_block_range"`    // Max blocks per RPC query (default: 5000)
	DisableFinalityChecker bool                    `json:"disable_finality_checker"`
}

// CoordinatorConfig contains configuration for the verification coordinator.
type CoordinatorConfig struct {
	SourceConfigs       map[protocol.ChainSelector]SourceConfig `json:"source_configs"`
	VerifierID          string                                  `json:"verifier_id"`
	StorageBatchSize    int                                     `json:"storage_batch_size"`    // Maximum number of CCVData items to batch before writing to storage (default: 50)
	StorageBatchTimeout time.Duration                           `json:"storage_batch_timeout"` // Maximum duration to wait before flushing incomplete storage batch (default: 100ms)
	StorageRetryDelay   time.Duration                           `json:"storage_retry_delay"`   // Delay before retrying failed storage writes (default: 2s)
	CursePollInterval   time.Duration                           `json:"curse_poll_interval"`   // How often to poll RMN Remote contracts for curse status (default: 2s)
}

// VerificationError represents an error that occurred during message verification.
type VerificationError struct {
	Task      VerificationTask
	Timestamp time.Time
	Error     error
	// Retryable defines whether Coordinator should retry that error.
	// That way, Verifier can decide how higher order layer should act upon failure.
	// Additionally, it can suggest a delay before retrying.
	Retryable bool
	// Delay specifies how long to wait before retrying the verification. If empty, 10s is assumed.
	Delay *time.Duration
}

func (v *VerificationError) DelayOrDefault() time.Duration {
	if v.Delay != nil {
		return *v.Delay
	}
	return 10 * time.Second
}

func NewRetriableVerificationError(
	err error,
	task VerificationTask,
	delay time.Duration,
) VerificationError {
	return VerificationError{
		Timestamp: time.Now(),
		Error:     err,
		Task:      task,
		Retryable: true,
		Delay:     &delay,
	}
}

func NewVerificationError(err error, task VerificationTask) VerificationError {
	return VerificationError{
		Timestamp: time.Now(),
		Error:     err,
		Task:      task,
	}
}
