package types

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// VerificationTask represents the complete CCIPMessageSent event data from the onRamp/proxy.
type VerificationTask struct {
	ReceiptBlobs []types.ReceiptWithBlob `json:"receipt_blobs"`
	Message      types.Message           `json:"message"`
}

// SourceReaderConfig contains configuration for the EVM source reader.
type SourceReaderConfig struct {
	OnRampAddress       types.UnknownAddress `json:"onramp_address"`
	ChainSelector       types.ChainSelector  `json:"chain_selector"`
	PollInterval        time.Duration        `json:"poll_interval"`
	StartBlock          uint64               `json:"start_block,omitempty"`
	MessagesChannelSize int                  `json:"messages_channel_size"`
}

// SourceConfig contains configuration for a single source chain.
type SourceConfig struct {
	VerifierAddress types.UnknownAddress `json:"verifier_address"`
}

// CoordinatorConfig contains configuration for the verification coordinator.
type CoordinatorConfig struct {
	SourceConfigs         map[types.ChainSelector]SourceConfig `json:"source_configs"`
	VerifierID            string                               `json:"verifier_id"`
	ProcessingChannelSize int                                  `json:"processing_channel_size"`
	ProcessingTimeout     time.Duration                        `json:"processing_timeout"`
	MaxBatchSize          int                                  `json:"max_batch_size"`
}

// VerificationError represents an error that occurred during message verification.
type VerificationError struct {
	Timestamp time.Time
	Error     error
	Task      VerificationTask
}

// Verifier defines the interface for message verification logic.
type Verifier interface {
	// VerifyMessage performs the actual verification of a message asynchronously
	VerifyMessage(ctx context.Context, task VerificationTask, ccvDataCh chan<- types.CCVData, verificationErrorCh chan<- VerificationError)
}
