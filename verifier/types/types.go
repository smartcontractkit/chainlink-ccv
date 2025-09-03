package types

import (
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// VerificationTask represents the complete CCIPMessageSent event data from the onRamp/proxy
type VerificationTask struct {
	Message      common.Message           `json:"message"`       // the complete message
	ReceiptBlobs []common.ReceiptWithBlob `json:"receipt_blobs"` // receipt blobs from event
}

// SourceReaderConfig contains configuration for the EVM source reader
type SourceReaderConfig struct {
	ChainSelector       cciptypes.ChainSelector `json:"chain_selector"`
	OnRampAddress       common.UnknownAddress   `json:"onramp_address"`
	PollInterval        time.Duration           `json:"poll_interval"`
	StartBlock          uint64                  `json:"start_block,omitempty"`
	MessagesChannelSize int                     `json:"messages_channel_size"`
}

// SourceConfig contains configuration for a single source chain
type SourceConfig struct {
	VerifierAddress common.UnknownAddress `json:"verifier_address"`
}

// CoordinatorConfig contains configuration for the verification coordinator
type CoordinatorConfig struct {
	VerifierID            string                                   `json:"verifier_id"`
	SourceConfigs         map[cciptypes.ChainSelector]SourceConfig `json:"source_configs"`
	ProcessingChannelSize int                                      `json:"processing_channel_size"`
	ProcessingTimeout     time.Duration                            `json:"processing_timeout"`
	MaxBatchSize          int                                      `json:"max_batch_size"`
}
