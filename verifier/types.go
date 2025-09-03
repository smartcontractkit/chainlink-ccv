package verifier

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

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

// SourceReader defines the interface for reading CCIP messages from source chains
type SourceReader interface {
	// Start begins reading messages and pushing them to the messages channel
	Start(ctx context.Context) error

	// Stop stops the reader and closes the messages channel
	Stop() error

	// VerificationTaskChannel returns the channel where new message events are delivered
	VerificationTaskChannel() <-chan common.VerificationTask

	// HealthCheck returns the current health status of the reader
	HealthCheck(ctx context.Context) error
}

// MessageSigner defines the interface for signing messages using the new chain-agnostic format
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature and verifier blob
	SignMessage(ctx context.Context, verificationTask common.VerificationTask, sourceVerifierAddress common.UnknownAddress) ([]byte, []byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() common.UnknownAddress
}
