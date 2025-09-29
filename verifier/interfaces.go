package verifier

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// MessageSigner defines the interface for signing messages using the new chain-agnostic format.
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature
	SignMessage(ctx context.Context, verificationTask VerificationTask, sourceVerifierAddress protocol.UnknownAddress) ([]byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() protocol.UnknownAddress
}

// SourceReader defines the interface for reading CCIP messages from source chains.
type SourceReader interface {
	// Start begins reading messages and pushing them to the messages channel
	Start(ctx context.Context) error

	// Stop stops the reader and closes the messages channel
	Stop() error

	// VerificationTaskChannel returns the channel where new message events are delivered
	VerificationTaskChannel() <-chan VerificationTask

	// HealthCheck returns the current health status of the reader
	HealthCheck(ctx context.Context) error

	// LatestBlock returns the latest block height
	LatestBlock(ctx context.Context) (*big.Int, error)

	// LatestFinalizedBlock returns the latest finalized block height
	LatestFinalizedBlock(ctx context.Context) (*big.Int, error)
}

// CheckpointManager defines the interface for checkpoint operations.
type CheckpointManager interface {
	// WriteCheckpoint writes a checkpoint for a specific chain
	WriteCheckpoint(ctx context.Context, chainSelector protocol.ChainSelector, blockHeight *big.Int) error

	// ReadCheckpoint reads a checkpoint for a specific chain, returns nil if not found
	ReadCheckpoint(ctx context.Context, chainSelector protocol.ChainSelector) (*big.Int, error)
}
