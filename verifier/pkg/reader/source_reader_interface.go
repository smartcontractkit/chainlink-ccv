package reader

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
)

// SourceReader defines the interface for reading CCIP messages from source chains.
type SourceReader interface {
	// Start begins reading messages and pushing them to the messages channel
	Start(ctx context.Context) error

	// Stop stops the reader and closes the messages channel
	Stop() error

	// VerificationTaskChannel returns the channel where new message events are delivered
	VerificationTaskChannel() <-chan types.VerificationTask

	// HealthCheck returns the current health status of the reader
	HealthCheck(ctx context.Context) error

	// LatestBlock returns the latest block height
	LatestBlock(ctx context.Context) (*big.Int, error)

	// LatestFinalizedBlock returns the latest finalized block height
	LatestFinalizedBlock(ctx context.Context) (*big.Int, error)
}
