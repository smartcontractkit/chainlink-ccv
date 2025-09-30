package protocol

import (
	"context"
	"math/big"
)

// CheckpointManager defines the interface for checkpoint operations.
type CheckpointManager interface {
	// WriteCheckpoint writes a checkpoint for a specific chain
	WriteCheckpoint(ctx context.Context, chainSelector ChainSelector, blockHeight *big.Int) error

	// ReadCheckpoint reads a checkpoint for a specific chain, returns nil if not found
	ReadCheckpoint(ctx context.Context, chainSelector ChainSelector) (*big.Int, error)
}
