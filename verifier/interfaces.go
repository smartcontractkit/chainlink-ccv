package verifier

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

// MessageSigner defines the interface for signing messages using the new chain-agnostic format.
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature
	SignMessage(ctx context.Context, verificationTask VerificationTask, sourceVerifierAddress protocol.UnknownAddress) ([]byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() protocol.UnknownAddress
}

// Verifier defines the interface for message verification logic.
type Verifier interface {
	// VerifyMessages performs verification of a batch of messages, adding successful results to the batcher.
	// Returns a BatchResult containing any verification errors that occurred.
	VerifyMessages(ctx context.Context, tasks []VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.CCVData]) batcher.BatchResult[VerificationError]
}

// SourceReader defines the interface for reading CCIP messages from source chains.
// This interface abstracts polling-based access to blockchain data.
//
// Implementations should handle chain-specific details and use an injected HeadTracker
// for latest block state queries.
//
// Thread-safety: All methods must be safe for concurrent calls.
type SourceReader interface {
	// VerificationTasks returns tasks in the given block range
	VerificationTasks(ctx context.Context, fromBlock, toBlock *big.Int) ([]VerificationTask, error)

	// BlockTime returns the timestamp of a given block.
	BlockTime(ctx context.Context, block *big.Int) (uint64, error)

	// GetBlocksHeaders returns the full block headers for a batch of block numbers.
	// This is more efficient than individual calls when building the chain tail.
	// Returns error if any block doesn't exist or RPC call fails.
	GetBlocksHeaders(ctx context.Context, blockNumber []*big.Int) (map[*big.Int]protocol.BlockHeader, error)

	// GetBlockHeaderByHash returns a block header by its hash.
	// Required for walking back parent chain during LCA finding in reorg detection.
	// Returns nil if block doesn't exist, error for RPC failures.
	GetBlockHeaderByHash(ctx context.Context, hash protocol.Bytes32) (*protocol.BlockHeader, error)
}
