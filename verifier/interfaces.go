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

// SourceReader defines the interface for reading CCIP messages from source chains.
// This interface abstracts both polling and subscription-based access to blockchain data.
//
// Implementations should handle chain-specific details:
//
// Thread-safety: All methods must be safe for concurrent calls.
type SourceReader interface {
	// VerificationTasks returns tasks in the given block range
	VerificationTasks(ctx context.Context, fromBlock, toBlock *big.Int) ([]VerificationTask, error)

	// BlockTime returns the timestamp of a given block.
	BlockTime(ctx context.Context, block *big.Int) (uint64, error)

	// LatestBlockHeight returns the latest block height
	LatestBlockHeight(ctx context.Context) (*big.Int, error)

	// LatestFinalizedBlockHeight returns the latest finalized block height
	LatestFinalizedBlockHeight(ctx context.Context) (*big.Int, error)

	// SubscribeNewHeads subscribes to new block headers.
	// Returns a channel that receives new headers as they arrive.
	// Implementation may poll internally and push to channel for chains without native subscriptions.
	// The returned channel is closed when subscription ends or context is cancelled.
	// Returns error if subscription cannot be established.
	SubscribeNewHeads(ctx context.Context) (<-chan *protocol.BlockHeader, error)

	// GetBlocksHeaders returns the full block header (number, hash, parent hash, timestamp).
	// This is more efficient than separate calls when building the chain tail.
	// Returns error if block doesn't exist or RPC call fails.
	GetBlocksHeaders(ctx context.Context, blockNumber []*big.Int) (map[*big.Int]protocol.BlockHeader, error)
}

// Verifier defines the interface for message verification logic.
type Verifier interface {
	// VerifyMessages performs verification of a batch of messages, adding successful results to the batcher.
	// Returns a BatchResult containing any verification errors that occurred.
	VerifyMessages(ctx context.Context, tasks []VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.CCVData]) batcher.BatchResult[VerificationError]
}
