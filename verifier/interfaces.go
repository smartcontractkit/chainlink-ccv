package verifier

import (
	"context"
	"math/big"
	"time"

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
	// The returned channel is closed when subscription ends or context is canceled.
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

// Monitoring provides all core monitoring functionality for the verifier.
type Monitoring interface {
	// Metrics returns the metrics labeler for the verifier.
	Metrics() MetricLabeler
}

// MetricLabeler provides all metric recording functionality for the verifier.
type MetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) MetricLabeler

	// E2E - North Star Metric

	// RecordMessageE2ELatency records the full message lifecycle latency from source read to storage write.
	RecordMessageE2ELatency(ctx context.Context, duration time.Duration)

	// Message processing counters

	// IncrementMessagesProcessed increments the counter for successfully processed messages.
	IncrementMessagesProcessed(ctx context.Context)
	// IncrementMessagesVerificationFailed increments the counter for failed message verifications.
	IncrementMessagesVerificationFailed(ctx context.Context)

	// Fine-grained latency breakdown for debugging

	// RecordFinalityWaitDuration records the time a message spent waiting in the finality queue.
	RecordFinalityWaitDuration(ctx context.Context, duration time.Duration)
	// RecordMessageVerificationDuration records the duration of the full VerifyMessage operation.
	RecordMessageVerificationDuration(ctx context.Context, duration time.Duration)
	// RecordStorageWriteDuration records the duration of writing to offchain storage.
	RecordStorageWriteDuration(ctx context.Context, duration time.Duration)

	// Queue health metrics

	// RecordFinalityQueueSize records the current size of the finality queue.
	RecordFinalityQueueSize(ctx context.Context, size int64)
	// RecordCCVDataChannelSize records the current size of the CCV data channel buffer.
	RecordCCVDataChannelSize(ctx context.Context, size int64)

	// Error tracking

	// IncrementStorageWriteErrors increments the counter for storage write errors.
	IncrementStorageWriteErrors(ctx context.Context)

	// Chain state tracking (for multi-chain monitoring)

	// RecordSourceChainLatestBlock records the latest block number for a source chain.
	RecordSourceChainLatestBlock(ctx context.Context, blockNum int64)
	// RecordSourceChainFinalizedBlock records the latest finalized block number for a source chain.
	RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64)
}
