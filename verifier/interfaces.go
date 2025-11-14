package verifier

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

// MessageSigner defines the interface for signing data.
// TODO: revisit this, shouldn't be ECDSA specific?
type MessageSigner interface {
	// Sign returns an ECDSA signature that is 65 bytes long (R + S + V).
	Sign(data []byte) (signed []byte, err error)
}

// Verifier defines the interface for message verification logic.
type Verifier interface {
	// VerifyMessages performs verification of a batch of messages, adding successful results to the batcher.
	// Returns a BatchResult containing any verification errors that occurred.
	VerifyMessages(ctx context.Context, tasks []VerificationTask, ccvDataBatcher *batcher.Batcher[CCVDataWithIdempotencyKey]) batcher.BatchResult[VerificationError]
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
