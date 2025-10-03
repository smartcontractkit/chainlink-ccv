package common

import (
	"context"
	"time"
)

// VerifierMonitoring provides all core monitoring functionality for the verifier.
type VerifierMonitoring interface {
	// Metrics returns the metrics labeler for the verifier.
	Metrics() VerifierMetricLabeler
}

// VerifierMetricLabeler provides all metric recording functionality for the verifier.
type VerifierMetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) VerifierMetricLabeler

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
