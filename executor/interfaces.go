package executor

import (
	"context"
	"time"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// StreamerResult is the result of a streaming operation.
type StreamerResult struct {
	Error    error
	Messages []common.MessageWithMetadata
}

// MessageSubscriber produces a channel of Messages objects that have new verifications.
type MessageSubscriber interface {
	// Start a streamer as a background process, it should send data to the
	// message channel as it becomes available.
	Start(
		ctx context.Context,
	) (<-chan common.MessageWithMetadata, <-chan error, error)

	// IsRunning returns whether the streamer is running.
	IsRunning() bool
}

// MessageReader reads messages from a storage backend based on query parameters. It is implemented by the IndexerAPI.
type MessageReader interface {
	// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message and its metadata.
	ReadMessages(ctx context.Context, queryData v1.MessagesInput) (map[string]common.MessageWithMetadata, error)
}

// VerifierResultReader reads verifier results from a storage backend based on messageID. It is implemented by the IndexerAPI.
type VerifierResultReader interface {
	// GetVerifierResults returns all verifierResults for a given messageID
	GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error)
}

// Executor is responsible for executing validating messages.
type Executor interface {
	services.Service

	// HandleMessage gets any supplementary data and tries to execute the message
	HandleMessage(ctx context.Context, message protocol.Message) (shouldRetry bool, err error)
	// CheckValidMessage checks that message is valid
	CheckValidMessage(ctx context.Context, message protocol.Message) error
}

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	// We need chain selector as well as messageID because messageID is hashed and we cannot use it to get message information.
	// todo: align so both functions are either return delay or return timestamp.
	GetReadyTimestamp(messageID protocol.Bytes32, chainSel protocol.ChainSelector, baseTime time.Time) time.Time
	// GetRetryDelay returns the delay in seconds to retry a message. It uses destination chain because some executors may not support all chains
	GetRetryDelay(destinationChain protocol.ChainSelector) time.Duration
}

// Monitoring provides all core monitoring functionality for the executor. Also can be implemented as a no-op.
type Monitoring interface {
	// Metrics returns the metrics labeler for the executor.
	Metrics() MetricLabeler
}

// MetricLabeler provides all metric recording functionality for the indexer.
type MetricLabeler interface {
	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) MetricLabeler
	// RecordMessageExecutionLatency records the duration of the full ExecuteMessage operation.
	RecordMessageExecutionLatency(ctx context.Context, duration time.Duration, destSelector protocol.ChainSelector)
	// IncrementMessagesProcessed increments the counter for successfully processed messages.
	IncrementMessagesProcessed(ctx context.Context)
	// IncrementMessagesProcessingFailed increments the counter for failed message executions.
	IncrementMessagesProcessingFailed(ctx context.Context)
	// IncrementCCVInfoCacheHits increments the counter for cache hits in the destination reader.
	IncrementCCVInfoCacheHits(ctx context.Context)
	// IncrementCCVInfoCacheMisses increments the counter for cache misses in the destination reader.
	IncrementCCVInfoCacheMisses(ctx context.Context)
	// RecordQueryCCVInfoLatency records the duration of the GetCCVSForMessage operation, including cache hits and chain queries.
	RecordQueryCCVInfoLatency(ctx context.Context, duration time.Duration, destSelector protocol.ChainSelector)
	// IncrementExpiredMessages increments the counter for expired messages.
	IncrementExpiredMessages(ctx context.Context)
	// IncrementAlreadyExecutedMessages increments the counter for already executed messages.
	IncrementAlreadyExecutedMessages(ctx context.Context)
	// RecordMessageHeapSize records the size of the message heap.
	RecordMessageHeapSize(ctx context.Context, size int64)
}
