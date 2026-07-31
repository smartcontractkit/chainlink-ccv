package monitoring

import (
	"context"
	"time"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Monitoring provides all core monitoring functionality for the executor. Also can be implemented as a no-op.
// ServiceMetrics is embedded so that common service-level metrics (e.g. ccip_service_started)
// and any future ones are part of this interface without changing it.
type Monitoring interface {
	// Metrics returns the metrics labeler for the executor.
	Metrics() MetricLabeler
	// Tracing returns the tracer used across the executor pipeline.
	Tracing() tracing.Tracing
	commonmetrics.ServiceMetrics
}

// MetricLabeler provides all metric recording functionality for the indexer.
type MetricLabeler interface {
	ccvcommon.CurseCheckerMetrics

	// With returns a new metrics labeler with the given key-value pairs.
	With(keyValues ...string) MetricLabeler
	// RecordMessageExecutionLatency records the duration of the full ExecuteMessage operation.
	RecordMessageExecutionLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector)
	// IncrementMessagesProcessing increments the counter for processed messages.
	IncrementMessagesProcessing(ctx context.Context)
	// IncrementMessagesProcessingError increments the counter for failed message executions.
	IncrementMessagesProcessingError(ctx context.Context, retry bool)
	// RecordOfframpGetCCVsForMessageLatency records the duration of the GetCCVSForMessage onchain call.
	RecordOfframpGetCCVsForMessageLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector)
	// IncrementOfframpGetCCVsForMessageFailure increments the counter of failed GetCCVSForMessage onchain calls.
	IncrementOfframpGetCCVsForMessageFailure(ctx context.Context, destChainSelector protocol.ChainSelector)
	// IncrementExpiredMessages increments the counter for expired messages.
	IncrementExpiredMessages(ctx context.Context)
	// IncrementAlreadyExecutedMessages increments the counter for already executed messages.
	IncrementAlreadyExecutedMessages(ctx context.Context)
	// RecordMessageHeapSize records the size of the message heap.
	RecordMessageHeapSize(ctx context.Context, size int64)
	// IncrementHeartbeatSuccess increments the counter for successful heartbeats to indexer.
	IncrementHeartbeatSuccess(ctx context.Context)
	// IncrementHeartbeatFailure increments the counter for failed heartbeats to indexer.
	IncrementHeartbeatFailure(ctx context.Context)
	// IncrementIndexerSwitch increment the counter for number of times we switch between indexers.
	IncrementIndexerSwitch(ctx context.Context)
	// IncrementAllIndexersFailed fires when we were unable to access any healthy indexers.
	IncrementAllIndexersFailed(ctx context.Context)
	// SetLastHeartbeatTimestamp sets the timestamp of the last successful heartbeat.
	SetLastHeartbeatTimestamp(ctx context.Context, timestamp int64)
	// IncrementUnrecoverableMessageFailure fires when we were unable to execute a message due to an unrecoverable error.
	IncrementUnrecoverableMessageFailure(ctx context.Context)
	// IncrementDestinationReaderCriticalFailure fires when a destination reader
	// has entered an unrecoverable failure state (e.g. the execution attempt
	// poller permanently failed). This should trigger an alert.
	IncrementDestinationReaderCriticalFailure(ctx context.Context, destChainSelector protocol.ChainSelector)
}
