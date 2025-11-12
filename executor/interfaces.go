package executor

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// StreamerResult is the result of a streaming operation.
type StreamerResult struct {
	Error    error
	Messages []protocol.Message
}

// MessageSubscriber produces a channel of Messages objects that have new verifications.
type MessageSubscriber interface {
	// Start a streamer as a background process, it should send data to the
	// message channel as it becomes available.
	// TODO: this function signature is really odd, we shouldn't be passing in a pointer to a waitgroup.
	Start(
		ctx context.Context,
		wg *sync.WaitGroup,
	) (<-chan StreamerResult, error)

	// IsRunning returns whether the streamer is running.
	IsRunning() bool
}

// MessageReader reads messages from a storage backend based on query parameters. It is implemented by the IndexerAPI.
type MessageReader interface {
	// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
	ReadMessages(ctx context.Context, queryData protocol.MessagesV1Request) (map[string]protocol.Message, error)
}

// VerifierResultReader reads verifier results from a storage backend based on messageID. It is implemented by the IndexerAPI.
type VerifierResultReader interface {
	// GetVerifierResults returns all verifierResults for a given messageID
	GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.CCVData, error)
}

// Executor is responsible for executing validating messages.
type Executor interface {
	// AttemptExecuteMessage gets any supplementary data and tries to execute the message
	AttemptExecuteMessage(ctx context.Context, message protocol.Message) error
	// CheckValidMessage checks that message is valid
	CheckValidMessage(ctx context.Context, message protocol.Message) error
}

// StatusChecker tells us if a message should be executed and retried.
type StatusChecker interface {
	GetMessageStatus(ctx context.Context, message protocol.Message) (bool, bool, error)
}

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters.
type ContractTransmitter interface {
	// ConvertAndWriteMessageToChain converts and transmits message to chain
	ConvertAndWriteMessageToChain(ctx context.Context, report AbstractAggregatedReport) error
}

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	// todo: Switch this to GetReadyDelay instead of GetReadyTimestamp
	GetReadyTimestamp(messageID protocol.Bytes32, verifierTimestamp int64) int64
	// GetRetryDelay returns the delay in seconds to retry a message. It uses destination chain because some executors may not support all chains
	GetRetryDelay(destinationChain protocol.ChainSelector) int64
}

// DestinationReader is an interface for reading message status and data from a single destination chain
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
// When integrating with non-evms, the implementer only needs to add support for a single chain.
type DestinationReader interface {
	// GetCCVSForMessage return cross-chain verifications for selected message
	GetCCVSForMessage(ctx context.Context, message protocol.Message) (CCVAddressInfo, error)
	// GetMessageExecutionState returns true if message is executed
	GetMessageExecutionState(ctx context.Context, message protocol.Message) (MessageExecutionState, error)
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
	RecordMessageExecutionLatency(ctx context.Context, duration time.Duration)
	// IncrementMessagesProcessed increments the counter for successfully processed messages.
	IncrementMessagesProcessed(ctx context.Context)
	// IncrementMessagesProcessingFailed increments the counter for failed message executions.
	IncrementMessagesProcessingFailed(ctx context.Context)
}
