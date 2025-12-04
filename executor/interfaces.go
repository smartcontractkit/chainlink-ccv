package executor

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// StreamerResult is the result of a streaming operation.
type StreamerResult struct {
	Error    error
	Messages []protocol.MessageWithMetadata
}

// MessageSubscriber produces a channel of Messages objects that have new verifications.
type MessageSubscriber interface {
	// Start a streamer as a background process, it should send data to the
	// message channel as it becomes available.
	// TODO: this function signature is really odd, we shouldn't be passing in a pointer to a waitgroup.
	Start(
		ctx context.Context,
		results chan protocol.MessageWithMetadata,
		errors chan error,
	) error

	// IsRunning returns whether the streamer is running.
	IsRunning() bool
}

// MessageReader reads messages from a storage backend based on query parameters. It is implemented by the IndexerAPI.
type MessageReader interface {
	// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message and its metadata.
	ReadMessages(ctx context.Context, queryData protocol.MessagesV1Request) (map[string]protocol.MessageWithMetadata, error)
}

// VerifierResultReader reads verifier results from a storage backend based on messageID. It is implemented by the IndexerAPI.
type VerifierResultReader interface {
	// GetVerifierResults returns all verifierResults for a given messageID
	GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error)
}

// Executor is responsible for executing validating messages.
type Executor interface {
	// AttemptExecuteMessage gets any supplementary data and tries to execute the message
	HandleMessage(ctx context.Context, message protocol.Message) (shouldRetry bool, err error)
	// CheckValidMessage checks that message is valid
	CheckValidMessage(ctx context.Context, message protocol.Message) error
}

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters.
type ContractTransmitter interface {
	// ConvertAndWriteMessageToChain converts and transmits message to chain
	ConvertAndWriteMessageToChain(ctx context.Context, report AbstractAggregatedReport) error
}

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	// We need chain selector as well as messageID because messageID is hashed and we cannot use it to get message information.
	// todo: align so both functions are either return delay or return timestamp.
	GetReadyTimestamp(messageID protocol.Bytes32, chainSel protocol.ChainSelector, baseTime time.Time) time.Time
	// GetRetryDelay returns the delay in seconds to retry a message. It uses destination chain because some executors may not support all chains
	GetRetryDelay(destinationChain protocol.ChainSelector) time.Duration
}

// DestinationReader is an interface for reading message status and data from a single destination chain
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
// When integrating with non-evms, the implementer only needs to add support for a single chain.
type DestinationReader interface {
	// GetCCVSForMessage return cross-chain verifications for selected message
	GetCCVSForMessage(ctx context.Context, message protocol.Message) (CCVAddressInfo, error)
	// GetMessageExecutability returns true if message can be executed based on its on chain execution state.
	GetMessageExecutability(ctx context.Context, message protocol.Message) (bool, error)
	// GetRMNCursedSubjects returns the full list of cursed subjects for the chain. These can be Bytes16 ChainSelectors or the GlobalCurseSubject.
	GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error)
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
