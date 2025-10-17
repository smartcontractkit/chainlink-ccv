package executor

import (
	"context"
	"sync"

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

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters.
type ContractTransmitter interface {
	// ConvertAndWriteMessageToChain converts and transmits message to chain
	ConvertAndWriteMessageToChain(ctx context.Context, report AbstractAggregatedReport) error
}

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	GetReadyTimestamp(messageID protocol.Bytes32, verifierTimestamp int64) int64
}

// DestinationReader is an interface for reading message status and data from a single destination chain
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
// When integrating with non-evms, the implementer only needs to add support for a single chain.
type DestinationReader interface {
	// GetCCVSForMessage return cross-chain verifications for selected message
	GetCCVSForMessage(ctx context.Context, message protocol.Message) (CcvAddressInfo, error)
	// IsMessageExecuted returns true if message is executed
	IsMessageExecuted(ctx context.Context, message protocol.Message) (bool, error)
}
