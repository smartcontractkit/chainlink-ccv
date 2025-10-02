package executor

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// StreamerResult is the result of a streaming operation.
type StreamerResult struct {
	Error    error
	Messages []MessageWithCCVData
}

// CCVResultStreamer produces a channel of MessageWithCCVData objects, the
// channel should only close if there is an error.
type CCVResultStreamer interface {
	// Start a streamer as a background process, it should send data to the
	// message channel as it becomes available.
	Start(
		ctx context.Context,
		lggr logger.Logger,
		wg *sync.WaitGroup,
	) (<-chan StreamerResult, error)

	// IsRunning returns whether or not the streamer is running.
	IsRunning() bool
}

// Executor is responsible for executing validating messages.
type Executor interface {
	// ExecuteMessage executes the message
	ExecuteMessage(ctx context.Context, messageWithCCVData MessageWithCCVData) error
	// CheckValidMessage checks that message is valid
	CheckValidMessage(ctx context.Context, messageWithCCVData MessageWithCCVData) error
}

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters.
type ContractTransmitter interface {
	// ConvertAndWriteMessageToChain converts and transmits message to chain
	ConvertAndWriteMessageToChain(ctx context.Context, report AbstractAggregatedReport) error
}

type LeaderElector interface {
	// GetReadyTimestamp to determine when a message is ready to be executed by this executor
	GetReadyTimestamp(messageID protocol.Bytes32, message protocol.Message, verifierTimestamp int64) int64
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
