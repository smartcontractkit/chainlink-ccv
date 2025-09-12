package executor

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// StreamerResult is the result of a streaming operation, it contains either
type StreamerResult struct {
	Messages []types.MessageWithCCVData
	Error    error
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
	ExecuteMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error
	// CheckValidMessage checks that message is valid
	CheckValidMessage(ctx context.Context, messageWithCCVData types.MessageWithCCVData) error
}
