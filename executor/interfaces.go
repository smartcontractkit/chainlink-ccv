package executor

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CCVResultStreamer produces a channel of MessageWithCCVData objects, the
// channel should only close if there is an error.
type CCVResultStreamer interface {
	// Start a streamer as a background process, it should send data to the
	// message channel as it becomes available.
	Start(
		ctx context.Context,
		lggr logger.Logger,
		wg *sync.WaitGroup,
	) (<-chan types.MessageWithCCVData, error)

	// Status of the streamer, returns whether or not it's running and a nil
	// error if healthy.
	Status() (bool, error)
}
