package executor

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CCVResultStreamer produces a channel of MessageWithCCVData objects, the
// channel should only close if there is an error.
type CCVResultStreamer func(
	ctx context.Context,
	lggr logger.Logger,
	wg *sync.WaitGroup,
) <-chan types.MessageWithCCVData
