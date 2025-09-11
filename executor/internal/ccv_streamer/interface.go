package ccv_streamer

import (
	"context"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Streamer func(
	ctx context.Context,
	lggr logger.Logger,
	wg *sync.WaitGroup,
) <-chan types.MessageWithCCVData
