package statuschecker

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type StatusChecker struct {
	lggr               logger.Logger
	destinationReaders map[protocol.ChainSelector]executor.DestinationReader
}

func NewStatusChecker(lggr logger.Logger, destinationReaders map[protocol.ChainSelector]executor.DestinationReader) *StatusChecker {
	return &StatusChecker{
		lggr:               lggr,
		destinationReaders: destinationReaders,
	}
}

// GetMessageStatus checks if a message should be executed and/or retried.
// MESSAGE_UNTOUCHED: Message should be executed and retried.
// MESSAGE_IN_PROGRESS: Message is in progress, should be retried, but not currently executed.
// MESSAGE_SUCCESS: Message was executed successfully, don't retry and don't execute.
// MESSAGE_FAILURE: Message failed to execute, don't retry and don't execute.
func (sc *StatusChecker) GetMessageStatus(ctx context.Context, message protocol.Message) (shouldRetry bool, shouldExecute bool, err error) {
	// Check if the message is already executed to not waste gas and time.
	destinationChain := message.DestChainSelector
	messageID, err := message.MessageID()
	if err != nil {
		return false, false, fmt.Errorf("failed to get message ID: %w", err)
	}
	// todo: Add curse detection

	execuctionState, err := sc.destinationReaders[destinationChain].GetMessageExecutionState(
		ctx,
		message,
	)
	// TODO: use Logpoller to check confirmed/finalized state?
	// TODO: cache on GetMessageExecutionState IFF message is successful?
	if err != nil {
		// If we can't get execution state, don't execute, but put back in heap to retry later.
		return true, false, fmt.Errorf("failed to check GetMessageExecutionState: %w", err)
	}
	switch execuctionState {
	case executor.MESSAGE_SUCCESS:
		shouldRetry, shouldExecute, err = false, false, nil

	case executor.MESSAGE_IN_PROGRESS:
		shouldRetry, shouldExecute, err = true, false, nil

	// If message has failed to execute in the past, don't retry and don't execute.
	// Any changes to VerifierResults should be manually executed.
	case executor.MESSAGE_FAILURE:
		shouldRetry, shouldExecute, err = false, false, nil

	case executor.MESSAGE_UNTOUCHED:
		shouldRetry, shouldExecute, err = true, true, nil
	}

	sc.lggr.Infow("message status",
		"messageID", messageID,
		"executionState", execuctionState,
		"shouldRetry", shouldRetry,
		"shouldExecute", shouldExecute,
	)

	return shouldRetry, shouldExecute, err

}
