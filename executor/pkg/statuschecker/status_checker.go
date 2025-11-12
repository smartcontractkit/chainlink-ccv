package statuschecker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type StatusChecker struct {
	lggr               logger.Logger
	destinationReaders map[protocol.ChainSelector]executor.DestinationReader
	messageExpiry      map[protocol.Bytes32]int64
	expiryDuration     time.Duration
	messageExpiryMu    sync.RWMutex
}

func NewStatusChecker(lggr logger.Logger, destinationReaders map[protocol.ChainSelector]executor.DestinationReader, expiryDuration time.Duration) *StatusChecker {
	messageExpiry := make(map[protocol.Bytes32]int64)
	return &StatusChecker{
		lggr:               lggr,
		destinationReaders: destinationReaders,
		messageExpiry:      messageExpiry,
		expiryDuration:     expiryDuration,
	}
}

// GetMessageStatus checks if a message should be executed and/or retried.
// Returns (shouldRetry bool, shouldExecute bool, error) to indicate whether the message should be retried (added back to heap) and executed.
func (sc *StatusChecker) GetMessageStatus(ctx context.Context, message protocol.Message, currentTime int64) (bool, bool, error) {
	messageID, err := message.MessageID()
	if err != nil {
		return false, false, fmt.Errorf("failed to get message ID: %w", err)
	}
	if sc.IsMessageExpired(messageID, currentTime) {
		return false, false, nil
	}
	if sc.IsCursed(message) {
		return false, false, nil
	}
	shouldRetry, shouldExecute, err := sc.GetExecutionState(ctx, message, messageID)
	if !shouldRetry { // if message should not be retried, don't add back to heap
		sc.messageExpiryMu.Lock()
		defer sc.messageExpiryMu.Unlock()
		delete(sc.messageExpiry, messageID)
	}
	return shouldRetry, shouldExecute, err
}

// IsMessageExpired checks the message retry against an 8 hour expiry timer.
func (sc *StatusChecker) IsMessageExpired(messageID protocol.Bytes32, currentTime int64) bool {
	// todo: Have some garbage collection on the expiry map to ensure there're no stale entries
	sc.messageExpiryMu.RLock()
	defer sc.messageExpiryMu.RUnlock()

	expiryTime, ok := sc.messageExpiry[messageID]
	if !ok {
		// if no expiry time, add to expiry map, indicate not expired
		sc.messageExpiry[messageID] = currentTime + int64(sc.expiryDuration.Seconds())
	}
	// if message is expired, delete from expiry map
	if currentTime > expiryTime {
		delete(sc.messageExpiry, messageID)
		return true
	}
	return false
}

func (sc *StatusChecker) IsCursed(message protocol.Message) bool {
	// todo: implement
	return false
}

// GetExecutionState checks the execution state of a message and returns if it should be retried and executed.
// MESSAGE_UNTOUCHED: Message should be executed and retried.
// MESSAGE_IN_PROGRESS: Message is in progress, should be retried, but not currently executed.
// MESSAGE_SUCCESS: Message was executed successfully, don't retry and don't execute.
// MESSAGE_FAILURE: Message failed to execute, don't retry and don't execute.
func (sc *StatusChecker) GetExecutionState(ctx context.Context, message protocol.Message, id protocol.Bytes32) (shouldRetry, shouldExecute bool, err error) {
	// Check if the message is already executed to not waste gas and time.
	destinationChain := message.DestChainSelector

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
		"messageID", id,
		"executionState", execuctionState,
		"shouldRetry", shouldRetry,
		"shouldExecute", shouldExecute,
	)

	return shouldRetry, shouldExecute, err
}
