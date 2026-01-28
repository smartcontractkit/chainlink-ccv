package destinationreader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

const (
	// defaultPollInterval is the default interval for polling when WebSocket is not available.
	defaultPollInterval = 5 * time.Second
	// functionSelectorLength is the length of an Ethereum function selector in bytes.
	functionSelectorLength = 4
	// expectedParamCount is the expected number of parameters for the execute function.
	expectedParamCount = 3
	// executeMethodName is the name of the execute method in the offramp ABI.
	executeMethodName = "execute"
	// evmExecutionAttemptPollerServiceName is the name of the service.
	evmExecutionAttemptPollerServiceName = "evm.executionattemptpoller.Service"
	// maxFilterBlockRange is the maximum block range for filter queries to avoid RPC limits.
	// Common Ethereum RPC limits are around 10,000 blocks, using a conservative value here.
	maxFilterBlockRange = 5000
	// maxSubscriptionReconnectAttempts is the maximum number of times to attempt reconnecting the subscription
	// before falling back to HTTP polling mode.
	maxSubscriptionReconnectAttempts = 5
	// baseReconnectBackoffDuration is the base duration for exponential backoff when reconnecting subscriptions.
	baseReconnectBackoffDuration = 1 * time.Second
)

var (
	_          = services.Service(&EvmExecutionAttemptPoller{})
	offrampABI = evmtypes.MustGetABI(offramp.OffRampABI)

	errNilClient = errors.New("client cannot be nil")
	errNilLogger = errors.New("logger cannot be nil")
)

// EvmExecutionAttemptPoller polls for execution state changed events and caches execution attempts.
type EvmExecutionAttemptPoller struct {
	services.StateMachine
	lggr            logger.Logger
	chainSelector   protocol.ChainSelector
	client          client.Client
	startBlock      uint64
	offRampFilterer offramp.OffRampFilterer
	eventCh         chan *offramp.OffRampExecutionStateChanged
	subscription    event.Subscription
	attemptCache    *expirable.LRU[protocol.Bytes32, []protocol.ExecutionAttempt]
	cancelFunc      context.CancelFunc
	runWg           sync.WaitGroup
	pollInterval    time.Duration
	lastPolledBlock uint64
	lookbackWindow  time.Duration
}

func (p *EvmExecutionAttemptPoller) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Healthy()
	return report
}

func (p *EvmExecutionAttemptPoller) Name() string {
	return strings.Join([]string{p.chainSelector.String(), evmExecutionAttemptPollerServiceName}, ".")
}

// NewEVMExecutionAttemptPoller creates a new execution attempt poller for the given offramp address.
// The poller watches for ExecutionStateChanged events and caches execution attempts.
// If WebSocket is not available, it will fall back to HTTP polling.
func NewEVMExecutionAttemptPoller(
	offRampAddress common.Address,
	client client.Client,
	lggr logger.Logger,
	attemptCacheExpiration time.Duration,
) (*EvmExecutionAttemptPoller, error) {
	if client == nil {
		return nil, errNilClient
	}
	if lggr == nil {
		return nil, errNilLogger
	}

	offRampFilterer, err := offramp.NewOffRampFilterer(offRampAddress, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create offramp filterer: %w", err)
	}

	attemptCache := expirable.NewLRU[protocol.Bytes32, []protocol.ExecutionAttempt](0, nil, attemptCacheExpiration)
	return &EvmExecutionAttemptPoller{
		lggr:            lggr,
		client:          client,
		offRampFilterer: *offRampFilterer,
		eventCh:         make(chan *offramp.OffRampExecutionStateChanged),
		attemptCache:    attemptCache,
		lastPolledBlock: 0,
		pollInterval:    defaultPollInterval,
		lookbackWindow:  attemptCacheExpiration, // Use cache expiration as lookback window
	}, nil
}

// Start starts the poller service. It implements the services.Service interface.
// It first tries to use WebSocket subscription, and falls back to HTTP polling if WebSocket is not available.
func (p *EvmExecutionAttemptPoller) Start(ctx context.Context) error {
	return p.StartOnce(evmExecutionAttemptPollerServiceName, func() error {
		// Find the starting block before starting the poller
		if err := p.getStartBlock(ctx, p.lookbackWindow); err != nil {
			return fmt.Errorf("failed to get start block: %w", err)
		}

		runCtx, cancel := context.WithCancel(context.Background())
		p.cancelFunc = cancel

		err := p.startWSMode(runCtx)
		if err != nil {
			// if WS unavailable, we'll poll via HTTP
			p.startHTTPMode(runCtx)
		}

		return nil
	})
}

// blockRange represents a range of blocks to search.
type blockRange struct {
	lower uint64
	upper uint64
}

// getStartBlock finds the block number from the specified duration.
// It efficiently narrows down the search range by going backwards from the latest block
// in chunks of maxFilterBlockRange, then uses binary search within the narrowed range.
func (p *EvmExecutionAttemptPoller) getStartBlock(ctx context.Context, lookbackWindow time.Duration) error {
	targetTime := time.Now().Add(-lookbackWindow)

	latestBlockNum, latestTime, err := p.getLatestBlockInfo(ctx)
	if err != nil {
		return err
	}

	p.lggr.Infow("Finding start block",
		"latestBlock", latestBlockNum,
		"targetTime", targetTime,
		"lookbackWindow", lookbackWindow)

	// Early return if latest block is already older than target
	if latestTime.Before(targetTime) {
		p.lggr.Warnw("Latest block is older than target time, using it as start",
			"latestBlockTime", latestTime,
			"targetTime", targetTime)
		p.startBlock = latestBlockNum
		return nil
	}

	searchRange, err := p.narrowSearchRange(ctx, latestBlockNum, targetTime)
	if err != nil {
		return err
	}

	foundBlock, err := p.binarySearchBlockByTime(ctx, searchRange, targetTime)
	if err != nil {
		return err
	}

	// Verify and set the final start block
	return p.verifyAndSetStartBlock(ctx, foundBlock, targetTime)
}

// getLatestBlockInfo retrieves the latest block number and timestamp.
func (p *EvmExecutionAttemptPoller) getLatestBlockInfo(ctx context.Context) (uint64, time.Time, error) {
	header, err := p.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to get latest block header: %w", err)
	}

	blockNum := header.Number.Uint64()
	blockTime := time.Unix(int64(header.Time), 0) //nolint:gosec // G115: Should be good for 236 years, might want to revisit this then.
	return blockNum, blockTime, nil
}

// narrowSearchRange narrows down the search range by going backwards from the latest block
// in chunks of maxFilterBlockRange until finding a block older than targetTime.
func (p *EvmExecutionAttemptPoller) narrowSearchRange(ctx context.Context, latestBlock uint64, targetTime time.Time) (blockRange, error) {
	currentBlock := latestBlock

	for currentBlock > 0 {
		checkBlock := p.calculateCheckBlock(currentBlock)

		checkTime, err := p.getBlockTime(ctx, checkBlock)
		if err != nil {
			return blockRange{}, fmt.Errorf("failed to get block time for block %d: %w", checkBlock, err)
		}

		if checkTime.Before(targetTime) {
			// Found a block older than target, narrow down between checkBlock and currentBlock
			blockRangeVal := blockRange{lower: checkBlock, upper: currentBlock}
			p.lggr.Debugw("Narrowed search range",
				"lowerBound", blockRangeVal.lower,
				"upperBound", blockRangeVal.upper,
				"rangeSize", blockRangeVal.upper-blockRangeVal.lower)
			return blockRangeVal, nil
		}

		// Reached block 0 and it's still newer than target
		if checkBlock == 0 {
			return blockRange{lower: 0, upper: currentBlock}, nil
		}

		currentBlock = checkBlock
	}

	// fallback: should not reach here, but return safe default
	return blockRange{lower: 0, upper: latestBlock}, nil
}

// calculateCheckBlock calculates the block number to check when going backwards.
// It goes back by maxFilterBlockRange or to block 0, whichever is closer.
func (p *EvmExecutionAttemptPoller) calculateCheckBlock(currentBlock uint64) uint64 {
	if currentBlock > maxFilterBlockRange {
		return currentBlock - maxFilterBlockRange
	}
	return 0
}

// getBlockTime retrieves the timestamp for a given block number.
func (p *EvmExecutionAttemptPoller) getBlockTime(ctx context.Context, blockNum uint64) (time.Time, error) {
	header, err := p.client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNum))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get block header for block %d: %w", blockNum, err)
	}
	return time.Unix(int64(header.Time), 0), nil //nolint:gosec // G115: Should be good for 236 years, might want to revisit this then.
}

// binarySearchBlockByTime performs binary search within the given block range to find
// the block closest to but not exceeding the target time.
func (p *EvmExecutionAttemptPoller) binarySearchBlockByTime(ctx context.Context, blockRangeVal blockRange, targetTime time.Time) (uint64, error) {
	p.lggr.Debugw("Searching for startingBlock within narrowed range",
		"lowerBound", blockRangeVal.lower,
		"upperBound", blockRangeVal.upper,
		"rangeSize", blockRangeVal.upper-blockRangeVal.lower)

	startBlock := blockRangeVal.lower
	endBlock := blockRangeVal.upper

	for startBlock < endBlock {
		midBlock := (startBlock + endBlock) / 2

		midTime, err := p.getBlockTime(ctx, midBlock)
		if err != nil {
			return 0, fmt.Errorf("failed to get block time for block %d: %w", midBlock, err)
		}

		if midTime.Before(targetTime) {
			// Block is before target time, search in the upper half
			startBlock = midBlock + 1
		} else {
			// Block is at or after target time, search in the lower half
			endBlock = midBlock
		}
	}

	if startBlock > 0 {
		foundTime, err := p.getBlockTime(ctx, startBlock)
		if err != nil {
			return 0, fmt.Errorf("failed to get block time for verification: %w", err)
		}
		// If this block's time exceeds targetTime, use the previous block
		if foundTime.After(targetTime) {
			startBlock--
		}
		// If foundTime == targetTime or foundTime < targetTime, startBlock is correct
	}

	return startBlock, nil
}

// verifyAndSetStartBlock verifies the found block and sets it as the start block.
func (p *EvmExecutionAttemptPoller) verifyAndSetStartBlock(ctx context.Context, blockNum uint64, targetTime time.Time) error {
	foundTime, err := p.getBlockTime(ctx, blockNum)
	if err != nil {
		return fmt.Errorf("failed to verify start block %d: %w", blockNum, err)
	}

	p.lggr.Infow("Found start block",
		"startBlock", blockNum,
		"blockTime", foundTime,
		"targetTime", targetTime,
		"timeDifference", time.Since(foundTime))

	p.startBlock = blockNum
	return nil
}

func (p *EvmExecutionAttemptPoller) startHTTPMode(ctx context.Context) {
	p.lggr.Infow("WebSocket subscription not available, falling back to HTTP polling", "startBlock", p.startBlock)
	p.lastPolledBlock = p.startBlock

	p.runWg.Go(func() {
		p.runPolling(ctx)
	})

	p.lggr.Infow("Execution attempt poller started in polling mode")
}

func (p *EvmExecutionAttemptPoller) startWSMode(ctx context.Context) error {
	subscription, err := p.offRampFilterer.WatchExecutionStateChanged(
		&bind.WatchOpts{Start: &p.startBlock, Context: ctx},
		p.eventCh, nil, nil, nil,
	)
	if err != nil {
		return err
	}

	p.subscription = subscription
	p.runWg.Go(func() {
		p.run(ctx)
	})

	p.runWg.Go(func() {
		p.monitorSubscription(ctx)
	})

	p.lggr.Infow("execution attempt poller started in WebSocket mode")
	return nil
}

// Close stops the poller service and cleans up resources. It implements the services.Service interface.
func (p *EvmExecutionAttemptPoller) Close() error {
	return p.StopOnce("evm.executionattemptpoller.Service", func() error {
		p.lggr.Infow("Stopping execution attempt poller")

		// Unsubscribe from events first to stop new events from being sent to the channel
		// (only relevant for WebSocket mode)
		if p.subscription != nil {
			p.subscription.Unsubscribe()
		}

		if p.cancelFunc != nil {
			p.cancelFunc()
		}

		p.runWg.Wait()

		p.lggr.Infow("Execution attempt poller stopped")
		return nil
	})
}

// GetExecutionAttempts retrieves cached execution attempts for the given message.
func (p *EvmExecutionAttemptPoller) GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]protocol.ExecutionAttempt, error) {
	msgID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to get message ID: %w", err)
	}

	attempts, exists := p.attemptCache.Get(msgID)
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modification
	result := make([]protocol.ExecutionAttempt, len(attempts))
	copy(result, attempts)
	return result, nil
}

// run processes execution state changed events and caches execution attempts.
func (p *EvmExecutionAttemptPoller) run(ctx context.Context) {
	for {
		select {
		case execStateChanged, ok := <-p.eventCh:
			if !ok {
				p.lggr.Debugw("Event channel closed, exiting run loop")
				return
			}

			if err := p.processExecutionStateChanged(ctx, execStateChanged); err != nil {
				p.lggr.Warnw("Failed to process execution state changed event, this may be due to invalid callData",
					"error", err,
					"messageID", execStateChanged.MessageId,
					"txHash", execStateChanged.Raw.TxHash)
			}

		case <-ctx.Done():
			p.lggr.Debugw("Context cancelled, exiting run loop")
			return
		}
	}
}

// monitorSubscription monitors the subscription for errors and implements exponential backoff
// to reconnect. If max reconnect attempts are reached, it falls back to HTTP polling mode.
// Only used in WebSocket mode.
func (p *EvmExecutionAttemptPoller) monitorSubscription(ctx context.Context) {
	subscription := p.subscription

	select {
	case err := <-subscription.Err():
		if err == nil {
			p.lggr.Debug("Subscription closed successfully")
			return
		}

		p.lggr.Errorw("Subscription error occurred, will attempt to reconnect", "error", err)
		if err := p.handleReconnection(ctx); err != nil {
			p.lggr.Warn("Unable to reconnect to WS, falling back to HTTP polling")
			p.startHTTPMode(ctx)
			return
		}

		// Handle reconnection starts anothing monitoring session with the new subscription
		return
	case <-ctx.Done():
		p.lggr.Warn("Context cancelled, stopping monitoring subscription")
		return
	}
}

func (p *EvmExecutionAttemptPoller) handleReconnection(ctx context.Context) error {
	reconnectAttempts := 0

	for {
		if reconnectAttempts >= maxSubscriptionReconnectAttempts {
			p.lggr.Warnw("Max subscription reconnect attempts reached, falling back to HTTP polling mode", "maxAttempts", maxSubscriptionReconnectAttempts)
			return errors.New("unable to reconnect, max attempts reached")
		}

		// Attempt to reconnect
		backoffDuration := p.calculateReconnectBackoff(reconnectAttempts)
		p.lggr.Infow("No active subscription, attempting to reconnect", "backoffDuration", backoffDuration, "reconnectAttempt", reconnectAttempts+1)

		select {
		case <-time.After(backoffDuration):
			if err := p.reconnectSubscription(ctx); err != nil {
				p.lggr.Errorw("Failed to reconnect subscription", "error", err, "reconnectAttempt", reconnectAttempts+1)
				reconnectAttempts++
				continue
			}

			p.lggr.Infow("Successfully reconnected subscription", "reconnectAttempt", reconnectAttempts+1)

			// Restart the processing and subscription monitoring
			p.runWg.Go(func() {
				p.run(ctx)
			})
			p.runWg.Go(func() {
				p.monitorSubscription(ctx)
			})
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// calculateReconnectBackoff calculates the exponential backoff duration for reconnection attempts.
// Uses formula: baseDuration * 2^attempt, with a maximum cap to prevent excessive delays.
func (p *EvmExecutionAttemptPoller) calculateReconnectBackoff(attempt int) time.Duration {
	// Exponential backoff: baseDuration * 2^attempt
	backoffDuration := baseReconnectBackoffDuration * time.Duration(1<<attempt)

	// Cap at 30 seconds to prevent excessive delays
	maxBackoff := 30 * time.Second
	if backoffDuration > maxBackoff {
		backoffDuration = maxBackoff
	}

	return backoffDuration
}

// reconnectSubscription attempts to reconnect the WebSocket subscription.
// It safely replaces the old subscription with a new one.
func (p *EvmExecutionAttemptPoller) reconnectSubscription(ctx context.Context) error {
	// Unsubscribe the old subscription if it exists
	if p.subscription != nil {
		p.subscription.Unsubscribe()
		p.subscription = nil
	}

	// Get the current block to resume from where we left off
	// We'll use the last polled block or start block as the starting point
	startBlock := max(p.lastPolledBlock, p.startBlock)

	// Create a new subscription
	subscription, err := p.offRampFilterer.WatchExecutionStateChanged(
		&bind.WatchOpts{Start: &startBlock, Context: ctx},
		p.eventCh, nil, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to reconnect subscription: %w", err)
	}

	p.subscription = subscription
	return nil
}

// runPolling runs the polling loop for HTTP RPC mode.
// It periodically queries for new ExecutionStateChanged events using FilterExecutionStateChanged.
func (p *EvmExecutionAttemptPoller) runPolling(ctx context.Context) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.lggr.Debugw("Context cancelled, exiting polling loop")
			return
		case <-ticker.C:
			if err := p.pollForEvents(ctx); err != nil {
				p.lggr.Warnw("Failed to poll for execution state changed events", "error", err)
			}
		}
	}
}

// pollForEvents queries for ExecutionStateChanged events since the last polled block.
// It handles large ranges by batching queries to respect max filter sizes.
func (p *EvmExecutionAttemptPoller) pollForEvents(ctx context.Context) error {
	fromBlock := p.getLastPolledBlock()

	// Get the latest block number
	header, err := p.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest block header: %w", err)
	}

	toBlock := header.Number.Uint64()

	// If we're already at the latest block, nothing to do
	if toBlock <= fromBlock {
		return nil
	}

	// Process the range in batches if it exceeds maxFilterBlockRange
	currentFrom := fromBlock + 1
	totalEventCount := 0

	for currentFrom <= toBlock {
		// Calculate the end block for this batch
		batchEnd := min(currentFrom+maxFilterBlockRange-1, toBlock)

		batchEndPtr := batchEnd
		p.lggr.Debugw("Querying events in batch",
			"fromBlock", currentFrom,
			"toBlock", batchEnd,
			"batchSize", batchEnd-currentFrom+1)

		// Query for events in this batch
		filter, err := p.offRampFilterer.FilterExecutionStateChanged(&bind.FilterOpts{
			Start:   currentFrom,
			End:     &batchEndPtr,
			Context: ctx,
		}, nil, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to create filter for execution state changed events [%d, %d]: %w",
				currentFrom, batchEnd, err)
		}

		var batchEventCount int
		for filter.Next() {
			event := filter.Event
			batchEventCount++
			totalEventCount++

			// Process the event (same as WebSocket mode)
			if err := p.processExecutionStateChanged(ctx, event); err != nil {
				p.lggr.Warnw("Failed to process execution state changed event from polling",
					"error", err,
					"messageID", event.MessageId,
					"txHash", event.Raw.TxHash,
					"blockNumber", event.Raw.BlockNumber)
				// Continue processing other events even if one fails
			}
		}

		if err := filter.Error(); err != nil {
			_ = filter.Close()
			return fmt.Errorf("filter iteration error for batch [%d, %d]: %w",
				currentFrom, batchEnd, err)
		}

		if err := filter.Close(); err != nil {
			p.lggr.Warnw("Failed to close filter", "error", err)
		}

		if batchEventCount > 0 {
			p.lggr.Debugw("Processed batch events",
				"fromBlock", currentFrom,
				"toBlock", batchEnd,
				"eventCount", batchEventCount)
		}

		// Move to the next batch
		currentFrom = batchEnd + 1
	}

	// Update last polled block regardless of event count
	p.setLastPolledBlock(toBlock)

	if totalEventCount > 0 {
		p.lggr.Debugw("Polled execution state changed events",
			"fromBlock", fromBlock+1,
			"toBlock", toBlock,
			"totalEventCount", totalEventCount)
	}

	return nil
}

func (p *EvmExecutionAttemptPoller) getLastPolledBlock() uint64 {
	return p.lastPolledBlock
}

func (p *EvmExecutionAttemptPoller) setLastPolledBlock(block uint64) {
	p.lastPolledBlock = block
}

// processExecutionStateChanged processes a single execution state changed event.
func (p *EvmExecutionAttemptPoller) processExecutionStateChanged(ctx context.Context, event *offramp.OffRampExecutionStateChanged) error {
	msgID := event.MessageId
	txHash := event.Raw.TxHash

	transaction, err := p.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return fmt.Errorf("failed to get transaction by hash %s: %w", txHash.Hex(), err)
	}

	executionAttempt, err := p.decodeCallDataToExecutionAttempt(transaction.Data(), transaction.Gas())
	if err != nil {
		return fmt.Errorf("failed to decode call data for transaction %s: %w", txHash.Hex(), err)
	}

	// Invairant check: assert that computed messageID matches on-chain event emission.
	attemptMsgID := executionAttempt.Report.Message.MustMessageID()
	if !bytes.Equal(msgID[:], attemptMsgID[:]) {
		p.lggr.Errorw("MessageID from event does not match the computed messageID. This should never happen.", "messageID", msgID, "computedMessageID", attemptMsgID)
		return fmt.Errorf("computed message id does not match event message id")
	}

	// store the execution attempt in cache
	attempts, _ := p.attemptCache.Get(msgID)
	attempts = append(attempts, *executionAttempt)
	p.attemptCache.Add(msgID, attempts)

	p.lggr.Debugw("Cached execution attempt",
		"messageID", msgID,
		"txHash", txHash.Hex(),
		"gasLimit", executionAttempt.TransactionGasLimit)

	return nil
}

// decodeCallDataToExecutionAttempt decodes the transaction call data into an ExecutionAttempt.
// It validates the function selector, unpacks ABI-encoded parameters, and constructs the attempt.
func (p *EvmExecutionAttemptPoller) decodeCallDataToExecutionAttempt(callData []byte, gasLimit uint64) (*protocol.ExecutionAttempt, error) {
	method, ok := offrampABI.Methods[executeMethodName]
	if !ok {
		return nil, fmt.Errorf("execute method not found in offramp ABI")
	}

	if len(callData) < functionSelectorLength {
		return nil, fmt.Errorf("call data too short: expected at least %d bytes for function selector, got %d",
			functionSelectorLength, len(callData))
	}

	callDataSelector := callData[:functionSelectorLength]
	if !bytes.Equal(callDataSelector, method.ID) {
		return nil, fmt.Errorf("call data does not match execute function selector: expected %x, got %x",
			method.ID, callDataSelector)
	}

	// Strip function selector before unpacking (ABI unpack expects only parameters)
	paramsData := callData[functionSelectorLength:]
	values, err := method.Inputs.Unpack(paramsData)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack execute call data: %w", err)
	}

	if len(values) != expectedParamCount {
		return nil, fmt.Errorf("unexpected number of unpacked values: expected %d, got %d",
			expectedParamCount, len(values))
	}

	// Extract and validate parameters with proper type assertions
	encodedMsg, ok := values[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid type for encodedMsg: expected []byte, got %T", values[0])
	}

	contractCcvs, ok := values[1].([]common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid type for contractCcvs: expected []common.Address, got %T", values[1])
	}

	ccvData, ok := values[2].([][]byte)
	if !ok {
		return nil, fmt.Errorf("invalid type for ccvData: expected [][]byte, got %T", values[2])
	}

	// Convert the message bytes into a struct
	message, err := protocol.DecodeMessage(encodedMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message: %w", err)
	}

	// Convert contract addresses to protocol.UnknownAddress
	ccvs := make([]protocol.UnknownAddress, len(contractCcvs))
	for i, addr := range contractCcvs {
		ccvs[i] = protocol.UnknownAddress(addr.Bytes())
	}

	report := protocol.AbstractAggregatedReport{
		CCVS:    ccvs,
		CCVData: ccvData,
		Message: *message,
	}

	return &protocol.ExecutionAttempt{
		Report:              report,
		TransactionGasLimit: new(big.Int).SetUint64(gasLimit),
	}, nil
}
