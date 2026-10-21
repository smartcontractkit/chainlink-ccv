package destinationreader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

const (
	// defaultPollInterval is the default interval for polling when WebSocket is not available.
	defaultPollInterval = 5 * time.Second
	// stalenessPollIntervals is how many poll intervals without a successful poll Ready
	// tolerates before reporting not-ready; the default staleness threshold.
	stalenessPollIntervals = 50
	// functionSelectorLength is the length of an Ethereum function selector in bytes.
	functionSelectorLength = 4
	// expectedParamCount is the expected number of parameters for the execute function.
	expectedParamCount = 4
	// executeMethodName is the name of the execute method in the offramp ABI.
	executeMethodName = "execute"
	// evmExecutionAttemptPollerServiceName is the name of the service.
	evmExecutionAttemptPollerServiceName = "evm.executionattemptpoller.Service"
	// maxFilterBlockRange is the maximum block range for filter queries to avoid RPC limits.
	// Common Ethereum RPC limits are around 10,000 blocks, using a conservative value here.
	maxFilterBlockRange = 1000
	// maxSubscriptionReconnectAttempts is the maximum number of times to attempt reconnecting the subscription
	// before falling back to HTTP polling mode.
	maxSubscriptionReconnectAttempts = 5
	// baseReconnectBackoffDuration is the base duration for exponential backoff when reconnecting subscriptions.
	baseReconnectBackoffDuration = 1 * time.Second
	// eventKeyLength is the length of a replay-detection key: 32-byte tx hash plus 4-byte log index.
	eventKeyLength = common.HashLength + 4
	// seenEventsMaxEntries bounds the replay-detection set; its TTL matches the attempt cache.
	seenEventsMaxEntries = 10_000
)

var (
	_          = services.Service(&EvmExecutionAttemptPoller{})
	offrampABI = evmtypes.MustGetABI(offramp.OffRampABI)

	errNilClient          = errors.New("client cannot be nil")
	errNilLogger          = errors.New("logger cannot be nil")
	ErrBackfillInProgress = errors.New("execution attempt poller backfill in progress")
)

// EvmExecutionAttemptPoller polls for execution state changed events and caches execution attempts.
type EvmExecutionAttemptPoller struct {
	services.StateMachine
	lggr            logger.Logger
	chainSelector   protocol.ChainSelector
	client          client.Client
	offRampAddress  common.Address
	startBlock      uint64
	offRampFilterer offramp.OffRampFilterer
	eventCh         chan *offramp.OffRampExecutionStateChanged
	// subMu guards subscription, which is read and replaced by reconnect and Close.
	subMu            sync.Mutex
	subscription     event.Subscription
	attemptCache     *expirable.LRU[protocol.Bytes32, []protocol.ExecutionAttempt]
	seenEvents       *expirable.LRU[[eventKeyLength]byte, struct{}]
	cancelFunc       context.CancelFunc
	runWg            sync.WaitGroup
	pollInterval     time.Duration
	reconnectBackoff time.Duration
	lastPolledBlock  atomic.Uint64
	// wsBlockPartial is true when lastPolledBlock was set by a single event rather than a full
	// block scan, so an HTTP fallback replays that block inclusively.
	wsBlockPartial atomic.Bool
	lookbackWindow time.Duration
	// stalenessThreshold is how long HTTP polling may go without a successful poll before
	// Ready fails; defaults to stalenessPollIntervals × pollInterval.
	stalenessThreshold time.Duration
	backfillComplete   atomic.Bool
	fatalErr           atomic.Pointer[error]
	// pollingMode is true in HTTP polling mode; lastSuccessfulPoll (unix ts) drives
	// Ready() staleness there. WS mode has no poll loop, so silence is not anomalous.
	pollingMode        atomic.Bool
	lastSuccessfulPoll atomic.Int64
}

func (p *EvmExecutionAttemptPoller) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Ready()
	return report
}

// Ready returns nil when the poller has completed its initial backfill and is
// fully operational. Returns ErrBackfillInProgress while the backfill is still
// running, or an errNotStarted error if the service hasn't been started.
// In HTTP polling mode it also fails once no poll has succeeded for the
// staleness threshold, so a dead RPC turns the reader not-ready instead of silently stale.
func (p *EvmExecutionAttemptPoller) Ready() error {
	if err := p.StateMachine.Ready(); err != nil {
		return err
	}
	if fatalErr := p.fatalErr.Load(); fatalErr != nil {
		return *fatalErr
	}
	if !p.backfillComplete.Load() {
		return ErrBackfillInProgress
	}
	if last := p.lastSuccessfulPoll.Load(); p.pollingMode.Load() && last > 0 {
		if since := time.Since(time.Unix(last, 0)); since > p.stalenessThreshold {
			return fmt.Errorf("no successful execution-attempt poll for %s", since.Round(time.Second))
		}
	}
	return nil
}

// Healthy returns the recorded fatal error, if any; unlike Ready it stays nil during backfill.
func (p *EvmExecutionAttemptPoller) Healthy() error {
	if err := p.StateMachine.Healthy(); err != nil {
		return err
	}
	if fatalErr := p.fatalErr.Load(); fatalErr != nil {
		return *fatalErr
	}
	return nil
}

func (p *EvmExecutionAttemptPoller) Name() string {
	return strings.Join([]string{p.chainSelector.String(), evmExecutionAttemptPollerServiceName}, ".")
}

// NewEVMExecutionAttemptPoller creates a new execution attempt poller for the given offramp address.
// On startup the poller performs an initial HTTP backfill over the lookback window to populate the
// cache with historical execution attempts, then switches to WebSocket subscription mode for
// ongoing events. If WebSocket is unavailable, HTTP polling continues from the backfill position.
func NewEVMExecutionAttemptPoller(
	offRampAddress common.Address,
	client client.Client,
	lggr logger.Logger,
	attemptCacheExpiration time.Duration,
	stalenessThreshold time.Duration,
) (*EvmExecutionAttemptPoller, error) {
	if client == nil {
		return nil, errNilClient
	}
	if lggr == nil {
		return nil, errNilLogger
	}
	if stalenessThreshold <= 0 {
		stalenessThreshold = stalenessPollIntervals * defaultPollInterval
	}

	offRampFilterer, err := offramp.NewOffRampFilterer(offRampAddress, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create offramp filterer: %w", err)
	}

	attemptCache := expirable.NewLRU[protocol.Bytes32, []protocol.ExecutionAttempt](0, nil, attemptCacheExpiration)
	return &EvmExecutionAttemptPoller{
		lggr:               lggr,
		client:             client,
		offRampAddress:     offRampAddress,
		offRampFilterer:    *offRampFilterer,
		eventCh:            make(chan *offramp.OffRampExecutionStateChanged),
		attemptCache:       attemptCache,
		seenEvents:         expirable.NewLRU[[eventKeyLength]byte, struct{}](seenEventsMaxEntries, nil, attemptCacheExpiration),
		pollInterval:       defaultPollInterval,
		reconnectBackoff:   baseReconnectBackoffDuration,
		stalenessThreshold: stalenessThreshold,
		lookbackWindow:     attemptCacheExpiration, // Use cache expiration as lookback window
	}, nil
}

// Start starts the poller service. It implements the services.Service interface.
// The startup sequence (getStartBlock, backfill, WS/HTTP mode) runs in a background
// goroutine so that Start returns immediately. Use Ready() to check when the backfill
// is complete and the poller is fully operational.
func (p *EvmExecutionAttemptPoller) Start(ctx context.Context) error {
	return p.StartOnce(evmExecutionAttemptPollerServiceName, func() error {
		runCtx, cancel := context.WithCancel(ctx)
		p.cancelFunc = cancel

		p.runWg.Go(func() {
			p.runStartupSequence(runCtx)
		})

		return nil
	})
}

// runStartupSequence performs the full startup: find the start block, backfill
// historical events, then switch to WS or HTTP polling mode. If getStartBlock
// fails the error is stored as a fatal error (surfaced via Healthy and Ready)
// and backfillComplete is never set, so Ready() will continue to return an error.
// Context cancellation (e.g. from Close) is not treated as a fatal error.
func (p *EvmExecutionAttemptPoller) runStartupSequence(ctx context.Context) {
	if err := p.getStartBlock(ctx, p.lookbackWindow); err != nil {
		if ctx.Err() != nil {
			p.lggr.Infow("Startup sequence cancelled", "error", err)
			return
		}
		fatalErr := fmt.Errorf("failed to get start block: %w", err)
		p.lggr.Errorw("Failed to get start block, execution attempt poller permanently failed", "error", fatalErr)
		p.fatalErr.Store(&fatalErr)
		return
	}

	if err := p.runBackfill(ctx); err != nil {
		p.lggr.Errorw("Initial HTTP backfill failed, continuing without complete history", "error", err)
		p.setLastPolledBlock(p.startBlock)
	}

	p.backfillComplete.Store(true)

	if err := p.startWSMode(ctx); err != nil {
		p.startHTTPMode(ctx)
	}
}

// runBackfill performs a one-shot synchronous HTTP poll covering the full lookback window
// (from startBlock to the current latest block). It positions lastPolledBlock just before
// startBlock so that pollForEvents picks up all events in the window.
func (p *EvmExecutionAttemptPoller) runBackfill(ctx context.Context) error {
	p.lggr.Infow("Starting HTTP backfill", "startBlock", p.startBlock, "lookbackWindow", p.lookbackWindow)

	if p.startBlock > 0 {
		p.setLastPolledBlock(p.startBlock - 1)
	}
	// When startBlock == 0, lastPolledBlock stays at 0 so pollForEvents begins from block 1.

	if err := p.pollForEvents(ctx); err != nil {
		return fmt.Errorf("backfill failed: %w", err)
	}

	p.lggr.Infow("HTTP backfill complete", "lastPolledBlock", p.getLastPolledBlock())
	return nil
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
	// lastPolledBlock is already positioned correctly by runBackfill (or its fallback),
	// so HTTP polling continues from where history coverage ended.
	p.lggr.Infow("WebSocket subscription not available, continuing with HTTP polling", "lastPolledBlock", p.getLastPolledBlock())

	p.pollingMode.Store(true)
	p.lastSuccessfulPoll.Store(time.Now().Unix())

	p.runWg.Go(func() {
		p.runPolling(ctx)
	})

	p.lggr.Infow("Execution attempt poller started in HTTP polling mode")
}

func (p *EvmExecutionAttemptPoller) startWSMode(ctx context.Context) error {
	// Use lastPolledBlock as the subscription start so the WS stream begins exactly
	// where the backfill left off, preventing duplicate or missed events.
	startBlock := p.getLastPolledBlock()
	subscription, err := p.offRampFilterer.WatchExecutionStateChanged(
		&bind.WatchOpts{Start: &startBlock, Context: ctx},
		p.eventCh, nil, nil, nil,
	)
	if err != nil {
		return err
	}

	p.subMu.Lock()
	if ctx.Err() != nil {
		p.subMu.Unlock()
		subscription.Unsubscribe()
		return ctx.Err()
	}
	p.subscription = subscription
	p.subMu.Unlock()

	// run is started exactly once here and consumes eventCh for the service lifetime;
	// reconnects restart only monitorSubscription.
	p.runWg.Go(func() {
		p.run(ctx)
	})

	p.runWg.Go(func() {
		p.monitorSubscription(ctx)
	})

	p.lggr.Infow("Execution attempt poller started in WebSocket mode", "startBlock", startBlock)
	return nil
}

// Close stops the poller service and cleans up resources. It implements the services.Service interface.
func (p *EvmExecutionAttemptPoller) Close() error {
	return p.StopOnce("evm.executionattemptpoller.Service", func() error {
		p.lggr.Infow("Stopping execution attempt poller")

		// Cancel first so reconnect backoff exits on ctx before the subscription is closed.
		if p.cancelFunc != nil {
			p.cancelFunc()
		}

		p.subMu.Lock()
		if p.subscription != nil {
			p.subscription.Unsubscribe()
			p.subscription = nil
		}
		p.subMu.Unlock()

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
					protocol.LogKeyMessageID, protocol.Bytes32(execStateChanged.MessageId).String(),
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
	p.subMu.Lock()
	subscription := p.subscription
	p.subMu.Unlock()

	if subscription == nil {
		p.lggr.Debug("No active subscription to monitor")
		return
	}

	select {
	case err := <-subscription.Err():
		if err == nil {
			p.lggr.Debug("Subscription closed successfully")
			return
		}

		p.lggr.Errorw("Subscription error occurred, will attempt to reconnect", "error", err)
		if err := p.handleReconnection(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
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
				if ctx.Err() != nil {
					return nil
				}
				p.lggr.Errorw("Failed to reconnect subscription", "error", err, "reconnectAttempt", reconnectAttempts+1)
				reconnectAttempts++
				continue
			}
			if ctx.Err() != nil {
				return nil
			}

			p.lggr.Infow("Successfully reconnected subscription", "reconnectAttempt", reconnectAttempts+1)

			// run already consumes eventCh for the service lifetime; restart only the monitor.
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
	base := p.reconnectBackoff
	if base <= 0 {
		base = baseReconnectBackoffDuration
	}
	// Exponential backoff: baseDuration * 2^attempt
	backoffDuration := base * time.Duration(1<<attempt)

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
	p.subMu.Lock()
	if p.subscription != nil {
		p.subscription.Unsubscribe()
		p.subscription = nil
	}
	p.subMu.Unlock()

	// Resume from lastPolledBlock; fall back to startBlock only as a safety guard if
	// lastPolledBlock is somehow behind (e.g. WS mode started before backfill completed).
	startBlock := max(p.getLastPolledBlock(), p.startBlock)

	// Create a new subscription
	subscription, err := p.offRampFilterer.WatchExecutionStateChanged(
		&bind.WatchOpts{Start: &startBlock, Context: ctx},
		p.eventCh, nil, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to reconnect subscription: %w", err)
	}

	p.subMu.Lock()
	if ctx.Err() != nil {
		p.subMu.Unlock()
		subscription.Unsubscribe()
		return ctx.Err()
	}
	p.subscription = subscription
	p.subMu.Unlock()
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
			} else {
				p.lastSuccessfulPoll.Store(time.Now().Unix())
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

	// Process the range in batches if it exceeds maxFilterBlockRange.
	// If lastPolledBlock was set by a WebSocket event rather than a full block scan,
	// replay that block inclusively so remaining logs in the block are not skipped.
	currentFrom := fromBlock + 1
	if p.wsBlockPartial.Load() {
		currentFrom = fromBlock
	}

	// If we're already at the latest block, nothing to do
	if toBlock < currentFrom {
		return nil
	}
	startFrom := currentFrom
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
					protocol.LogKeyMessageID, protocol.Bytes32(event.MessageId).String(),
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
			"fromBlock", startFrom,
			"toBlock", toBlock,
			"totalEventCount", totalEventCount)
	}

	return nil
}

func (p *EvmExecutionAttemptPoller) getLastPolledBlock() uint64 {
	return p.lastPolledBlock.Load()
}

func (p *EvmExecutionAttemptPoller) setLastPolledBlock(block uint64) {
	p.lastPolledBlock.Store(block)
	p.wsBlockPartial.Store(false)
}

// advanceLastPolledBlock moves the cursor forward to block; it never moves backward.
// Because a single event does not guarantee the entire block has been consumed,
// wsBlockPartial is set so an HTTP fallback replays that block inclusively.
func (p *EvmExecutionAttemptPoller) advanceLastPolledBlock(block uint64) {
	for {
		current := p.lastPolledBlock.Load()
		if block < current {
			return
		}
		if block == current {
			p.wsBlockPartial.Store(true)
			return
		}
		if p.lastPolledBlock.CompareAndSwap(current, block) {
			p.wsBlockPartial.Store(true)
			return
		}
	}
}

// eventKey identifies an event by transaction hash and log index for replay detection.
func eventKey(event *offramp.OffRampExecutionStateChanged) [eventKeyLength]byte {
	var key [eventKeyLength]byte
	copy(key[:common.HashLength], event.Raw.TxHash.Bytes())
	binary.BigEndian.PutUint32(key[common.HashLength:], uint32(event.Raw.Index)) //nolint:gosec // G115: log index is bounded by logs per block
	return key
}

// processExecutionStateChanged processes a single execution state changed event.
// Events already seen (e.g. replayed by a resubscription) are skipped, and each
// successfully processed event advances lastPolledBlock to its block number.
func (p *EvmExecutionAttemptPoller) processExecutionStateChanged(ctx context.Context, event *offramp.OffRampExecutionStateChanged) error {
	msgID := event.MessageId
	txHash := event.Raw.TxHash

	key := eventKey(event)
	if p.seenEvents.Contains(key) {
		return nil
	}

	transaction, err := p.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return fmt.Errorf("failed to get transaction by hash %s: %w", txHash.Hex(), err)
	}

	txTo := transaction.To()
	if txTo == nil || *txTo != p.offRampAddress {
		return fmt.Errorf("transaction %s destination %v does not match offramp address %s",
			txHash.Hex(), txTo, p.offRampAddress.Hex())
	}

	executionAttempt, err := p.decodeCallDataToExecutionAttempt(transaction)
	if err != nil {
		return fmt.Errorf("failed to decode call data for transaction %s: %w", txHash.Hex(), err)
	}

	// Invairant check: assert that computed messageID matches on-chain event emission.
	attemptMsgID := executionAttempt.Report.Message.MustMessageID()
	if !bytes.Equal(msgID[:], attemptMsgID[:]) {
		p.lggr.Errorw("MessageID from event does not match the computed messageID. This should never happen.", protocol.LogKeyMessageID, protocol.Bytes32(msgID).String(), "computedMessageID", attemptMsgID.String())
		return fmt.Errorf("computed message id does not match event message id")
	}

	executionAttempt.Failed = executor.MessageExecutionState(event.State) == executor.FAILURE
	executionAttempt.FailureData = event.ReturnData

	// store the execution attempt in cache
	attempts, _ := p.attemptCache.Get(msgID)
	attempts = append(attempts, *executionAttempt)
	p.attemptCache.Add(msgID, attempts)

	p.seenEvents.Add(key, struct{}{})
	p.advanceLastPolledBlock(event.Raw.BlockNumber)

	p.lggr.Debugw("Cached execution attempt",
		"messageID", msgID,
		"txHash", txHash.Hex(),
		"gasLimit", executionAttempt.TransactionGasLimit)

	return nil
}

// decodeCallDataToExecutionAttempt decodes the transaction call data into an ExecutionAttempt.
// It validates the function selector, unpacks ABI-encoded parameters, and constructs the attempt.
func (p *EvmExecutionAttemptPoller) decodeCallDataToExecutionAttempt(tx *types.Transaction) (*protocol.ExecutionAttempt, error) {
	callData := tx.Data()

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

	gasLimitOverride, ok := values[3].(uint32)
	if !ok {
		return nil, fmt.Errorf("invalid type for gasLimitOverride: expected uint32, got %T", values[3])
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

	// Intrinsic gas depends on the destination chain fork, so accept only the envelope the executor produces:
	// no access list, no EIP-7702 authorizations, and the canonical ABI encoding of the arguments.
	canonicalArgs, err := method.Inputs.Pack(encodedMsg, contractCcvs, ccvData, gasLimitOverride)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode execute call data for canonical-encoding check: %w", err)
	}
	canonicalCallData := append(append([]byte{}, method.ID...), canonicalArgs...)
	hasNonCanonicalGasEnvelope := len(tx.AccessList()) > 0 ||
		len(tx.SetCodeAuthorizations()) > 0 ||
		!bytes.Equal(callData, canonicalCallData)

	return &protocol.ExecutionAttempt{
		Report:                     report,
		TransactionGasLimit:        new(big.Int).SetUint64(tx.Gas()),
		GasLimitOverride:           new(big.Int).SetUint64(uint64(gasLimitOverride)),
		HasNonCanonicalGasEnvelope: hasNonCanonicalGasEnvelope,
	}, nil
}
