package destinationreader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
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
	// functionSelectorLength is the length of an Ethereum function selector in bytes.
	functionSelectorLength = 4
	// expectedParamCount is the expected number of parameters for the execute function.
	expectedParamCount = 3
	// executeMethodName is the name of the execute method in the offramp ABI.
	executeMethodName = "execute"
)

var (
	offrampABI = evmtypes.MustGetABI(offramp.OffRampABI)

	errNilClient = errors.New("client cannot be nil")
	errNilLogger = errors.New("logger cannot be nil")
)

// EvmExecutionAttemptPoller polls for execution state changed events and caches execution attempts.
type EvmExecutionAttemptPoller struct {
	services.StateMachine
	lggr            logger.Logger
	client          client.Client
	startBlock      uint64
	offRampFilterer offramp.OffRampFilterer
	eventCh         chan *offramp.OffRampExecutionStateChanged
	subscription    event.Subscription
	attemptCache    *expirable.LRU[protocol.Bytes32, []executor.ExecutionAttempt]
	cancelFunc      context.CancelFunc
	runWg           sync.WaitGroup
	pollInterval    time.Duration
	lastPolledBlock uint64
}

// NewEVMExecutionAttemptPoller creates a new execution attempt poller for the given offramp address.
// The poller watches for ExecutionStateChanged events and caches execution attempts.
// If WebSocket is not available, it will fall back to HTTP polling.
func NewEVMExecutionAttemptPoller(
	offRampAddress common.Address,
	client client.Client,
	lggr logger.Logger,
	startBlock uint64,
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

	attemptCache := expirable.NewLRU[protocol.Bytes32, []executor.ExecutionAttempt](0, nil, attemptCacheExpiration)
	return &EvmExecutionAttemptPoller{
		lggr:            lggr,
		client:          client,
		offRampFilterer: *offRampFilterer,
		eventCh:         make(chan *offramp.OffRampExecutionStateChanged),
		attemptCache:    attemptCache,
		startBlock:      startBlock,
		lastPolledBlock: startBlock,
		pollInterval:    defaultPollInterval,
	}, nil
}

// Start starts the poller service. It implements the services.Service interface.
// It first tries to use WebSocket subscription, and falls back to HTTP polling if WebSocket is not available.
func (p *EvmExecutionAttemptPoller) Start(ctx context.Context) error {
	return p.StartOnce("evm.executionattemptpoller.Service", func() error {
		runCtx, cancel := context.WithCancel(context.Background())
		p.cancelFunc = cancel

		err := p.startWSMode(runCtx)
		if err != nil {
			// if WS unavailable, we'll poll via HTTP
			return p.startHTTPMode(runCtx)
		}

		return nil
	})
}

func (p *EvmExecutionAttemptPoller) Stop() error {
	return p.StopOnce("evm.executionattemptpoller.Service", func() error {
		p.lggr.Info("Stopping EVM Execution Attempt Poller")
		p.cancelFunc()
		p.runWg.Wait()
		p.lggr.Info("Stopped EVM Execution Attempt Poller")
		return nil
	})
}

func (p *EvmExecutionAttemptPoller) startHTTPMode(ctx context.Context) error {
	p.lggr.Infow("WebSocket subscription not available, falling back to HTTP polling", "startBlock", p.startBlock)
	p.lastPolledBlock = p.startBlock

	p.runWg.Go(func() {
		p.runPolling(ctx)
	})

	p.lggr.Infow("Execution attempt poller started in polling mode")
	return nil
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
func (p *EvmExecutionAttemptPoller) GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]executor.ExecutionAttempt, error) {
	msgID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to get message ID: %w", err)
	}

	attempts, exists := p.attemptCache.Get(msgID)
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modification
	result := make([]executor.ExecutionAttempt, len(attempts))
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

// monitorSubscription monitors the subscription for errors and logs them.
// Only used in WebSocket mode.
func (p *EvmExecutionAttemptPoller) monitorSubscription(ctx context.Context) {
	for {
		select {
		case err := <-p.subscription.Err():
			if err != nil {
				p.lggr.Errorw("Subscription error occurred", "error", err)
			}
			return
		case <-ctx.Done():
			return
		}
	}
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

	// Query for events in the block range
	filter, err := p.offRampFilterer.FilterExecutionStateChanged(&bind.FilterOpts{
		Start:   fromBlock + 1, // Start from the next block after last polled
		End:     &toBlock,
		Context: ctx,
	}, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create filter for execution state changed events: %w", err)
	}

	// Close the filter later, always returns nil so ignoring error check
	defer func() { _ = filter.Close() }()

	var eventCount int
	for filter.Next() {
		event := filter.Event
		eventCount++

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
		return fmt.Errorf("filter iteration error: %w", err)
	}

	// Update last polled block regardless of event count
	p.setLastPolledBlock(toBlock)

	if eventCount > 0 {
		p.lggr.Debugw("Polled execution state changed events",
			"fromBlock", fromBlock+1,
			"toBlock", toBlock,
			"eventCount", eventCount)
	}

	return nil
}

// getLastPolledBlock returns the last polled block number in a thread-safe manner.
func (p *EvmExecutionAttemptPoller) getLastPolledBlock() uint64 {
	p.RLock()
	defer p.RUnlock()
	return p.lastPolledBlock
}

// setLastPolledBlock sets the last polled block number in a thread-safe manner.
func (p *EvmExecutionAttemptPoller) setLastPolledBlock(block uint64) {
	p.Lock()
	defer p.Unlock()
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
func (p *EvmExecutionAttemptPoller) decodeCallDataToExecutionAttempt(callData []byte, gasLimit uint64) (*executor.ExecutionAttempt, error) {
	method, ok := offrampABI.Methods[executeMethodName]
	if !ok {
		return nil, fmt.Errorf("execute method not found in offramp ABI")
	}

	if len(callData) < functionSelectorLength {
		return nil, fmt.Errorf("call data too short: expected at least %d bytes for function selector, got %d",
			functionSelectorLength, len(callData))
	}

	callDataSelector := callData[:functionSelectorLength]
	if len(method.ID) != functionSelectorLength || !bytes.Equal(callDataSelector, method.ID) {
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

	report := executor.AbstractAggregatedReport{
		CCVS:    ccvs,
		CCVData: ccvData,
		Message: *message,
	}

	return &executor.ExecutionAttempt{
		Report:              report,
		TransactionGasLimit: new(big.Int).SetUint64(gasLimit),
	}, nil
}
