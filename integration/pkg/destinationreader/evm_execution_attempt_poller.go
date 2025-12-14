package destinationreader

import (
	"bytes"
	"context"
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

var offrampABI = evmtypes.MustGetABI(offramp.OffRampABI)

// evmExecutionAttemptPoller polls for execution state changed events and caches execution attempts.
type evmExecutionAttemptPoller struct {
	services.StateMachine
	lggr            logger.Logger
	client          client.Client
	offRampFilterer offramp.OffRampFilterer
	eventCh         chan *offramp.OffRampExecutionStateChanged
	subscription    event.Subscription
	attemptCache    *expirable.LRU[protocol.Bytes32, []executor.ExecutionAttempt]
	runCtx          context.Context
	runCancel       context.CancelFunc
	runWg           sync.WaitGroup
}

// NewEVMExecutionAttemptPoller creates a new execution attempt poller for the given offramp address.
// The poller watches for ExecutionStateChanged events and caches execution attempts.
func NewEVMExecutionAttemptPoller(
	offRampAddress common.Address,
	client client.Client,
	lggr logger.Logger,
	attemptCacheExpiration time.Duration,
) (*evmExecutionAttemptPoller, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	offRampFilterer, err := offramp.NewOffRampFilterer(offRampAddress, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create offramp filterer: %w", err)
	}

	attemptCache := expirable.NewLRU[protocol.Bytes32, []executor.ExecutionAttempt](0, nil, attemptCacheExpiration)
	return &evmExecutionAttemptPoller{
		lggr:            lggr,
		client:          client,
		offRampFilterer: *offRampFilterer,
		eventCh:         make(chan *offramp.OffRampExecutionStateChanged),
		attemptCache:    attemptCache,
	}, nil
}

// Start starts the poller service. It implements the services.Service interface.
func (ap *evmExecutionAttemptPoller) Start(ctx context.Context) error {
	return ap.StartOnce("evm.executionattemptpoller.Service", func() error {
		subscription, err := ap.offRampFilterer.WatchExecutionStateChanged(&bind.WatchOpts{}, ap.eventCh, nil, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to watch execution state changed events: %w", err)
		}

		ap.subscription = subscription
		ap.runCtx, ap.runCancel = context.WithCancel(context.Background())

		ap.runWg.Go(func() {
			ap.run(ap.runCtx)
		})

		ap.runWg.Go(func() {
			ap.monitorSubscription(ap.runCtx)
		})

		ap.lggr.Infow("Execution attempt poller started")
		return nil
	})
}

// Close stops the poller service and cleans up resources. It implements the services.Service interface.
func (ap *evmExecutionAttemptPoller) Close() error {
	return ap.StopOnce("evm.executionattemptpoller.Service", func() error {
		ap.lggr.Infow("Stopping execution attempt poller")

		// Unsubscribe from events first to stop new events from being sent to the channel
		if ap.subscription != nil {
			ap.subscription.Unsubscribe()
		}

		// Cancel the run context to signal goroutines to stop
		if ap.runCancel != nil {
			ap.runCancel()
		}

		// Wait for goroutines to finish
		ap.runWg.Wait()

		ap.lggr.Infow("Execution attempt poller stopped")
		return nil
	})
}

// run processes execution state changed events and caches execution attempts.
func (ap *evmExecutionAttemptPoller) run(ctx context.Context) {
	for {
		select {
		case execStateChanged, ok := <-ap.eventCh:
			if !ok {
				ap.lggr.Debugw("Event channel closed, exiting run loop")
				return
			}

			if err := ap.processExecutionStateChanged(ctx, execStateChanged); err != nil {
				ap.lggr.Warnw("Failed to process execution state changed event",
					"error", err,
					"messageID", execStateChanged.MessageId,
					"txHash", execStateChanged.Raw.TxHash)
			}

		case <-ctx.Done():
			ap.lggr.Debugw("Context cancelled, exiting run loop")
			return
		}
	}
}

// monitorSubscription monitors the subscription for errors and logs them.
func (ap *evmExecutionAttemptPoller) monitorSubscription(ctx context.Context) {
	for {
		select {
		case err := <-ap.subscription.Err():
			if err != nil {
				ap.lggr.Errorw("Subscription error occurred", "error", err)
			}
			return
		case <-ctx.Done():
			return
		}
	}
}

// processExecutionStateChanged processes a single execution state changed event.
func (ap *evmExecutionAttemptPoller) processExecutionStateChanged(ctx context.Context, event *offramp.OffRampExecutionStateChanged) error {
	msgID := event.MessageId
	txHash := event.Raw.TxHash

	transaction, err := ap.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return fmt.Errorf("failed to get transaction by hash %s: %w", txHash.Hex(), err)
	}

	executionAttempt, err := ap.decodeCallDataToExecutionAttempt(transaction.Data(), transaction.Gas())
	if err != nil {
		return fmt.Errorf("failed to decode call data for transaction %s: %w", txHash.Hex(), err)
	}

	// Store the execution attempt in cache
	attempts, _ := ap.attemptCache.Get(msgID)
	attempts = append(attempts, *executionAttempt)
	ap.attemptCache.Add(msgID, attempts)

	ap.lggr.Debugw("Cached execution attempt",
		"messageID", msgID,
		"txHash", txHash.Hex(),
		"gasLimit", executionAttempt.TransactionGasLimit)

	return nil
}

// decodeCallDataToExecutionAttempt decodes the transaction call data into an ExecutionAttempt.
// It validates the function selector, unpacks ABI-encoded parameters, and constructs the attempt.
func (ap *evmExecutionAttemptPoller) decodeCallDataToExecutionAttempt(callData []byte, gasLimit uint64) (*executor.ExecutionAttempt, error) {
	const (
		functionSelectorLength = 4
		expectedParamCount     = 3
	)

	method, ok := offrampABI.Methods["execute"]
	if !ok {
		return nil, fmt.Errorf("execute method not found in offramp ABI")
	}

	if len(callData) < functionSelectorLength {
		return nil, fmt.Errorf("call data too short: expected at least %d bytes for function selector, got %d",
			functionSelectorLength, len(callData))
	}

	// Verify function selector matches
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

	// Decode the encoded message
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
		TransactionGasLimit: big.NewInt(int64(gasLimit)),
	}, nil
}

// GetExecutionAttempts retrieves cached execution attempts for the given message.
func (ap *evmExecutionAttemptPoller) GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]executor.ExecutionAttempt, error) {
	_ = ctx // context reserved for future use (e.g., cache invalidation)

	msgID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to get message ID: %w", err)
	}

	attempts, exists := ap.attemptCache.Get(msgID)
	if !exists {
		return []executor.ExecutionAttempt{}, nil
	}

	// return a copy to prevent external modification
	result := make([]executor.ExecutionAttempt, len(attempts))
	copy(result, attempts)
	return result, nil
}
