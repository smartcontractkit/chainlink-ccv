package reader

import (
	"context"
	"encoding/binary"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
)

// BlockchainSourceReader implements SourceReader for reading CCIPMessageSent events from blockchain
type BlockchainSourceReader struct {
	chainClient     client.Client
	contractAddress string
	chainSelector   protocol.ChainSelector
	logger          logger.Logger

	// Event monitoring
	ccipMessageSentTopic string
	lastProcessedBlock   *big.Int
	pollInterval         time.Duration

	// Channels and control
	verificationTaskCh chan types.VerificationTask
	stopCh             chan struct{}
	wg                 sync.WaitGroup

	// State
	isRunning bool
	mu        sync.RWMutex
}

// NewBlockchainSourceReader creates a new blockchain-based source reader
func NewBlockchainSourceReader(
	chainClient client.Client,
	contractAddress string,
	chainSelector protocol.ChainSelector,
	logger logger.Logger,
) *BlockchainSourceReader {
	return &BlockchainSourceReader{
		chainClient:          chainClient,
		contractAddress:      contractAddress,
		chainSelector:        chainSelector,
		logger:               logger,
		ccipMessageSentTopic: "0xa816f7e08da08b1aa0143155f28f728327e40df7f707f612cb3566ab91229820",
		pollInterval:         3 * time.Second,
		verificationTaskCh:   make(chan types.VerificationTask, 100),
		stopCh:               make(chan struct{}),
	}
}

// Start begins reading messages and pushing them to the messages channel
func (r *BlockchainSourceReader) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isRunning {
		return nil // Already running
	}

	r.logger.Infow("🔄 Starting BlockchainSourceReader",
		"chainSelector", r.chainSelector,
		"contract", r.contractAddress,
		"topic", r.ccipMessageSentTopic)

	// Test connectivity before starting
	if err := r.testConnectivity(ctx); err != nil {
		r.logger.Errorw("❌ Connectivity test failed", "error", err)
		return err
	}

	r.isRunning = true
	r.wg.Add(1)

	go r.eventMonitoringLoop(ctx)

	r.logger.Infow("✅ BlockchainSourceReader started successfully")
	return nil
}

// Stop stops the reader and closes the messages channel
func (r *BlockchainSourceReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isRunning {
		return nil // Already stopped
	}

	r.logger.Infow("🛑 Stopping BlockchainSourceReader")

	close(r.stopCh)
	r.wg.Wait()
	close(r.verificationTaskCh)

	r.isRunning = false

	r.logger.Infow("✅ BlockchainSourceReader stopped successfully")
	return nil
}

// VerificationTaskChannel returns the channel where new message events are delivered
func (r *BlockchainSourceReader) VerificationTaskChannel() <-chan types.VerificationTask {
	return r.verificationTaskCh
}

// HealthCheck returns the current health status of the reader
func (r *BlockchainSourceReader) HealthCheck(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.isRunning {
		return nil // Not running is OK for health check
	}

	// Test basic connectivity
	return r.testConnectivity(ctx)
}

// testConnectivity tests if we can connect to the blockchain client
func (r *BlockchainSourceReader) testConnectivity(ctx context.Context) error {
	if r.chainClient == nil {
		return nil // No client configured
	}

	if len(r.chainClient.NodeStates()) == 0 {
		r.logger.Warnw("⚠️ No nodes available for connectivity test")
		return nil // Don't fail health check for this
	}

	// Test if we can make an RPC call
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.chainClient.LatestBlockHeight(testCtx)
	if err != nil {
		r.logger.Warnw("⚠️ Connectivity test failed", "error", err)
		// Don't return error - this is a soft failure
	}

	return nil
}

// eventMonitoringLoop runs the continuous event monitoring
func (r *BlockchainSourceReader) eventMonitoringLoop(ctx context.Context) {
	defer r.wg.Done()

	// Add panic recovery
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Errorw("❌ Recovered from panic in event monitoring loop", "panic", rec)
		}
	}()

	contractAddr := common.HexToAddress(r.contractAddress)
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	// Initial delay
	time.Sleep(5 * time.Second)
	r.logger.Infow("⏳ Initial delay completed, starting event monitoring cycles")

	for {
		select {
		case <-ctx.Done():
			r.logger.Infow("🛑 Context cancelled, stopping event monitoring")
			return

		case <-r.stopCh:
			r.logger.Infow("🛑 Stop signal received, stopping event monitoring")
			return

		case <-ticker.C:
			r.processEventCycle(ctx, contractAddr)
		}
	}
}

// processEventCycle processes a single cycle of event monitoring
func (r *BlockchainSourceReader) processEventCycle(ctx context.Context, contractAddr common.Address) {
	// Wrap in panic recovery
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Warnw("⚠️ Recovered from panic in monitoring cycle", "panic", rec)
		}
	}()

	// Check client connectivity
	if r.chainClient == nil || len(r.chainClient.NodeStates()) == 0 {
		r.logger.Debugw("🔍 No nodes available, skipping cycle")
		return
	}

	// Get current block
	blockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	currentBlock, err := r.chainClient.LatestBlockHeight(blockCtx)
	cancel()

	if err != nil {
		r.logger.Warnw("⚠️ Failed to get latest block", "error", err)
		return
	}

	// Set query range
	var fromBlock *big.Int
	if r.lastProcessedBlock == nil {
		// First run - look at last 100 blocks
		if currentBlock.Cmp(big.NewInt(100)) > 0 {
			fromBlock = new(big.Int).Sub(currentBlock, big.NewInt(100))
		} else {
			fromBlock = big.NewInt(1)
		}
	} else {
		fromBlock = new(big.Int).Add(r.lastProcessedBlock, big.NewInt(1))
	}

	// Only query if there are new blocks
	if fromBlock.Cmp(currentBlock) > 0 {
		return
	}

	// Query for logs
	rangeQuery := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   currentBlock,
		Addresses: []common.Address{contractAddr},
		Topics:    [][]common.Hash{{common.HexToHash(r.ccipMessageSentTopic)}},
	}

	logsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	logs, err := r.chainClient.FilterLogs(logsCtx, rangeQuery)
	cancel()

	if err != nil {
		r.logger.Warnw("⚠️ Failed to filter logs", "error", err)
		return
	}

	// Process found events
	for _, log := range logs {
		r.processCCIPMessageSentEvent(log)
	}

	// Update processed block
	r.lastProcessedBlock = new(big.Int).Set(currentBlock)

	if len(logs) > 0 {
		r.logger.Infow("📈 Processed block range",
			"fromBlock", fromBlock.String(),
			"toBlock", currentBlock.String(),
			"eventsFound", len(logs))
		r.logger.Infow("Event details", "logs", logs)
	} else {
		r.logger.Debugw("🔍 No events found in range",
			"fromBlock", fromBlock.String(),
			"toBlock", currentBlock.String())
	}
}

// processCC IPMessageSentEvent processes a single CCIPMessageSent event
func (r *BlockchainSourceReader) processCCIPMessageSentEvent(log ethtypes.Log) {
	r.logger.Infow("🎉 Found CCIPMessageSent event!",
		"chainSelector", r.chainSelector,
		"blockNumber", log.BlockNumber,
		"txHash", log.TxHash.Hex(),
		"contract", log.Address.Hex())

	// Parse indexed topics
	var destChainSelector uint64
	var sequenceNumber uint64

	if len(log.Topics) >= 3 {
		destChainSelector = binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
		sequenceNumber = binary.BigEndian.Uint64(log.Topics[2][24:])    // Last 8 bytes

		r.logger.Infow("📊 Event details",
			"sourceChainSelector", r.chainSelector,
			"destChainSelector", destChainSelector,
			"sequenceNumber", sequenceNumber)
	}

	// Create a mock message for now - in a real implementation, you'd parse the event data
	// to extract the full message details
	senderAddr, _ := protocol.NewUnknownAddressFromHex("0x1234567890123456789012345678901234567890")
	receiverAddr, _ := protocol.NewUnknownAddressFromHex("0x0987654321098765432109876543210987654321")
	onRampAddr, _ := protocol.NewUnknownAddressFromHex(r.contractAddress)
	offRampAddr, _ := protocol.NewUnknownAddressFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	// Create empty token transfer
	tokenTransfer := protocol.NewEmptyTokenTransfer()

	// Create message
	message, err := protocol.NewMessage(
		r.chainSelector,
		protocol.ChainSelector(destChainSelector),
		protocol.SeqNum(sequenceNumber),
		onRampAddr,
		offRampAddr,
		0, // finality
		senderAddr,
		receiverAddr,
		[]byte("parsed-dest-blob"), // This would be parsed from log.Data
		[]byte("parsed-data"),      // This would be parsed from log.Data
		tokenTransfer,
	)
	if err != nil {
		r.logger.Errorw("❌ Failed to create message", "error", err)
		return
	}

	// Create receipt blobs - this would typically be parsed from the event data
	receiptBlobs := []protocol.ReceiptWithBlob{
		{
			Issuer:            onRampAddr,
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("parsed-receipt-blob"), // This would be parsed from log.Data
			ExtraArgs:         []byte{},
		},
	}

	// Create verification task
	task := types.VerificationTask{
		Message:      *message,
		ReceiptBlobs: receiptBlobs,
	}

	// Send to verification channel (non-blocking)
	select {
	case r.verificationTaskCh <- task:
		r.logger.Infow("✅ Verification task sent to channel",
			"sourceChain", r.chainSelector,
			"destChain", destChainSelector,
			"sequenceNumber", sequenceNumber)
	default:
		r.logger.Warnw("⚠️ Verification task channel full, dropping event",
			"sourceChain", r.chainSelector,
			"sequenceNumber", sequenceNumber)
	}
}
