package reader

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier"
)

const (
	// CheckpointBufferBlocks is the number of blocks to lag behind finalized
	// to ensure downstream processing is complete.
	CheckpointBufferBlocks = 20

	// CheckpointInterval is how often to write checkpoints.
	CheckpointInterval = 300 * time.Second

	// StartupLookbackHours when no checkpoint exists.
	StartupLookbackHours = 8

	// CheckpointRetryAttempts on startup.
	CheckpointRetryAttempts = 5
)

// EVMSourceReader implements SourceReader for reading CCIPMessageSent events from blockchain.
type EVMSourceReader struct {
	chainClient          client.Client
	logger               logger.Logger
	lastProcessedBlock   *big.Int
	verificationTaskCh   chan verifiertypes.VerificationTask
	stopCh               chan struct{}
	ccipMessageSentTopic string
	contractAddress      string
	wg                   sync.WaitGroup
	pollInterval         time.Duration
	chainSelector        protocol.ChainSelector
	mu                   sync.RWMutex
	isRunning            bool

	// Checkpoint management
	checkpointManager     protocol.CheckpointManager
	lastCheckpointTime    time.Time
	lastCheckpointedBlock *big.Int
}

// NewEVMSourceReader creates a new blockchain-based source reader.
func NewEVMSourceReader(
	chainClient client.Client,
	contractAddress string,
	chainSelector protocol.ChainSelector,
	checkpointManager protocol.CheckpointManager,
	logger logger.Logger,
) *EVMSourceReader {
	return &EVMSourceReader{
		chainClient:          chainClient,
		logger:               logger,
		verificationTaskCh:   make(chan verifiertypes.VerificationTask, 100),
		stopCh:               make(chan struct{}),
		pollInterval:         3 * time.Second,
		chainSelector:        chainSelector,
		ccipMessageSentTopic: ccv_proxy.CCVProxyCCIPMessageSent{}.Topic().Hex(),
		contractAddress:      contractAddress,
		checkpointManager:    checkpointManager,
	}
}

// Start begins reading messages and pushing them to the messages channel.
func (r *EVMSourceReader) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isRunning {
		return nil // Already running
	}

	r.logger.Infow("🔄 Starting EVMSourceReader",
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

	r.logger.Infow("✅ EVMSourceReader started successfully")
	return nil
}

// Stop stops the reader and closes the messages channel.
func (r *EVMSourceReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isRunning {
		return nil // Already stopped
	}

	r.logger.Infow("🛑 Stopping EVMSourceReader")

	close(r.stopCh)
	r.wg.Wait()
	close(r.verificationTaskCh)

	r.isRunning = false

	r.logger.Infow("✅ EVMSourceReader stopped successfully")
	return nil
}

// VerificationTaskChannel returns the channel where new message events are delivered.
func (r *EVMSourceReader) VerificationTaskChannel() <-chan verifiertypes.VerificationTask {
	return r.verificationTaskCh
}

// HealthCheck returns the current health status of the reader.
func (r *EVMSourceReader) HealthCheck(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.isRunning {
		return nil // Not running is OK for health check
	}

	// Test basic connectivity
	return r.testConnectivity(ctx)
}

// testConnectivity tests if we can connect to the blockchain client.
func (r *EVMSourceReader) testConnectivity(ctx context.Context) error {
	if r.chainClient == nil {
		return nil // No client configured
	}

	if len(r.chainClient.NodeStates()) == 0 {
		r.logger.Warnw("⚠️ No nodes available for connectivity test")
		return fmt.Errorf("no nodes available")
	}

	// Test if we can make an RPC call
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.chainClient.LatestBlockHeight(testCtx)
	if err != nil {
		r.logger.Warnw("⚠️ Connectivity test failed", "error", err)
		return fmt.Errorf("connectivity test failed: %w", err)
	}

	return nil
}

// readCheckpointWithRetries tries to read checkpoint from aggregator with exponential backoff.
func (r *EVMSourceReader) readCheckpointWithRetries(ctx context.Context, maxAttempts int) (*big.Int, error) {
	if r.checkpointManager == nil {
		r.logger.Debugw("No checkpoint manager available for checkpoint reading")
		return nil, nil
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		checkpoint, err := r.checkpointManager.ReadCheckpoint(ctx, r.chainSelector)
		if err == nil {
			return checkpoint, nil
		}

		lastErr = err
		r.logger.Warnw("Failed to read checkpoint",
			"attempt", attempt,
			"maxAttempts", maxAttempts,
			"error", err)

		if attempt < maxAttempts {
			// Exponential backoff: 1s, 2s, 4s
			backoffDuration := time.Duration(1<<(attempt-1)) * time.Second
			r.logger.Debugw("Retrying checkpoint read after backoff", "duration", backoffDuration)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDuration):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("failed to read checkpoint after %d attempts: %w", maxAttempts, lastErr)
}

// calculateBlockFromHoursAgo calculates the block number from the specified hours ago.
func (r *EVMSourceReader) calculateBlockFromHoursAgo(ctx context.Context, lookbackHours uint64) (*big.Int, error) {
	currentBlock, err := r.chainClient.LatestBlockHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current block height: %w", err)
	}

	// Try to sample recent blocks to estimate block time
	sampleSize := int64(2)
	startBlock := new(big.Int).Sub(currentBlock, big.NewInt(sampleSize))
	if startBlock.Sign() < 0 {
		startBlock = big.NewInt(0)
	}

	// Get timestamps for block time calculation
	startHeader, err := r.chainClient.HeaderByNumber(ctx, startBlock)
	if err != nil {
		r.logger.Warnw("Failed to get start header for block time calculation, using fallback", "error", err)
		return r.fallbackBlockEstimate(currentBlock), nil
	}

	currentHeader, err := r.chainClient.HeaderByNumber(ctx, currentBlock)
	if err != nil {
		r.logger.Warnw("Failed to get current header for block time calculation, using fallback", "error", err)
		return r.fallbackBlockEstimate(currentBlock), nil
	}

	// Calculate average block time
	blockDiff := new(big.Int).Sub(currentBlock, startBlock)
	timeDiff := currentHeader.Time - startHeader.Time

	if blockDiff.Sign() > 0 && timeDiff > 0 {
		avgBlockTime := timeDiff / blockDiff.Uint64()
		blocksInLookback := (lookbackHours * 3600) / avgBlockTime
		lookbackBlock := new(big.Int).Sub(currentBlock, new(big.Int).SetUint64(blocksInLookback))

		if lookbackBlock.Sign() < 0 {
			lookbackBlock = big.NewInt(0)
		}

		r.logger.Infow("Calculated lookback",
			"currentBlock", currentBlock.String(),
			"lookbackHours", lookbackHours,
			"avgBlockTime", avgBlockTime,
			"blocksInLookback", blocksInLookback,
			"lookbackBlock", lookbackBlock.String())

		return lookbackBlock, nil
	}

	return r.fallbackBlockEstimate(currentBlock), nil
}

// fallbackBlockEstimate provides a conservative fallback when block time calculation fails.
func (r *EVMSourceReader) fallbackBlockEstimate(currentBlock *big.Int) *big.Int {
	// Conservative fallback: 100 blocks
	lookback := new(big.Int).Sub(currentBlock, big.NewInt(100))
	if lookback.Sign() < 0 {
		return big.NewInt(0)
	}

	r.logger.Infow("Using fallback block estimate",
		"currentBlock", currentBlock.String(),
		"fallbackLookback", lookback.String())

	return lookback
}

// initializeStartBlock determines the starting block for event monitoring.
func (r *EVMSourceReader) initializeStartBlock(ctx context.Context) (*big.Int, error) {
	r.logger.Infow("Initializing start block for event monitoring")

	// Try to read checkpoint with retries
	checkpoint, err := r.readCheckpointWithRetries(ctx, CheckpointRetryAttempts)
	if err != nil {
		r.logger.Warnw("Failed to read checkpoint after retries, falling back to lookback hours window",
			"lookbackHours", StartupLookbackHours,
			"error", err)
	}

	if checkpoint == nil {
		r.logger.Infow("No checkpoint found, calculating from lookback hours ago", "lookbackHours", StartupLookbackHours)
		return r.calculateBlockFromHoursAgo(ctx, StartupLookbackHours)
	}

	// Resume from checkpoint + 1
	startBlock := new(big.Int).Add(checkpoint, big.NewInt(1))
	r.logger.Infow("Resuming from checkpoint",
		"checkpointBlock", checkpoint.String(),
		"startBlock", startBlock.String())

	return startBlock, nil
}

// calculateCheckpointBlock determines the safe checkpoint block (finalized - buffer).
func (r *EVMSourceReader) calculateCheckpointBlock(ctx context.Context) (*big.Int, error) {
	finalized, err := r.LatestFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}

	checkpointBlock := new(big.Int).Sub(finalized, big.NewInt(CheckpointBufferBlocks))

	// Handle early chain scenario
	if checkpointBlock.Sign() <= 0 {
		r.logger.Debugw("Too early to checkpoint",
			"finalized", finalized.String(),
			"buffer", CheckpointBufferBlocks)
		return nil, nil
	}

	// Safety: don't checkpoint beyond what we've read
	if r.lastProcessedBlock != nil && checkpointBlock.Cmp(r.lastProcessedBlock) > 0 {
		checkpointBlock = new(big.Int).Set(r.lastProcessedBlock)
		r.logger.Debugw("Capping checkpoint at last processed block",
			"finalized", finalized.String(),
			"lastProcessed", r.lastProcessedBlock.String(),
			"checkpoint", checkpointBlock.String())
	}

	return checkpointBlock, nil
}

// updateCheckpoint writes a checkpoint if conditions are met.
func (r *EVMSourceReader) updateCheckpoint(ctx context.Context) {
	// Skip if no checkpoint manager
	if r.checkpointManager == nil {
		return
	}

	// Only checkpoint periodically
	if time.Since(r.lastCheckpointTime) < CheckpointInterval {
		return
	}

	// Calculate safe checkpoint block (finalized - buffer)
	checkpointBlock, err := r.calculateCheckpointBlock(ctx)
	if err != nil {
		r.logger.Warnw("Failed to calculate checkpoint block", "error", err)
		return
	}

	if checkpointBlock == nil {
		// Too early to checkpoint (still in buffer zone from genesis)
		r.logger.Debugw("Skipping checkpoint - too early")
		return
	}

	// Don't re-checkpoint the same block
	if r.lastCheckpointedBlock != nil &&
		checkpointBlock.Cmp(r.lastCheckpointedBlock) <= 0 {
		r.logger.Debugw("Skipping checkpoint - no progress",
			"checkpointBlock", checkpointBlock.String(),
			"lastCheckpointed", r.lastCheckpointedBlock.String())
		return
	}

	// Write checkpoint (fire-and-forget, just log errors)
	err = r.checkpointManager.WriteCheckpoint(ctx, r.chainSelector, checkpointBlock)
	if err != nil {
		r.logger.Errorw("Failed to write checkpoint",
			"error", err,
			"block", checkpointBlock.String())
		// Continue processing, don't fail
	} else {
		r.logger.Infow("Checkpoint updated",
			"checkpointBlock", checkpointBlock.String(),
			"currentProcessed", r.lastProcessedBlock.String())
		r.lastCheckpointTime = time.Now()
		r.lastCheckpointedBlock = new(big.Int).Set(checkpointBlock)
	}
}

// eventMonitoringLoop runs the continuous event monitoring.
func (r *EVMSourceReader) eventMonitoringLoop(ctx context.Context) {
	defer r.wg.Done()

	// Add panic recovery
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Errorw("❌ Recovered from panic in event monitoring loop", "panic", rec)
		}
	}()

	// Initialize start block on first run
	if r.lastProcessedBlock == nil {
		startBlock, err := r.initializeStartBlock(ctx)
		if err != nil {
			r.logger.Errorw("Failed to initialize start block", "error", err)
			// Use fallback
			startBlock = big.NewInt(1)
		}
		r.lastProcessedBlock = startBlock
		r.logger.Infow("Initialized start block", "block", startBlock.String())
	}

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
			r.logger.Infow("🛑 Close signal received, stopping event monitoring")
			return

		case <-ticker.C:
			r.processEventCycle(ctx, contractAddr)
		}
	}
}

// processEventCycle processes a single cycle of event monitoring.
func (r *EVMSourceReader) processEventCycle(ctx context.Context, contractAddr common.Address) {
	// Check client connectivity
	if r.chainClient == nil || len(r.chainClient.NodeStates()) == 0 {
		r.logger.Errorw("🔍 No nodes available, skipping cycle")
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
	if r.lastProcessedBlock != nil {
		fromBlock = new(big.Int).Add(r.lastProcessedBlock, big.NewInt(1))
	} else {
		// This should not happen since we initialize lastProcessedBlock in eventMonitoringLoop
		r.logger.Errorw("lastProcessedBlock is nil in processEventCycle - this should not happen")
		fromBlock = big.NewInt(1)
	}

	// Only query if there are new blocks
	if fromBlock.Cmp(currentBlock) > 0 {
		r.logger.Debugw("🔍 No new blocks to process", "fromBlock", fromBlock.String(),
			"currentBlock", currentBlock.String())
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

	// Try to checkpoint if appropriate
	r.updateCheckpoint(ctx)

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

// processCCIPMessageSentEvent processes a single CCIPMessageSent event.
func (r *EVMSourceReader) processCCIPMessageSentEvent(log types.Log) {
	r.logger.Infow("🎉 Found CCIPMessageSent event!",
		"chainSelector", r.chainSelector,
		"blockNumber", log.BlockNumber,
		"txHash", log.TxHash.Hex(),
		"contract", log.Address.Hex())

	// Parse indexed topics
	var destChainSelector uint64
	var nonce uint64
	var messageID [32]byte

	if len(log.Topics) >= 4 {
		destChainSelector = binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
		nonce = binary.BigEndian.Uint64(log.Topics[2][24:])             // Last 8 bytes
		copy(messageID[:], log.Topics[3][:])                            // Full 32 bytes

		r.logger.Infow("📊 Event details",
			"sourceChainSelector", r.chainSelector,
			"destChainSelector", destChainSelector,
			"nonce", nonce,
			"messageId", common.Bytes2Hex(messageID[:]))
	}

	// Parse the event data using the ABI
	event := &ccv_proxy.CCVProxyCCIPMessageSent{}
	event.DestChainSelector = destChainSelector
	event.MessageId = messageID
	event.SequenceNumber = nonce
	abi, err := ccv_proxy.CCVProxyMetaData.GetAbi()
	if err != nil {
		r.logger.Errorw("❌ Failed to get ABI", "error", err)
		return
	}
	err = abi.UnpackIntoInterface(event, "CCIPMessageSent", log.Data)
	if err != nil {
		r.logger.Errorw("❌ Failed to unpack CCIPMessageSent event payload", "error", err)
		return
	}
	// Log the event structure using the fixed bindings
	r.logger.Infow("📋 CCVProxy Event Structure",
		"destChainSelector", event.DestChainSelector,
		"nonce", event.SequenceNumber,
		"messageId", common.Bytes2Hex(event.MessageId[:]),
		"verifierReceiptCount", len(event.VerifierReceipts),
		"receiptBlobCount", len(event.ReceiptBlobs))

	// Log verifier receipts
	for i, vr := range event.VerifierReceipts {
		r.logger.Infow("🧾 Verifier Receipt",
			"index", i,
			"issuer", vr.Issuer.Hex(),
			"destGasLimit", vr.DestGasLimit,
			"destBytesOverhead", vr.DestBytesOverhead,
			"feeTokenAmount", vr.FeeTokenAmount.String(),
			"extraArgs", common.Bytes2Hex(vr.ExtraArgs))
	}

	// Log executor receipt
	r.logger.Infow("📋 Executor Receipt",
		"issuer", event.ExecutorReceipt.Issuer.Hex(),
		"destGasLimit", event.ExecutorReceipt.DestGasLimit,
		"destBytesOverhead", event.ExecutorReceipt.DestBytesOverhead,
		"feeTokenAmount", event.ExecutorReceipt.FeeTokenAmount.String(),
		"extraArgs", common.Bytes2Hex(event.ExecutorReceipt.ExtraArgs))

	r.logger.Infow("📋 Decoding encoded message",
		"encodedMessageLength", len(event.EncodedMessage),
		"messageId", common.Bytes2Hex(event.MessageId[:]))
	decodedMsg, err := protocol.DecodeMessage(event.EncodedMessage)
	if err != nil {
		r.logger.Errorw("❌ Failed to decode message", "error", err)
		return
	}
	r.logger.Infow("📋 Decoded message",
		"message", decodedMsg)

	// Create receipt blobs from verifier receipts and receipt blobs
	receiptBlobs := make([]protocol.ReceiptWithBlob, 0, len(event.VerifierReceipts)+1)

	if len(event.VerifierReceipts) == 0 {
		r.logger.Errorw("❌ No verifier receipts found")
		return
	}
	// Process verifier receipts
	for i, vr := range event.VerifierReceipts {
		var blob []byte
		if i < len(event.ReceiptBlobs) && len(event.ReceiptBlobs[i]) > 0 {
			blob = event.ReceiptBlobs[i]
		} else {
			r.logger.Infow("⚠️ Empty or missing receipt blob",
				"verifierIndex", i,
			)
		}

		issuerAddr, _ := protocol.NewUnknownAddressFromHex(vr.Issuer.Hex())
		receiptBlob := protocol.ReceiptWithBlob{
			Issuer:            issuerAddr,
			DestGasLimit:      vr.DestGasLimit,
			DestBytesOverhead: vr.DestBytesOverhead,
			Blob:              blob,
			ExtraArgs:         vr.ExtraArgs,
		}
		receiptBlobs = append(receiptBlobs, receiptBlob)

		r.logger.Infow("📋 Processed verifier receipt",
			"index", i,
			"issuer", vr.Issuer.Hex(),
			"blobLength", len(blob))
	}

	if event.ExecutorReceipt.Issuer == (common.Address{}) {
		r.logger.Errorw("❌ Empty or missing executor receipt")
		return
	}
	// Add executor receipt if available
	issuerAddr, _ := protocol.NewUnknownAddressFromHex(event.ExecutorReceipt.Issuer.Hex())
	executorReceipt := protocol.ReceiptWithBlob{
		Issuer:            issuerAddr,
		DestGasLimit:      event.ExecutorReceipt.DestGasLimit,
		DestBytesOverhead: event.ExecutorReceipt.DestBytesOverhead,
		Blob:              []byte{},
		ExtraArgs:         event.ExecutorReceipt.ExtraArgs,
	}
	receiptBlobs = append(receiptBlobs, executorReceipt)

	r.logger.Infow("📋 Processed executor receipt",
		"issuer", event.ExecutorReceipt.Issuer.Hex())

	// Create verification task
	task := verifiertypes.VerificationTask{
		Message:      *decodedMsg,
		ReceiptBlobs: receiptBlobs,
		BlockNumber:  log.BlockNumber,
	}

	// Send to verification channel (non-blocking)
	select {
	case r.verificationTaskCh <- task:
		r.logger.Infow("✅ Verification task sent to channel",
			"sourceChain", r.chainSelector,
			"destChain", event.DestChainSelector,
			"nonce", nonce,
			"messageId", common.Bytes2Hex(event.MessageId[:]),
			"receiptsCount", len(receiptBlobs))
	default:
		r.logger.Warnw("⚠️ Verification task channel full, dropping event",
			"sourceChain", r.chainSelector,
			"nonce", nonce)
	}
}

// LatestBlock returns the latest block height from the chain client.
func (r *EVMSourceReader) LatestBlock(ctx context.Context) (*big.Int, error) {
	if r.chainClient == nil {
		return nil, fmt.Errorf("chain client not configured")
	}
	return r.chainClient.LatestBlockHeight(ctx)
}

// LatestFinalizedBlock returns the latest finalized block height from the chain client.
func (r *EVMSourceReader) LatestFinalizedBlock(ctx context.Context) (*big.Int, error) {
	if r.chainClient == nil {
		return nil, fmt.Errorf("chain client not configured")
	}

	// Try to get finalized block using the client's finalized block method
	head, err := r.chainClient.LatestFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized block: %w", err)
	}

	if head == nil {
		return nil, fmt.Errorf("finalized block head is nil")
	}

	return big.NewInt(head.Number), nil
}
