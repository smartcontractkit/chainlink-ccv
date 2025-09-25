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
	protocol2 "github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier"
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
	chainSelector        protocol2.ChainSelector
	mu                   sync.RWMutex
	isRunning            bool
}

// NewEVMSourceReader creates a new blockchain-based source reader.
func NewEVMSourceReader(
	chainClient client.Client,
	contractAddress string,
	chainSelector protocol2.ChainSelector,
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

// eventMonitoringLoop runs the continuous event monitoring.
func (r *EVMSourceReader) eventMonitoringLoop(ctx context.Context) {
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
	} else if currentBlock.Cmp(big.NewInt(100)) > 0 {
		fromBlock = new(big.Int).Sub(currentBlock, big.NewInt(100))
	} else {
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
	decodedMsg, err := protocol2.DecodeMessage(event.EncodedMessage)
	if err != nil {
		r.logger.Errorw("❌ Failed to decode message", "error", err)
		return
	}
	r.logger.Infow("📋 Decoded message",
		"message", decodedMsg)

	// Create receipt blobs from verifier receipts and receipt blobs
	receiptBlobs := make([]protocol2.ReceiptWithBlob, 0, len(event.VerifierReceipts)+1)

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

		issuerAddr, _ := protocol2.NewUnknownAddressFromHex(vr.Issuer.Hex())
		receiptBlob := protocol2.ReceiptWithBlob{
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
	issuerAddr, _ := protocol2.NewUnknownAddressFromHex(event.ExecutorReceipt.Issuer.Hex())
	executorReceipt := protocol2.ReceiptWithBlob{
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
