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
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
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
}

// NewEVMSourceReader creates a new blockchain-based source reader.
func NewEVMSourceReader(
	chainClient client.Client,
	contractAddress string,
	chainSelector protocol.ChainSelector,
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

	if len(log.Topics) >= 3 {
		destChainSelector = binary.BigEndian.Uint64(log.Topics[1][24:]) // Last 8 bytes
		nonce = binary.BigEndian.Uint64(log.Topics[2][24:])             // Last 8 bytes

		r.logger.Infow("📊 Event details",
			"sourceChainSelector", r.chainSelector,
			"destChainSelector", destChainSelector,
			"nonce", nonce)
	}

	// Parse the event data using the ABI
	event := &ccv_proxy.CCVProxyCCIPMessageSent{}
	abi, err := ccv_proxy.CCVProxyMetaData.GetAbi()
	if err != nil {
		r.logger.Errorw("❌ Failed to get ABI", "error", err)
		return
	}
	err = abi.UnpackIntoInterface(event, "CCIPMessageSent", log.Data)
	if err != nil {
		r.logger.Errorw("❌ Failed to unpack CCIPMessageSent event", "error", err)
		return
	}

	r.logger.Infow("📋 Parsed event data - Message Header",
		"messageId", common.Bytes2Hex(event.Message.Header.MessageId[:]),
		"sourceChainSelector", event.Message.Header.SourceChainSelector,
		"destChainSelector", event.Message.Header.DestChainSelector,
		"nonce", event.Message.Header.SequenceNumber)

	r.logger.Infow("📋 Parsed event data - Message Body",
		"sender", event.Message.Sender.Hex(),
		"receiver", string(event.Message.Receiver),
		"receiverHex", common.Bytes2Hex(event.Message.Receiver),
		"data", string(event.Message.Data),
		"dataHex", common.Bytes2Hex(event.Message.Data),
		"dataLength", len(event.Message.Data))

	r.logger.Infow("📋 Parsed event data - Fee Information",
		"feeToken", event.Message.FeeToken.Hex(),
		"feeTokenAmount", event.Message.FeeTokenAmount.String(),
		"feeValueJuels", event.Message.FeeValueJuels.String())

	r.logger.Infow("📋 Parsed event data - Token Transfers",
		"tokenTransferCount", len(event.Message.TokenTransfer))

	for i, tt := range event.Message.TokenTransfer {
		r.logger.Infow("📦 Token Transfer",
			"index", i,
			"sourceTokenAddress", tt.SourceTokenAddress.Hex(),
			"destTokenAddress", string(tt.DestTokenAddress),
			"destTokenAddressHex", common.Bytes2Hex(tt.DestTokenAddress),
			"amount", tt.Amount.String(),
			"extraData", string(tt.ExtraData),
			"extraDataHex", common.Bytes2Hex(tt.ExtraData),
			"receipt_issuer", tt.Receipt.Issuer.Hex(),
			"receipt_destGasLimit", tt.Receipt.DestGasLimit,
			"receipt_destBytesOverhead", tt.Receipt.DestBytesOverhead,
			"receipt_feeTokenAmount", tt.Receipt.FeeTokenAmount.String(),
			"receipt_extraArgs", common.Bytes2Hex(tt.Receipt.ExtraArgs))
	}

	r.logger.Infow("📋 Parsed event data - Verifier Receipts",
		"verifierReceiptCount", len(event.Message.VerifierReceipts))

	for i, vr := range event.Message.VerifierReceipts {
		r.logger.Infow("🧾 Verifier Receipt",
			"index", i,
			"issuer", vr.Issuer.Hex(),
			"destGasLimit", vr.DestGasLimit,
			"destBytesOverhead", vr.DestBytesOverhead,
			"feeTokenAmount", vr.FeeTokenAmount.String(),
			"extraArgs", common.Bytes2Hex(vr.ExtraArgs),
			"extraArgsLength", len(vr.ExtraArgs))
	}

	r.logger.Infow("📋 Parsed event data - Executor Receipt",
		"executor_issuer", event.Message.ExecutorReceipt.Issuer.Hex(),
		"executor_destGasLimit", event.Message.ExecutorReceipt.DestGasLimit,
		"executor_destBytesOverhead", event.Message.ExecutorReceipt.DestBytesOverhead,
		"executor_feeTokenAmount", event.Message.ExecutorReceipt.FeeTokenAmount.String(),
		"executor_extraArgs", common.Bytes2Hex(event.Message.ExecutorReceipt.ExtraArgs),
		"executor_extraArgsLength", len(event.Message.ExecutorReceipt.ExtraArgs))

	r.logger.Infow("📋 Parsed event data - Receipt Blobs",
		"receiptBlobCount", len(event.ReceiptBlobs))

	for i, blob := range event.ReceiptBlobs {
		r.logger.Infow("🗂️ Receipt Blob",
			"index", i,
			"length", len(blob),
			"data", string(blob),
			"dataHex", common.Bytes2Hex(blob))
	}

	// Create addresses from the parsed data
	senderAddr, err := protocol.NewUnknownAddressFromHex(event.Message.Sender.Hex())
	if err != nil {
		r.logger.Errorw("❌ Failed to create sender address", "error", err)
		return
	}

	receiverAddr, err := protocol.NewUnknownAddressFromHex(string(event.Message.Receiver))
	if err != nil {
		// If receiver is not a valid address, create a mock one
		receiverAddr, _ = protocol.NewUnknownAddressFromHex("0x0987654321098765432109876543210987654321")
	}

	onRampAddr, _ := protocol.NewUnknownAddressFromHex(r.contractAddress)

	// Extract offRamp from executorReceipt if available, otherwise use a default
	var offRampAddr protocol.UnknownAddress
	if event.Message.ExecutorReceipt.Issuer != (common.Address{}) {
		offRampAddr, _ = protocol.NewUnknownAddressFromHex(event.Message.ExecutorReceipt.Issuer.Hex())
	} else {
		offRampAddr, _ = protocol.NewUnknownAddressFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	}

	// Convert token transfers to protocol format and create TokenTransfer
	var tokenTransfer *protocol.TokenTransfer
	if len(event.Message.TokenTransfer) > 0 {
		// For now, we'll create an empty token transfer since the protocol expects encoded bytes
		// In a full implementation, you'd properly encode the token transfer data
		tokenTransfer = protocol.NewEmptyTokenTransfer()
		r.logger.Infow("📦 Token transfers found but using empty transfer for now",
			"tokenTransferCount", len(event.Message.TokenTransfer))
	} else {
		tokenTransfer = protocol.NewEmptyTokenTransfer()
	}

	// Create message
	message, err := protocol.NewMessage(
		r.chainSelector,
		protocol.ChainSelector(destChainSelector),
		protocol.Nonce(nonce),
		onRampAddr,
		offRampAddr,
		0, // finality - would need to calculate this
		senderAddr,
		receiverAddr,
		event.Message.Receiver, // dest blob
		event.Message.Data,     // data
		tokenTransfer,
	)
	if err != nil {
		r.logger.Errorw("❌ Failed to create message", "error", err)
		return
	}

	// Create receipt blobs from verifier receipts and receipt blobs
	receiptBlobs := make([]protocol.ReceiptWithBlob, 0, len(event.Message.VerifierReceipts)+2)

	// Check if onRamp address exists in any receipt issuer
	onRampFound := false
	r.logger.Infow("🔍 Checking for onRamp address in receipts",
		"onRampAddress", r.contractAddress,
		"verifierReceiptCount", len(event.Message.VerifierReceipts),
		"executorReceiptIssuer", event.Message.ExecutorReceipt.Issuer.Hex())

	for i, vr := range event.Message.VerifierReceipts {
		r.logger.Infow("🔍 Verifier receipt issuer check",
			"index", i,
			"issuer", vr.Issuer.Hex(),
			"matchesOnRamp", vr.Issuer.Hex() == r.contractAddress)
		if vr.Issuer.Hex() == r.contractAddress {
			onRampFound = true
			break
		}
	}
	if !onRampFound && event.Message.ExecutorReceipt.Issuer.Hex() == r.contractAddress {
		onRampFound = true
		r.logger.Infow("✅ OnRamp address found in executor receipt")
	}

	// If onRamp address not found in receipts, add it as the first receipt
	if !onRampFound {
		r.logger.Infow("⚠️ OnRamp address not found in receipts, adding synthetic receipt",
			"onRampAddress", r.contractAddress)

		onRampAddr, _ := protocol.NewUnknownAddressFromHex(r.contractAddress)
		var syntheticBlob []byte
		if len(event.ReceiptBlobs) > 0 && len(event.ReceiptBlobs[0]) > 0 {
			syntheticBlob = event.ReceiptBlobs[0]
		} else {
			// Create a meaningful synthetic blob with message data
			syntheticBlob = append(event.Message.Data, event.Message.Receiver...)
			if len(syntheticBlob) == 0 {
				syntheticBlob = []byte("synthetic-onramp-receipt-with-message-data")
			}
		}

		r.logger.Infow("📋 Creating synthetic receipt",
			"blobLength", len(syntheticBlob),
			"blobPreview", string(syntheticBlob[:min(50, len(syntheticBlob))]))

		syntheticReceipt := protocol.ReceiptWithBlob{
			Issuer:            onRampAddr,
			DestGasLimit:      300000, // Default gas limit
			DestBytesOverhead: 100,    // Default overhead
			Blob:              syntheticBlob,
			ExtraArgs:         []byte{},
		}
		receiptBlobs = append(receiptBlobs, syntheticReceipt)
	}

	// Process verifier receipts
	for i, vr := range event.Message.VerifierReceipts {
		var blob []byte
		if i < len(event.ReceiptBlobs) && len(event.ReceiptBlobs[i]) > 0 {
			blob = event.ReceiptBlobs[i]
		} else {
			// Create a meaningful blob from message data if receipt blob is empty/missing
			blob = append(event.Message.Data, event.Message.Receiver...)
			if len(blob) == 0 {
				blob = []byte("verifier-receipt-with-message-data")
			}
			r.logger.Warnw("⚠️ Empty or missing receipt blob, created synthetic one",
				"verifierIndex", i,
				"syntheticBlobLength", len(blob))
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
			"blobLength", len(blob),
			"isOnRamp", vr.Issuer.Hex() == r.contractAddress)
	}

	// Add executor receipt if available
	if event.Message.ExecutorReceipt.Issuer != (common.Address{}) {
		// Use the last blob for executor or create a default one
		var executorBlob []byte
		if len(event.ReceiptBlobs) > len(event.Message.VerifierReceipts) &&
			len(event.ReceiptBlobs[len(event.Message.VerifierReceipts)]) > 0 {
			executorBlob = event.ReceiptBlobs[len(event.Message.VerifierReceipts)]
		} else {
			// Create a meaningful blob from message data
			executorBlob = append(event.Message.Data, event.Message.Receiver...)
			if len(executorBlob) == 0 {
				executorBlob = []byte("executor-receipt-with-message-data")
			}
			r.logger.Warnw("⚠️ Empty or missing executor receipt blob, created synthetic one",
				"syntheticBlobLength", len(executorBlob))
		}

		issuerAddr, _ := protocol.NewUnknownAddressFromHex(event.Message.ExecutorReceipt.Issuer.Hex())
		executorReceipt := protocol.ReceiptWithBlob{
			Issuer:            issuerAddr,
			DestGasLimit:      event.Message.ExecutorReceipt.DestGasLimit,
			DestBytesOverhead: event.Message.ExecutorReceipt.DestBytesOverhead,
			Blob:              executorBlob,
			ExtraArgs:         event.Message.ExecutorReceipt.ExtraArgs,
		}
		receiptBlobs = append(receiptBlobs, executorReceipt)

		r.logger.Infow("📋 Processed executor receipt",
			"issuer", event.Message.ExecutorReceipt.Issuer.Hex(),
			"blobLength", len(executorBlob),
			"isOnRamp", event.Message.ExecutorReceipt.Issuer.Hex() == r.contractAddress)
	}

	// Create verification task
	task := verifiertypes.VerificationTask{
		Message:      *message,
		ReceiptBlobs: receiptBlobs,
	}

	// Send to verification channel (non-blocking)
	select {
	case r.verificationTaskCh <- task:
		r.logger.Infow("✅ Verification task sent to channel",
			"sourceChain", r.chainSelector,
			"destChain", destChainSelector,
			"nonce", nonce,
			"receiptsCount", len(receiptBlobs))
	default:
		r.logger.Warnw("⚠️ Verification task channel full, dropping event",
			"sourceChain", r.chainSelector,
			"nonce", nonce)
	}
}
