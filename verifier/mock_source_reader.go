package verifier

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
)

// MockSourceReader implements SourceReader for development/testing
type MockSourceReader struct {
	chainSelector      cciptypes.ChainSelector
	verificationTaskCh chan common.VerificationTask
	stopCh             chan struct{}
	started            bool
	lggr               logger.Logger
}

// NewMockSourceReader creates a new mock source reader
func NewMockSourceReader(chainSelector cciptypes.ChainSelector, lggr logger.Logger) *MockSourceReader {
	return &MockSourceReader{
		chainSelector:      chainSelector,
		verificationTaskCh: make(chan common.VerificationTask, 100),
		stopCh:             make(chan struct{}),
		lggr:               lggr,
	}
}

// Start begins reading messages and pushing them to the messages channel
func (m *MockSourceReader) Start(ctx context.Context) error {
	if m.started {
		return fmt.Errorf("mock source reader already started")
	}
	m.started = true

	m.lggr.Infow("Starting mock source reader", "chainSelector", m.chainSelector)

	// Start generating mock messages
	go m.generateMockMessages(ctx)

	return nil
}

// Stop stops the reader and closes the messages channel
func (m *MockSourceReader) Stop() error {
	if !m.started {
		return nil
	}

	m.lggr.Infow("Stopping mock source reader", "chainSelector", m.chainSelector)

	close(m.stopCh)
	close(m.verificationTaskCh)
	m.started = false

	return nil
}

// VerificationTaskChannel returns the channel where new message events are delivered
func (m *MockSourceReader) VerificationTaskChannel() <-chan common.VerificationTask {
	return m.verificationTaskCh
}

// HealthCheck returns the current health status of the reader
func (m *MockSourceReader) HealthCheck(ctx context.Context) error {
	if !m.started {
		return fmt.Errorf("mock source reader not started")
	}
	return nil
}

// generateMockMessages generates mock CCIP messages for testing
func (m *MockSourceReader) generateMockMessages(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second) // Generate a message every 10 seconds
	defer ticker.Stop()

	messageCounter := uint64(1)

	for {
		select {
		case <-ctx.Done():
			m.lggr.Infow("Mock message generation stopped due to context cancellation")
			return
		case <-m.stopCh:
			m.lggr.Infow("Mock message generation stopped")
			return
		case <-ticker.C:
			// Generate a mock verification task
			task := m.createMockVerificationTask(messageCounter)

			select {
			case m.verificationTaskCh <- task:
				m.lggr.Debugw("Generated mock verification task",
					"messageID", task.Message.Header.MessageID,
					"sequenceNumber", task.Message.Header.SequenceNumber,
					"sourceChain", task.Message.Header.SourceChainSelector,
					"destChain", task.Message.Header.DestChainSelector,
				)
				messageCounter++
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			}
		}
	}
}

// createMockVerificationTask creates a mock verification task
func (m *MockSourceReader) createMockVerificationTask(counter uint64) common.VerificationTask {
	// Create a mock message ID
	var messageID cciptypes.Bytes32
	copy(messageID[:], fmt.Sprintf("mock-msg-%d", counter))

	// Mock destination chain (different from source)
	destChain := cciptypes.ChainSelector(2337)
	if m.chainSelector == 2337 {
		destChain = cciptypes.ChainSelector(1337)
	}

	// Create mock sender and receiver addresses
	senderAddr, _ := common.NewUnknownAddressFromHex("0x1234567890123456789012345678901234567890")
	receiverAddr, _ := common.NewUnknownAddressFromHex("0x0987654321098765432109876543210987654321")
	onRampAddr, _ := common.NewUnknownAddressFromHex("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
	feeTokenAddr, _ := common.NewUnknownAddressFromHex("0x0000000000000000000000000000000000000000") // Native token

	message := common.Any2AnyVerifierMessage{
		Header: common.MessageHeader{
			MessageID:           messageID,
			SourceChainSelector: m.chainSelector,
			DestChainSelector:   destChain,
			SequenceNumber:      cciptypes.SeqNum(counter),
		},
		Sender:           senderAddr,
		OnRampAddress:    onRampAddr,
		Data:             []byte(fmt.Sprintf("mock-data-%d", counter)),
		Receiver:         receiverAddr,
		FeeToken:         feeTokenAddr,
		FeeTokenAmount:   big.NewInt(1000000),                         // 1 token
		FeeValueJuels:    big.NewInt(2000000),                         // 2 LINK
		TokenTransfer:    common.TokenTransfer{Amount: big.NewInt(0)}, // No token transfer
		VerifierReceipts: []common.Receipt{},
		ExecutorReceipt:  nil,
		TokenReceipt:     nil,
		ExtraArgs:        []byte{},
	}

	return common.VerificationTask{
		Message:      message,
		ReceiptBlobs: [][]byte{}, // No receipt blobs for mock
	}
}
