package verifier

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/mocks"
)

// DevSourceReaderSetup contains a mock source reader and its channel for development use
type DevSourceReaderSetup struct {
	Reader  *mocks.MockSourceReader
	Channel chan common.VerificationTask
}

// SetupDevSourceReader creates a mock source reader with an injected channel for development
// This follows the same pattern as the tests but doesn't require testing.T
func SetupDevSourceReader(chainSelector cciptypes.ChainSelector) *DevSourceReaderSetup {
	// Create a mock that doesn't require testing.T by using a nil interface
	mockReader := &mocks.MockSourceReader{}
	channel := make(chan common.VerificationTask, 100)

	// Set up expectations for the mock
	mockReader.On("Start", mock.Anything).Return(nil)
	mockReader.On("VerificationTaskChannel").Return((<-chan common.VerificationTask)(channel))
	mockReader.On("Stop").Run(func(args mock.Arguments) {
		close(channel)
	}).Return(nil)
	mockReader.On("HealthCheck", mock.Anything).Return(nil)

	return &DevSourceReaderSetup{
		Reader:  mockReader,
		Channel: channel,
	}
}

// StartMockMessageGenerator starts generating mock messages for development
// This replaces the heavyweight mock with a simple goroutine
func StartMockMessageGenerator(ctx context.Context, setup *DevSourceReaderSetup, chainSelector cciptypes.ChainSelector, lggr logger.Logger) {
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Generate a message every 10 seconds
		defer ticker.Stop()

		messageCounter := uint64(1)

		for {
			select {
			case <-ctx.Done():
				lggr.Infow("Mock message generation stopped due to context cancellation")
				return
			case <-ticker.C:
				// Generate a mock verification task
				task := createDevVerificationTask(messageCounter, chainSelector)

				select {
				case setup.Channel <- task:
					lggr.Infow("Generated mock verification task",
						"messageID", task.Message.Header.MessageID,
						"sequenceNumber", task.Message.Header.SequenceNumber,
						"sourceChain", task.Message.Header.SourceChainSelector,
						"destChain", task.Message.Header.DestChainSelector,
					)
					messageCounter++
				case <-ctx.Done():
					return
				}
			}
		}
	}()
}

// createDevVerificationTask creates a mock verification task for development
func createDevVerificationTask(counter uint64, chainSelector cciptypes.ChainSelector) common.VerificationTask {
	// Create a mock message ID
	var messageID cciptypes.Bytes32
	copy(messageID[:], fmt.Sprintf("mock-msg-%d-%d", chainSelector, counter))

	// Mock destination chain (different from source)
	destChain := cciptypes.ChainSelector(2337)
	if chainSelector == 2337 {
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
			SourceChainSelector: chainSelector,
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
