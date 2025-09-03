package verifier

import (
	"context"
	"fmt"

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
					messageID, err := task.Message.MessageID()
					if err != nil {
						lggr.Errorw("Failed to compute message ID", "error", err)
						continue
					}
					lggr.Infow("Generated mock verification task",
						"messageID", messageID,
						"sequenceNumber", task.Message.SequenceNumber,
						"sourceChain", task.Message.SourceChainSelector,
						"destChain", task.Message.DestChainSelector,
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

	// Create empty token transfer
	tokenTransfer := common.NewEmptyTokenTransfer()

	offRampAddr, _ := common.NewUnknownAddressFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	message := *common.NewMessage(
		chainSelector,
		destChain,
		cciptypes.SeqNum(counter),
		onRampAddr,
		offRampAddr,
		0, // finality
		senderAddr,
		receiverAddr,
		[]byte(fmt.Sprintf("mock-data-%d", counter)), // dest blob
		[]byte(fmt.Sprintf("mock-data-%d", counter)), // data
		tokenTransfer,
	)

	return common.VerificationTask{
		Message:      message,
		ReceiptBlobs: []common.ReceiptWithBlob{}, // No receipt blobs for mock
	}
}
