package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// DevSourceReaderSetup contains a mock source reader and its channel for development use.
type DevSourceReaderSetup struct {
	Reader  *verifier_mocks.MockSourceReader
	Channel chan types.VerificationTask
}

// SetupDevSourceReader creates a mock source reader with an injected channel for development
// This follows the same pattern as the tests but doesn't require testing.T.
func SetupDevSourceReader(chainSelector protocol.ChainSelector) *DevSourceReaderSetup {
	// Create a mock that doesn't require testing.T by using a nil interface
	mockReader := &verifier_mocks.MockSourceReader{}
	channel := make(chan types.VerificationTask, 100)

	// Set up expectations for the mock
	mockReader.On("Start", mock.Anything).Return(nil)
	mockReader.On("VerificationTaskChannel").Return((<-chan types.VerificationTask)(channel))
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
// This replaces the heavyweight mock with a simple goroutine.
func StartMockMessageGenerator(ctx context.Context, setup *DevSourceReaderSetup, chainSelector protocol.ChainSelector, verifierAddr protocol.UnknownAddress, lggr logger.Logger) {
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
				task := createDevVerificationTask(messageCounter, chainSelector, verifierAddr)

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

// createDevVerificationTask creates a mock verification task for development.
func createDevVerificationTask(counter uint64, chainSelector protocol.ChainSelector, verifierAddr protocol.UnknownAddress) types.VerificationTask {
	// Mock destination chain (different from source)
	destChain := protocol.ChainSelector(2337)
	if chainSelector == 2337 {
		destChain = protocol.ChainSelector(1337)
	}

	// Create mock sender and receiver addresses
	senderAddr, _ := protocol.NewUnknownAddressFromHex("0x1234567890123456789012345678901234567890")
	receiverAddr, _ := protocol.NewUnknownAddressFromHex("0x0987654321098765432109876543210987654321")
	// Use the provided verifier address as the onramp address
	onRampAddr := verifierAddr

	// Create empty token transfer
	tokenTransfer := protocol.NewEmptyTokenTransfer()

	offRampAddr, _ := protocol.NewUnknownAddressFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	message, _ := protocol.NewMessage(
		chainSelector,
		destChain,
		protocol.SeqNum(counter),
		onRampAddr,
		offRampAddr,
		0, // finality
		senderAddr,
		receiverAddr,
		[]byte(fmt.Sprintf("mock-data-%d", counter)), // dest blob
		[]byte(fmt.Sprintf("mock-data-%d", counter)), // data
		tokenTransfer,
	)

	// Create receipt blobs with onramp address as issuer (required for validation)
	// Convert counter to bytes (8 bytes for uint64, big-endian)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	receiptBlobs := []protocol.ReceiptWithBlob{
		{
			Issuer:            onRampAddr, // The onramp address must be the issuer
			DestGasLimit:      200000,     // Default gas limit for development
			DestBytesOverhead: 50,         // Default bytes overhead for development
			Blob:              counterBytes,
			ExtraArgs:         []byte{},
		},
	}

	return types.VerificationTask{
		Message:      *message,
		ReceiptBlobs: receiptBlobs,
	}
}
