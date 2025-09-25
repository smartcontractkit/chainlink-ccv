package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/stretchr/testify/mock"

	protocol2 "github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// DevSourceReaderSetup contains a mock source reader and its channel for development use.
type DevSourceReaderSetup struct {
	Reader  *verifier_mocks.MockSourceReader
	Channel chan verifier.VerificationTask
}

// SetupDevSourceReader creates a mock source reader with an injected channel for development
// This follows the same pattern as the tests but doesn't require testing.T.
func SetupDevSourceReader(chainSelector protocol2.ChainSelector) *DevSourceReaderSetup {
	// Create a mock that doesn't require testing.T by using a nil interface
	mockReader := &verifier_mocks.MockSourceReader{}
	channel := make(chan verifier.VerificationTask, 100)

	// Set up expectations for the mock
	mockReader.On("Start", mock.Anything).Return(nil)
	mockReader.On("VerificationTaskChannel").Return((<-chan verifier.VerificationTask)(channel))
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
func StartMockMessageGenerator(ctx context.Context, setup *DevSourceReaderSetup, chainSelector protocol2.ChainSelector, verifierAddr protocol2.UnknownAddress, lggr logger.Logger) {
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
						"nonce", task.Message.Nonce,
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
func createDevVerificationTask(counter uint64, chainSelector protocol2.ChainSelector, verifierAddr protocol2.UnknownAddress) verifier.VerificationTask {
	// Mock destination chain (different from source)
	destChain := protocol2.ChainSelector(2337)
	if chainSelector == 2337 {
		destChain = protocol2.ChainSelector(1337)
	}

	// Create mock sender and receiver addresses
	senderAddr, _ := protocol2.NewUnknownAddressFromHex("0x1234567890123456789012345678901234567890")
	receiverAddr, _ := protocol2.NewUnknownAddressFromHex("0x0987654321098765432109876543210987654321")
	// Use the provided verifier address as the onramp address
	onRampAddr := verifierAddr

	// Create empty token transfer
	tokenTransfer := protocol2.NewEmptyTokenTransfer()

	offRampAddr, _ := protocol2.NewUnknownAddressFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	message, _ := protocol2.NewMessage(
		chainSelector,
		destChain,
		protocol2.Nonce(counter),
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

	receiptBlobs := []protocol2.ReceiptWithBlob{
		{
			Issuer:            onRampAddr, // The onramp address must be the issuer
			DestGasLimit:      200000,     // Default gas limit for development
			DestBytesOverhead: 50,         // Default bytes overhead for development
			Blob:              counterBytes,
			ExtraArgs:         []byte{},
		},
	}

	return verifier.VerificationTask{
		Message:      *message,
		ReceiptBlobs: receiptBlobs,
	}
}
