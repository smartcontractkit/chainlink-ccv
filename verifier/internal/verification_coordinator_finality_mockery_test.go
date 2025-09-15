package internal

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// testVerifier keeps track of all processed messages for testing.
type testVerifier struct {
	processedTasks []types.VerificationTask
	mu             sync.RWMutex
}

func newTestVerifier() *testVerifier {
	return &testVerifier{
		processedTasks: make([]types.VerificationTask, 0),
	}
}

func (t *testVerifier) VerifyMessage(
	ctx context.Context,
	verificationTask types.VerificationTask,
	ccvDataCh chan<- protocol.CCVData,
	verificationErrorCh chan<- types.VerificationError,
) {
	t.mu.Lock()
	t.processedTasks = append(t.processedTasks, verificationTask)
	t.mu.Unlock()

	// Create mock CCV data
	messageID, _ := verificationTask.Message.MessageID()
	ccvData := protocol.CCVData{
		MessageID:             messageID,
		SequenceNumber:        verificationTask.Message.SequenceNumber,
		SourceChainSelector:   verificationTask.Message.SourceChainSelector,
		DestChainSelector:     verificationTask.Message.DestChainSelector,
		SourceVerifierAddress: protocol.UnknownAddress{},
		DestVerifierAddress:   protocol.UnknownAddress{},
		CCVData:               []byte("mock-signature"),
		BlobData:              []byte("mock-blob"),
		Timestamp:             time.Now().UnixMicro(),
		Message:               verificationTask.Message,
		ReceiptBlobs:          verificationTask.ReceiptBlobs,
	}

	select {
	case ccvDataCh <- ccvData:
	case <-ctx.Done():
	}
}

func (t *testVerifier) getProcessedTaskCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processedTasks)
}

// testStorage for testing.
type testStorage struct{}

func (m *testStorage) WriteCCVData(ctx context.Context, data []protocol.CCVData) error {
	return nil
}

func TestFinality_MockeryBasic_DefaultFinality(t *testing.T) {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	require.NoError(t, err)

	// Create mock finality-aware source reader
	mockSourceReader := verifier_mocks.NewMockFinalityAwareSourceReader(t)
	mockVerifier := newTestVerifier()
	mockStorage := &testStorage{}

	// Set up mock expectations
	verificationTaskCh := make(chan types.VerificationTask, 10)
	mockSourceReader.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader.EXPECT().VerificationTaskChannel().Return((<-chan types.VerificationTask)(verificationTaskCh))
	mockSourceReader.EXPECT().Stop().Return(nil)

	// Mock blockchain state: latest=1000, finalized=950
	mockSourceReader.EXPECT().LatestBlock(mock.Anything).Return(big.NewInt(1000), nil).Maybe()
	mockSourceReader.EXPECT().LatestFinalizedBlock(mock.Anything).Return(big.NewInt(950), nil).Maybe()

	config := types.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]types.SourceConfig{
			1337: {VerifierAddress: protocol.UnknownAddress([]byte("verifier-1337"))},
		},
		VerifierID: "test-finality-coordinator",
	}

	coordinator, err := NewVerificationCoordinator(
		WithVerifier(mockVerifier),
		WithSourceReaders(map[protocol.ChainSelector]reader.SourceReader{
			1337: mockSourceReader,
		}),
		WithStorage(mockStorage),
		WithConfig(config),
		WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = coordinator.Start(ctx)
	require.NoError(t, err)
	defer coordinator.Stop()

	// Message at block 940 (< finalized 950) should be processed immediately
	finalizedMessage := createTestMessage(t, 1, 1337, 2337)
	finalizedTask := types.VerificationTask{
		Message: finalizedMessage,
		ReceiptBlobs: []protocol.ReceiptWithBlob{{
			Issuer:            protocol.UnknownAddress([]byte("verifier-1337")),
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("test-blob"),
			ExtraArgs:         []byte{}, // Empty = default finality
		}},
		BlockNumber: 940, // 940 <= 950 (finalized), should be processed
	}

	// Send message
	verificationTaskCh <- finalizedTask

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Should have processed the finalized message
	processedCount := mockVerifier.getProcessedTaskCount()
	assert.Equal(t, 1, processedCount, "Should have processed the finalized message")

	// No pending messages
	coordinator.pendingMu.RLock()
	pendingCount := len(coordinator.pendingTasks)
	coordinator.pendingMu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Should have no pending messages")
}

func TestFinality_MockeryBasic_CustomFinality(t *testing.T) {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	require.NoError(t, err)

	// Create mock finality-aware source reader
	mockSourceReader := verifier_mocks.NewMockFinalityAwareSourceReader(t)
	mockVerifier := newTestVerifier()
	mockStorage := &testStorage{}

	// Set up mock expectations
	verificationTaskCh := make(chan types.VerificationTask, 10)
	mockSourceReader.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader.EXPECT().VerificationTaskChannel().Return((<-chan types.VerificationTask)(verificationTaskCh))
	mockSourceReader.EXPECT().Stop().Return(nil)

	// Mock blockchain state: latest=1000, finalized=950
	mockSourceReader.EXPECT().LatestBlock(mock.Anything).Return(big.NewInt(1000), nil).Maybe()
	mockSourceReader.EXPECT().LatestFinalizedBlock(mock.Anything).Return(big.NewInt(950), nil).Maybe()

	config := types.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]types.SourceConfig{
			1337: {VerifierAddress: protocol.UnknownAddress([]byte("verifier-1337"))},
		},
		VerifierID: "test-custom-finality-coordinator",
	}

	coordinator, err := NewVerificationCoordinator(
		WithVerifier(mockVerifier),
		WithSourceReaders(map[protocol.ChainSelector]reader.SourceReader{
			1337: mockSourceReader,
		}),
		WithStorage(mockStorage),
		WithConfig(config),
		WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = coordinator.Start(ctx)
	require.NoError(t, err)
	defer coordinator.Stop()

	// Create EVMExtraArgsV3 with custom finality of 15 blocks
	extraArgs := &protocol.EVMExtraArgsV3{
		RequiredCCV:       []protocol.CCV{},
		OptionalCCV:       []protocol.CCV{},
		Executor:          make(protocol.UnknownAddress, 20),
		ExecutorArgs:      []byte{},
		TokenArgs:         []byte{},
		FinalityConfig:    15, // Custom finality of 15 blocks
		RequiredCCVLen:    0,
		OptionalCCVLen:    0,
		ExecutorArgsLen:   0,
		TokenArgsLen:      0,
		OptionalThreshold: 0,
	}
	extraArgsBytes := extraArgs.ToBytes()

	// Message at block 980 with 15-block finality
	// Required: 980 + 15 = 995 <= 1000 (latest), should be processed
	readyMessage := createTestMessage(t, 1, 1337, 2337)
	readyTask := types.VerificationTask{
		Message: readyMessage,
		ReceiptBlobs: []protocol.ReceiptWithBlob{{
			Issuer:            protocol.UnknownAddress([]byte("verifier-1337")),
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("test-blob"),
			ExtraArgs:         extraArgsBytes,
		}},
		BlockNumber: 980, // 980 + 15 = 995 <= 1000, should be ready
	}

	// Send message
	verificationTaskCh <- readyTask

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Should have processed the ready message
	processedCount := mockVerifier.getProcessedTaskCount()
	assert.Equal(t, 1, processedCount, "Should have processed the ready message")

	// No pending messages
	coordinator.pendingMu.RLock()
	pendingCount := len(coordinator.pendingTasks)
	coordinator.pendingMu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Should have no pending messages")
}

func TestFinality_MockeryBasic_NonFinalityAware(t *testing.T) {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	require.NoError(t, err)

	// Create a regular source reader (not finality-aware)
	mockSourceReader := verifier_mocks.NewMockSourceReader(t)
	mockVerifier := newTestVerifier()
	mockStorage := &testStorage{}

	// Set up mock expectations
	verificationTaskCh := make(chan types.VerificationTask, 10)
	mockSourceReader.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader.EXPECT().VerificationTaskChannel().Return((<-chan types.VerificationTask)(verificationTaskCh))
	mockSourceReader.EXPECT().Stop().Return(nil)

	config := types.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]types.SourceConfig{
			1337: {VerifierAddress: protocol.UnknownAddress([]byte("verifier-1337"))},
		},
		VerifierID: "test-non-finality-coordinator",
	}

	coordinator, err := NewVerificationCoordinator(
		WithVerifier(mockVerifier),
		WithSourceReaders(map[protocol.ChainSelector]reader.SourceReader{
			1337: mockSourceReader,
		}),
		WithStorage(mockStorage),
		WithConfig(config),
		WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = coordinator.Start(ctx)
	require.NoError(t, err)
	defer coordinator.Stop()

	// Send message through non-finality-aware source reader
	message := createTestMessage(t, 1, 1337, 2337)
	task := types.VerificationTask{
		Message: message,
		ReceiptBlobs: []protocol.ReceiptWithBlob{{
			Issuer:            protocol.UnknownAddress([]byte("verifier-1337")),
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("test-blob"),
			ExtraArgs:         []byte{},
		}},
		BlockNumber: 1000,
	}

	verificationTaskCh <- task
	time.Sleep(150 * time.Millisecond)

	// Should be processed immediately (no finality checking)
	assert.Equal(t, 1, mockVerifier.getProcessedTaskCount(), "Message should be processed immediately")

	// No pending messages
	coordinator.pendingMu.RLock()
	pendingCount := len(coordinator.pendingTasks)
	coordinator.pendingMu.RUnlock()
	assert.Equal(t, 0, pendingCount, "No messages should be pending")
}

func createTestMessage(t *testing.T, seqNum protocol.SeqNum, sourceChainSelector, destChainSelector protocol.ChainSelector) protocol.Message {
	tokenTransfer := protocol.NewEmptyTokenTransfer()
	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		seqNum,
		onRampAddr,
		offRampAddr,
		0, // finality
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
	require.NoError(t, err)
	return *message
}
