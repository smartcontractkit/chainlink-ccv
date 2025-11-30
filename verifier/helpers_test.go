package verifier

import (
	"context"
	"encoding/binary"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccv_common "github.com/smartcontractkit/chainlink-ccv/common"
	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
)

// WaitForMessagesInStorage waits for the specified number of messages to be processed.
// Since messages are batched, we can't rely on one notification per message.
// Instead, we poll the storage to check if the expected count has been reached.
func WaitForMessagesInStorage(t *testing.T, storage *common.InMemoryOffchainStorage, count int) {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			require.FailNow(t, "Timeout waiting for messages", "expected %d messages, got %d", count, storage.GetTotalCount())
		case <-ticker.C:
			if storage.GetTotalCount() >= count {
				return
			}
		}
	}
}

func CreateTestMessage(t *testing.T, sequenceNumber protocol.SequenceNumber, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16, gasLimit uint32) protocol.Message {
	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	// Create test CCV and executor addresses for computing the hash
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11 // Use a simple test pattern

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22 // Use a simple test pattern

	// Compute the ccvAndExecutorHash from the test addresses
	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{protocol.UnknownAddress(ccvAddr)},
		protocol.UnknownAddress(executorAddr),
	)
	require.NoError(t, err)

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		sequenceNumber,
		onRampAddr,
		offRampAddr,
		finality,
		gasLimit,
		gasLimit,           // ccipReceiveGasLimit (same as executionGasLimit for tests)
		ccvAndExecutorHash, // ccvAndExecutorHash
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		nil,                 // nil token transfer = 0 length
	)
	require.NoError(t, err)
	return *message
}

// MockSourceReaderSetup contains a mock source Reader and its Channel.
type MockSourceReaderSetup struct {
	Reader  *protocol_mocks.MockSourceReader
	Channel chan protocol.MessageSentEvent
}

// SetupMockSourceReader creates a mock source Reader with expectations.
func SetupMockSourceReader(t *testing.T) *MockSourceReaderSetup {
	mockReader := protocol_mocks.NewMockSourceReader(t)
	channel := make(chan protocol.MessageSentEvent, 10)

	now := time.Now().Unix()

	mockReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(now), nil).Maybe()
	mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).Return(nil, nil).Maybe()

	// Mock GetBlocksHeaders to return proper block headers for the reorg detector
	// The reorg detector builds an initial tail from finalized to latest block
	mockReader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			headers := make(map[*big.Int]protocol.BlockHeader)
			for _, blockNum := range blockNumbers {
				headers[blockNum] = protocol.BlockHeader{
					Number:     blockNum.Uint64(),
					Hash:       protocol.Bytes32{byte(blockNum.Uint64() % 256)},
					ParentHash: protocol.Bytes32{byte((blockNum.Uint64() - 1) % 256)},
					Timestamp:  time.Now(),
				}
			}
			return headers, nil
		},
	).Maybe()

	return &MockSourceReaderSetup{
		Reader:  mockReader,
		Channel: channel,
	}
}

func (msrs *MockSourceReaderSetup) ExpectFetchMessageSentEvent(maybeVerificationTask bool) {
	call := msrs.Reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]protocol.MessageSentEvent, error) {
		var events []protocol.MessageSentEvent
		for {
			select {
			case event := <-msrs.Channel:
				events = append(events, event)
			default:
				return events, nil
			}
		}
	})
	if maybeVerificationTask {
		call.Maybe()
	}
}

// Test constants.
const (
	defaultDestChain = protocol.ChainSelector(100)
)

// noopMonitoring is a simple noop monitoring implementation for tests.
type noopMonitoring struct{}

func (m *noopMonitoring) Metrics() MetricLabeler { return &noopMetricLabeler{} }

type noopMetricLabeler struct{}

func (m *noopMetricLabeler) With(keyValues ...string) MetricLabeler                                 { return m }
func (m *noopMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration)    {}
func (m *noopMetricLabeler) IncrementMessagesProcessed(ctx context.Context)                         {}
func (m *noopMetricLabeler) IncrementMessagesVerificationFailed(ctx context.Context)                {}
func (m *noopMetricLabeler) RecordFinalityWaitDuration(ctx context.Context, duration time.Duration) {}
func (m *noopMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
}
func (m *noopMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {}
func (m *noopMetricLabeler) RecordFinalityQueueSize(ctx context.Context, size int64)                {}
func (m *noopMetricLabeler) RecordCCVDataChannelSize(ctx context.Context, size int64)               {}
func (m *noopMetricLabeler) IncrementStorageWriteErrors(ctx context.Context)                        {}
func (m *noopMetricLabeler) RecordSourceChainLatestBlock(ctx context.Context, blockNum int64)       {}
func (m *noopMetricLabeler) RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64)    {}

type NoopLatencyTracker struct{}

func (n NoopLatencyTracker) MarkMessageAsSeen(*VerificationTask)                                  {}
func (n NoopLatencyTracker) TrackMessageLatencies(context.Context, []protocol.VerifierNodeResult) {}

// TestVerifier keeps track of all processed messages for testing.
type TestVerifier struct {
	processedTasks []VerificationTask
	mu             sync.RWMutex
}

func NewTestVerifier() *TestVerifier {
	return &TestVerifier{
		processedTasks: make([]VerificationTask, 0),
	}
}

func (t *TestVerifier) VerifyMessages(
	_ context.Context,
	tasks []VerificationTask,
	ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult],
) batcher.BatchResult[VerificationError] {
	t.mu.Lock()
	t.processedTasks = append(t.processedTasks, tasks...)
	t.mu.Unlock()

	// Create mock CCV node data for each task
	for _, verificationTask := range tasks {
		messageID, _ := verificationTask.Message.MessageID()

		// Parse receipt structure to extract CCV addresses and executor address
		var ccvAddresses []protocol.UnknownAddress
		var executorAddress protocol.UnknownAddress
		if len(verificationTask.ReceiptBlobs) > 0 {
			// Calculate number of CCV blobs and token transfers from message
			numTokenTransfers := 0
			if verificationTask.Message.TokenTransferLength > 0 {
				numTokenTransfers = 1
			}
			numCCVBlobs := len(verificationTask.ReceiptBlobs) - numTokenTransfers - 1

			receiptStructure, err := protocol.ParseReceiptStructure(
				verificationTask.ReceiptBlobs,
				numCCVBlobs,
				numTokenTransfers,
			)
			if err == nil {
				ccvAddresses = receiptStructure.CCVAddresses
				executorAddress = receiptStructure.ExecutorAddress
			}
		}

		ccvNodeData := protocol.VerifierNodeResult{
			MessageID:       messageID,
			Message:         verificationTask.Message,
			CCVVersion:      []byte("mock-version"),
			CCVAddresses:    ccvAddresses,
			ExecutorAddress: executorAddress,
			Signature:       []byte("mock-signature"),
		}

		if err := ccvDataBatcher.Add(ccvNodeData); err != nil {
			// If context is canceled or batcher is closed, stop processing
			return batcher.BatchResult[VerificationError]{Items: nil, Error: nil}
		}
	}

	// No errors in this test implementation
	return batcher.BatchResult[VerificationError]{Items: nil, Error: nil}
}

func (t *TestVerifier) GetProcessedTaskCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processedTasks)
}

func (t *TestVerifier) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.processedTasks = make([]VerificationTask, 0)
}

func (t *TestVerifier) GetProcessedTasks() []VerificationTask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]VerificationTask(nil), t.processedTasks...)
}

// NoopStorage for testing.
type NoopStorage struct{}

func (m *NoopStorage) WriteCCVNodeData(ctx context.Context, data []protocol.VerifierNodeResult) error {
	return nil
}

func hashFromNumber(n uint64) protocol.Bytes32 {
	var h protocol.Bytes32
	binary.BigEndian.PutUint64(h[:], n)
	return h
}

// createTestMessageSentEvents creates a batch of MessageSentEvent for testing.
func createTestMessageSentEvents(
	t *testing.T,
	startNonce uint64,
	chainSelector, destChain protocol.ChainSelector,
	blockNumbers []uint64,
) []protocol.MessageSentEvent {
	t.Helper()

	// Create test CCV and executor addresses matching those in CreateTestMessage
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11 // Must match CreateTestMessage

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22 // Must match CreateTestMessage

	events := make([]protocol.MessageSentEvent, len(blockNumbers))
	for i, blockNum := range blockNumbers {
		sequenceNumber := startNonce + uint64(i)
		message := CreateTestMessage(t, protocol.SequenceNumber(sequenceNumber), chainSelector, destChain, 0, 300_000)
		messageID, _ := message.MessageID()

		events[i] = protocol.MessageSentEvent{
			DestChainSelector: message.DestChainSelector,
			SequenceNumber:    uint64(message.SequenceNumber),
			MessageID:         messageID,
			Message:           message,
			Receipts: []protocol.ReceiptWithBlob{
				{
					Issuer: protocol.UnknownAddress(ccvAddr),
					Blob:   []byte("receipt1"),
				}, // CCV receipt
				{
					Issuer: protocol.UnknownAddress(executorAddr),
					Blob:   []byte{},
				}, // Executor receipt at the end
			},
			BlockNumber: blockNum,
		}
	}
	return events
}

func newTestSRS(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader *protocol_mocks.MockSourceReader,
	chainStatusMgr protocol.ChainStatusManager,
	curseDetector *ccv_common.MockCurseCheckerService,
	pollInterval time.Duration,
) (*SourceReaderService, *protocol_mocks.MockFinalityViolationChecker) {
	t.Helper()

	lggr := logger.Test(t)

	srs, err := NewSourceReaderService(
		reader,
		chainSelector,
		chainStatusMgr,
		lggr,
		pollInterval,
		curseDetector,
	)
	require.NoError(t, err)

	// Override the internal finalityChecker with a mock.
	mockFC := protocol_mocks.NewMockFinalityViolationChecker(t)
	srs.finalityChecker = mockFC
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	return srs, mockFC
}
