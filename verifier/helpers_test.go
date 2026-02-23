package verifier

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	vcommon "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
)

// WaitForMessagesInStorage waits for the specified number of messages to be processed.
// Since messages are batched, we can't rely on one notification per message.
// Instead, we poll the storage to check if the expected count has been reached.
func WaitForMessagesInStorage(t *testing.T, storage *vcommon.InMemoryOffchainStorage, count int) {
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
	Reader  *mocks.MockSourceReader
	Channel chan protocol.MessageSentEvent
}

// SetupMockSourceReader creates a mock source Reader with expectations.
func SetupMockSourceReader(t *testing.T) *MockSourceReaderSetup {
	mockReader := mocks.NewMockSourceReader(t)
	channel := make(chan protocol.MessageSentEvent, 10)

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
func (m *noopMetricLabeler) RecordReorgTrackedSeqNums(ctx context.Context, count int64)             {}
func (m *noopMetricLabeler) SetVerifierFinalityViolated(ctx context.Context, selector protocol.ChainSelector, violated bool) {
}

func (m *noopMetricLabeler) SetRemoteChainCursed(ctx context.Context, localSelector, remoteSelector protocol.ChainSelector, cursed bool) {
}

func (m *noopMetricLabeler) SetLocalChainGlobalCursed(ctx context.Context, localSelector protocol.ChainSelector, globalCurse bool) {
}
func (m *noopMetricLabeler) IncrementHeartbeatsSent(ctx context.Context)                           {}
func (m *noopMetricLabeler) IncrementHeartbeatsFailed(ctx context.Context)                         {}
func (m *noopMetricLabeler) RecordHeartbeatDuration(ctx context.Context, duration time.Duration)   {}
func (m *noopMetricLabeler) SetVerifierHeartbeatTimestamp(ctx context.Context, timestamp int64)    {}
func (m *noopMetricLabeler) SetVerifierHeartbeatSentChainHeads(ctx context.Context, height uint64) {}
func (m *noopMetricLabeler) SetVerifierHeartbeatChainHeads(ctx context.Context, height uint64)     {}
func (m *noopMetricLabeler) SetVerifierHeartbeatScore(ctx context.Context, score float64)          {}
func (m *noopMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context)                    {}
func (m *noopMetricLabeler) IncrementHTTPRequestCounter(ctx context.Context)                       {}
func (m *noopMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context)                    {}
func (m *noopMetricLabeler) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
}

func (m *noopMetricLabeler) RecordStorageQueryDuration(ctx context.Context, method string, duration time.Duration) {
}

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
) []VerificationResult {
	t.mu.Lock()
	t.processedTasks = append(t.processedTasks, tasks...)
	t.mu.Unlock()

	results := make([]VerificationResult, 0, len(tasks))

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
			numCCVBlobs := len(verificationTask.ReceiptBlobs) - numTokenTransfers - 2

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

		results = append(results, VerificationResult{
			Result: &ccvNodeData,
		})
	}

	return results
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

	routerAddr := make([]byte, 20)
	routerAddr[0] = 0x44

	events := make([]protocol.MessageSentEvent, len(blockNumbers))
	for i, blockNum := range blockNumbers {
		sequenceNumber := startNonce + uint64(i)
		message := CreateTestMessage(t, protocol.SequenceNumber(sequenceNumber), chainSelector, destChain, 0, 300_000)
		messageID, _ := message.MessageID()

		events[i] = protocol.MessageSentEvent{
			MessageID: messageID,
			Message:   message,
			Receipts: []protocol.ReceiptWithBlob{
				{
					Issuer: protocol.UnknownAddress(ccvAddr),
					Blob:   []byte("receipt1"),
				}, // CCV receipt
				{
					Issuer: protocol.UnknownAddress(executorAddr),
					Blob:   []byte{},
				}, // Executor receipt
				{
					Issuer: protocol.UnknownAddress(routerAddr),
					Blob:   []byte("router-blob"),
				}, // Network fee receipt
			},
			BlockNumber: blockNum,
		}
	}
	return events
}

type noopFilter struct{}

func (n *noopFilter) Filter(msg protocol.MessageSentEvent) bool {
	return true
}

func newTestSRS(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader *mocks.MockSourceReader,
	chainStatusMgr protocol.ChainStatusManager,
	curseDetector *mocks.MockCurseCheckerService,
	pollInterval time.Duration,
	maxBlockRange uint64,
) (*SourceReaderService, *mocks.MockFinalityViolationChecker) {
	t.Helper()

	lggr := logger.Test(t)

	srs, err := NewSourceReaderService(
		t.Context(),
		reader,
		chainSelector,
		chainStatusMgr,
		lggr,
		SourceConfig{PollInterval: pollInterval, MaxBlockRange: maxBlockRange},
		curseDetector,
		&noopFilter{},
		&noopMetricLabeler{},
		NewPendingWritingTracker(lggr),
	)
	require.NoError(t, err)

	// Override the internal finalityChecker with a mock.
	mockFC := mocks.NewMockFinalityViolationChecker(t)
	srs.finalityChecker = mockFC
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	return srs, mockFC
}

// NewCoordinatorWithFastPolling creates a coordinator with fast polling intervals for testing.
// This is useful for DB-backed tests that need responsive queue processing.
func NewCoordinatorWithFastPolling(
	ctx context.Context,
	lggr logger.Logger,
	verifier Verifier,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
	messageTracker MessageLatencyTracker,
	monitoring Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	heartbeatClient heartbeatclient.HeartbeatSender,
	db *sql.DB,
	pollInterval time.Duration,
) (*Coordinator, error) {
	if db == nil {
		return nil, errors.New("db is required; in-memory implementations are no longer supported")
	}

	// Use the same initialization as NewCoordinator but with custom poll intervals
	lggr = logger.With(lggr, "verifierID", config.VerifierID)

	var err error
	enabledSourceReaders, err := filterOnlyEnabledSourceReaders(ctx, lggr, config, sourceReaders, chainStatusManager)
	if err != nil {
		return nil, fmt.Errorf("failed to filter enabled source readers: %w", err)
	}
	if len(enabledSourceReaders) == 0 {
		return nil, errors.New("no enabled/initialized chain sources, nothing to coordinate")
	}

	curseDetector, err := createCurseDetector(lggr, config, nil, enabledSourceReaders, monitoring.Metrics())
	if err != nil {
		return nil, fmt.Errorf("failed to create curse detector: %w", err)
	}

	writingTracker := NewPendingWritingTracker(lggr)

	dbSRS, taskVerifierProcessor, storageWriterProcessor, durableErr := createDurableProcessorsWithPollInterval(
		ctx, lggr, db, config, verifier, monitoring, enabledSourceReaders, chainStatusManager, curseDetector, messageTracker, storage, writingTracker, pollInterval,
	)
	if durableErr != nil {
		return nil, durableErr
	}

	sourceReaderServices := make(map[protocol.ChainSelector]services.Service)
	for chainSelector, srs := range dbSRS {
		sourceReaderServices[chainSelector] = srs
	}

	var heartbeatReporter *HeartbeatReporter
	if heartbeatClient != nil && config.HeartbeatInterval > 0 {
		allSelectors := make([]protocol.ChainSelector, 0, len(sourceReaders))
		for selector := range sourceReaders {
			allSelectors = append(allSelectors, selector)
		}

		heartbeatReporter, err = NewHeartbeatReporter(
			logger.With(lggr, "component", "HeartbeatReporter"),
			chainStatusManager,
			heartbeatClient,
			allSelectors,
			config.VerifierID,
			config.HeartbeatInterval,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create heartbeat reporter: %w", err)
		}
	}

	return &Coordinator{
		lggr:                   lggr,
		verifierID:             config.VerifierID,
		sourceReaderServices:   sourceReaderServices,
		curseDetector:          curseDetector,
		taskVerifierProcessor:  taskVerifierProcessor,
		storageWriterProcessor: storageWriterProcessor,
		heartbeatReporter:      heartbeatReporter,
	}, nil
}

// createDurableProcessorsWithPollInterval creates durable processors with custom poll intervals for testing.
func createDurableProcessorsWithPollInterval(
	ctx context.Context,
	lggr logger.Logger,
	db *sql.DB,
	config CoordinatorConfig,
	verifier Verifier,
	monitoring Monitoring,
	enabledSourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	chainStatusManager protocol.ChainStatusManager,
	curseDetector common.CurseCheckerService,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	writingTracker *PendingWritingTracker,
	pollInterval time.Duration,
) (map[protocol.ChainSelector]*SourceReaderServiceDB, services.Service, services.Service, error) {
	taskQueue, err := jobqueue.NewPostgresJobQueue[VerificationTask](
		db,
		jobqueue.QueueConfig{
			Name:          "verification_tasks",
			OwnerID:       config.VerifierID,
			RetryDuration: taskQueueRetryDuration,
			LockDuration:  taskQueueLockDuration,
		},
		logger.With(lggr, "component", "task_queue"),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create task queue: %w", err)
	}

	resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
		db,
		jobqueue.QueueConfig{
			Name:          "verification_results",
			OwnerID:       config.VerifierID,
			RetryDuration: resultQueueRetryDuration,
			LockDuration:  resultQueueLockDuration,
		},
		logger.With(lggr, "component", "result_queue"),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create result queue: %w", err)
	}

	sourceReadersDB, err := createSourceReadersDB(
		ctx, lggr, config, chainStatusManager, curseDetector, monitoring, enabledSourceReaders, writingTracker, taskQueue,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create DB source reader services: %w", err)
	}

	taskVerifierProcessor, err := NewTaskVerifierProcessorDBWithPollInterval(
		lggr,
		config.VerifierID,
		verifier,
		monitoring,
		taskQueue,
		resultQueue,
		writingTracker,
		config.StorageBatchSize,
		pollInterval,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create task verifier processor DB: %w", err)
	}

	storageWriterProcessor, err := NewStorageWriterProcessorDBWithPollInterval(
		ctx,
		lggr,
		config.VerifierID,
		messageTracker,
		storage,
		resultQueue,
		config,
		writingTracker,
		chainStatusManager,
		pollInterval,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create storage writer processor DB: %w", err)
	}

	return sourceReadersDB, taskVerifierProcessor, storageWriterProcessor, nil
}
