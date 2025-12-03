package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
)

// Test constants.
const (
	defaultDestChain  = protocol.ChainSelector(100)
	sourceChain1      = protocol.ChainSelector(42)
	sourceChain2      = protocol.ChainSelector(84)
	unconfiguredChain = protocol.ChainSelector(999)
)

// Test constants for verifier addresses matching CreateTestMessage.
var (
	// testCCVAddr is the CCV address used in test messages (matches CreateTestMessage).
	testCCVAddr = func() protocol.UnknownAddress {
		addr := make([]byte, 20)
		addr[0] = 0x11
		return protocol.UnknownAddress(addr)
	}()
)

// testSetup contains common test dependencies.
type testSetup struct {
	t                  *testing.T
	ctx                context.Context
	cancel             context.CancelFunc
	logger             logger.Logger
	storage            *common.InMemoryOffchainStorage
	chainStatusManager *protocol_mocks.MockChainStatusManager
	signerAddr         protocol.UnknownAddress
	signer             verifier.MessageSigner
}

const (
	latestBlockHeight    = 1000
	finalizedBlockHeight = 950
)

func mockLatestBlocks(reader *protocol_mocks.MockSourceReader) *protocol_mocks.MockSourceReader {
	latestHeader := &protocol.BlockHeader{
		Number:     latestBlockHeight,
		Hash:       protocol.Bytes32{byte(latestBlockHeight % 256)},
		ParentHash: protocol.Bytes32{byte((latestBlockHeight - 1) % 256)},
		Timestamp:  time.Now(),
	}
	finalizedHeader := &protocol.BlockHeader{
		Number:     finalizedBlockHeight,
		Hash:       protocol.Bytes32{byte(finalizedBlockHeight % 256)},
		ParentHash: protocol.Bytes32{byte((finalizedBlockHeight - 1) % 256)},
		Timestamp:  time.Now(),
	}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latestHeader, finalizedHeader, nil).Maybe()
	return reader
}

// newTestSetup creates common test dependencies.
func newTestSetup(t *testing.T) *testSetup {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	storage := common.NewInMemoryOffchainStorage(lggr)
	signer, addr := createTestSigner(t)
	chainStatusManager := protocol_mocks.NewMockChainStatusManager(t)
	chainStatusManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).Return(nil, nil)
	chainStatusManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).Return(nil).Maybe()

	return &testSetup{
		t:                  t,
		ctx:                ctx,
		cancel:             cancel,
		logger:             lggr,
		storage:            storage,
		chainStatusManager: chainStatusManager,
		signerAddr:         addr,
		signer:             signer,
	}
}

// cleanup should be called in defer.
func (ts *testSetup) cleanup() {
	ts.cancel()
}

// createTestSigner generates a test ECDSA message signer.
func createTestSigner(t *testing.T) (verifier.MessageSigner, protocol.UnknownAddress) {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, addr, err := commit.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)

	return signer, addr
}

// createCoordinatorConfig creates a coordinator config with the given sources.
func createCoordinatorConfig(coordinatorID string, sources map[protocol.ChainSelector]protocol.UnknownAddress) verifier.CoordinatorConfig {
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for chainSelector, address := range sources {
		sourceConfigs[chainSelector] = verifier.SourceConfig{
			VerifierAddress: address,
		}
	}

	return verifier.CoordinatorConfig{
		VerifierID:    coordinatorID,
		SourceConfigs: sourceConfigs,
	}
}

// createVerificationCoordinator creates a verification coordinator with the given setup.
func createVerificationCoordinator(
	ts *testSetup,
	config verifier.CoordinatorConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewFakeVerifierMonitoring()
	noopLatencyTracker := verifier.NoopLatencyTracker{}
	commitVerifier, err := commit.NewCommitVerifier(config, ts.signerAddr, ts.signer, ts.logger, noopMonitoring)
	require.NoError(ts.t, err)

	return verifier.NewCoordinator(
		ts.logger,
		commitVerifier,
		sourceReaders,
		ts.storage,
		config,
		noopLatencyTracker,
		noopMonitoring,
		ts.chainStatusManager,
	)
}

// sendEventsAsync sends message sent events asynchronously with a delay.
func sendEventsAsync(events []protocol.MessageSentEvent, channel chan<- protocol.MessageSentEvent, counter *atomic.Int32, delay time.Duration) {
	go func() {
		for _, event := range events {
			channel <- event
			if counter != nil {
				counter.Add(1)
			}
			time.Sleep(delay)
		}
	}()
}

// verifyStoredTasks is a helper to verify stored data matches expected tasks.
func verifyStoredTasks(t *testing.T, storedData []protocol.VerifierResult, expectedTasks []protocol.MessageSentEvent, expectedChain protocol.ChainSelector) {
	expectedIDs := make(map[[32]byte]bool)
	for _, task := range expectedTasks {
		messageID, err := task.Message.MessageID()
		require.NoError(t, err)
		expectedIDs[messageID] = true
	}
	for _, data := range storedData {
		assert.True(t, expectedIDs[data.MessageID], "Unexpected message ID: %s", data.MessageID.String())
		assert.Equal(t, expectedChain, data.Message.SourceChainSelector)
	}
}

// filterBySourceChain filters CCVData by source chain selector.
func filterBySourceChain(data []protocol.VerifierResult, sourceChain protocol.ChainSelector) []protocol.VerifierResult {
	var filtered []protocol.VerifierResult
	for _, d := range data {
		if d.Message.SourceChainSelector == sourceChain {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

func TestVerifier(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-custom-mockery-verifier", map[protocol.ChainSelector]protocol.UnknownAddress{
		sourceChain1: testCCVAddr,
	})

	// Set up mock source readerService
	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1: mockSetup.Reader,
	}

	// Set up mock head tracker
	mockLatestBlocks(mockSetup.Reader)

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create and send test events
	testEvents := []protocol.MessageSentEvent{
		createTestMessageSentEvent(t, 100, sourceChain1, defaultDestChain, 0, 300_000, 900),
		createTestMessageSentEvent(t, 200, sourceChain1, defaultDestChain, 0, 300_000, 901),
	}

	var messagesSent atomic.Int32
	sendEventsAsync(testEvents, mockSetup.Channel, &messagesSent, 10*time.Millisecond)

	// Wait for processing and verify results
	verifier.WaitForMessagesInStorage(ts.t, ts.storage, len(testEvents))

	err = v.Close()
	require.NoError(t, err)

	// Verify stored data
	storedData, err := ts.storage.GetAllCCVData()
	require.NoError(t, err)
	assert.Len(t, storedData, len(testEvents))
	assert.Equal(t, int(messagesSent.Load()), len(testEvents))

	// Verify message IDs
	expectedIDs := make(map[[32]byte]bool)
	for _, event := range testEvents {
		expectedIDs[event.MessageID] = true
	}
	for _, data := range storedData {
		assert.True(t, expectedIDs[data.MessageID], "Unexpected message ID: %s", data.MessageID.String())
	}
}

func TestMultiSourceVerifier_TwoSources(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-multi-source-verifier", map[protocol.ChainSelector]protocol.UnknownAddress{
		sourceChain1: testCCVAddr,
		sourceChain2: testCCVAddr,
	})

	// Set up mock source readers
	mockSetup1 := verifier.SetupMockSourceReader(t)
	mockSetup1.ExpectFetchMessageSentEvent(false)
	mockSetup2 := verifier.SetupMockSourceReader(t)
	mockSetup2.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1: mockSetup1.Reader,
		sourceChain2: mockSetup2.Reader,
	}

	mockLatestBlocks(mockSetup1.Reader)
	mockLatestBlocks(mockSetup2.Reader)

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create test events for both sources
	eventsSource1 := []protocol.MessageSentEvent{
		createTestMessageSentEvent(t, 100, sourceChain1, defaultDestChain, 0, 300_000, 100),
		createTestMessageSentEvent(t, 101, sourceChain1, defaultDestChain, 0, 300_000, 101),
	}
	eventsSource2 := []protocol.MessageSentEvent{
		createTestMessageSentEvent(t, 200, sourceChain2, defaultDestChain, 0, 300_000, 200),
		createTestMessageSentEvent(t, 201, sourceChain2, defaultDestChain, 0, 300_000, 201),
	}

	// Send events from both sources
	var messagesSent1, messagesSent2 atomic.Int32
	sendEventsAsync(eventsSource1, mockSetup1.Channel, &messagesSent1, 5*time.Millisecond)
	sendEventsAsync(eventsSource2, mockSetup2.Channel, &messagesSent2, 7*time.Millisecond)

	// Wait for all messages to be processed
	totalMessages := len(eventsSource1) + len(eventsSource2)
	verifier.WaitForMessagesInStorage(ts.t, ts.storage, totalMessages)

	err = v.Close()
	require.NoError(t, err)

	// Verify stored data for both sources
	allStoredData, err := ts.storage.GetAllCCVData()
	require.NoError(t, err)

	// Filter by source chain
	storedDataSource1 := filterBySourceChain(allStoredData, sourceChain1)
	storedDataSource2 := filterBySourceChain(allStoredData, sourceChain2)

	assert.Len(t, storedDataSource1, len(eventsSource1))
	assert.Len(t, storedDataSource2, len(eventsSource2))
	assert.Equal(t, int(messagesSent1.Load()), len(eventsSource1))
	assert.Equal(t, int(messagesSent2.Load()), len(eventsSource2))

	// Verify message IDs and chain selectors
	verifyStoredTasks(t, storedDataSource1, eventsSource1, sourceChain1)
	verifyStoredTasks(t, storedDataSource2, eventsSource2, sourceChain2)
}

func TestMultiSourceVerifier_SingleSourceFailure(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-failure-verifier", map[protocol.ChainSelector]protocol.UnknownAddress{
		sourceChain1: testCCVAddr,
		sourceChain2: testCCVAddr,
	})

	// Set up mock source readers.
	mockSetup1 := verifier.SetupMockSourceReader(t)
	mockSetup1.ExpectFetchMessageSentEvent(false)

	// Generate an error on source 2.
	mockSetup2 := verifier.SetupMockSourceReader(t)
	sentinelError := errors.New("The Terminator")
	mockSetup2.Reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(nil, sentinelError)

	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1: mockSetup1.Reader,
		sourceChain2: mockSetup2.Reader,
	}

	mockLatestBlocks(mockSetup1.Reader)
	mockLatestBlocks(mockSetup2.Reader)

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Send verification events only to source 1
	eventsSource1 := []protocol.MessageSentEvent{
		createTestMessageSentEvent(t, 100, sourceChain1, defaultDestChain, 0, 300_000, 100),
		createTestMessageSentEvent(t, 101, sourceChain1, defaultDestChain, 0, 300_000, 101),
	}

	sendEventsAsync(eventsSource1, mockSetup1.Channel, nil, 5*time.Millisecond)
	verifier.WaitForMessagesInStorage(ts.t, ts.storage, len(eventsSource1))

	err = v.Close()
	require.NoError(t, err)

	// Verify only source 1 data was stored
	allStoredData, err := ts.storage.GetAllCCVData()
	require.NoError(t, err)

	// Filter by source chain - only chain 42 should have data
	storedDataSource1 := filterBySourceChain(allStoredData, sourceChain1)
	storedDataSource2 := filterBySourceChain(allStoredData, sourceChain2)

	assert.Len(t, storedDataSource1, len(eventsSource1))
	assert.Len(t, storedDataSource2, 0) // No messages from failed source
}

func TestMultiSourceVerifier_HealthReporter(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-health-check", map[protocol.ChainSelector]protocol.UnknownAddress{
		sourceChain1: testCCVAddr,
		sourceChain2: testCCVAddr,
	})

	// Create mock source readers
	mockSetup1 := verifier.SetupMockSourceReader(t)
	mockSetup1.ExpectFetchMessageSentEvent(true)
	mockSetup2 := verifier.SetupMockSourceReader(t)
	mockSetup2.ExpectFetchMessageSentEvent(true)

	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1: mockSetup1.Reader,
		sourceChain2: mockSetup2.Reader,
	}

	mockLatestBlocks(mockSetup1.Reader)
	mockLatestBlocks(mockSetup2.Reader)

	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	// Before starting, should not be ready
	report := v.HealthReport()
	require.Error(t, report[v.Name()])
	assert.Contains(t, report[v.Name()].Error(), "service is \"Unstarted\", not started")

	// Start the verifier
	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// HealthReport should show coordinator is healthy
	report = v.HealthReport()
	require.NotNil(t, report)
	require.Contains(t, report, v.Name())
	require.NoError(t, report[v.Name()])

	// Close the verifier
	err = v.Close()
	require.NoError(t, err)

	// After stopping, should not be ready
	report = v.HealthReport()
	require.Error(t, report[v.Name()])
}

func TestVerificationErrorHandling(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	// Create config with only one source chain configured
	config := createCoordinatorConfig("test-error-handling", map[protocol.ChainSelector]protocol.UnknownAddress{
		sourceChain1: testCCVAddr,
		// unconfiguredChain is intentionally not included in the config
	})

	// Set up mock source readers for both chains.
	mockSetup1 := verifier.SetupMockSourceReader(t)
	mockSetup1.ExpectFetchMessageSentEvent(false)
	mockSetup2 := verifier.SetupMockSourceReader(t)
	mockSetup2.ExpectFetchMessageSentEvent(true)

	// Create source readers map that includes the unconfigured chain
	// This simulates having a readerService for a chain that's not in the coordinator config
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1:      mockSetup1.Reader,
		unconfiguredChain: mockSetup2.Reader,
	}

	// Set up mock head trackers - only for sourceChain1 since unconfiguredChain won't be started
	mockLatestBlocks(mockSetup1.Reader)

	// Create and start verifier - this should succeed even with extra readers
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create test verification events
	validEvent := createTestMessageSentEvent(t, 100, sourceChain1, defaultDestChain, 0, 300_000, 100)
	invalidEvent := createTestMessageSentEvent(t, 200, unconfiguredChain, defaultDestChain, 0, 300_000, 200)

	// Send events
	sendEventsAsync([]protocol.MessageSentEvent{validEvent}, mockSetup1.Channel, nil, 10*time.Millisecond)
	sendEventsAsync([]protocol.MessageSentEvent{invalidEvent}, mockSetup2.Channel, nil, 10*time.Millisecond)

	// Wait for valid event to be processed
	verifier.WaitForMessagesInStorage(ts.t, ts.storage, 1)

	// Give some time for error processing
	time.Sleep(200 * time.Millisecond)

	err = v.Close()
	require.NoError(t, err)

	// Verify results - only the configured source chain should have stored data
	storedData, err := ts.storage.GetAllCCVData()
	require.NoError(t, err)
	assert.Len(t, storedData, 1)
	assert.Equal(t, validEvent.MessageID, storedData[0].MessageID)

	// The unconfigured chain is not in the config, so we can't check its data
	// The test validates that events from unconfigured chains don't cause crashes
	// and that configured chains continue to work properly
}

// createTestMessageSentEvent creates a single MessageSentEvent for testing.
func createTestMessageSentEvent(t *testing.T, sequenceNumber protocol.SequenceNumber, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16, gasLimit uint32, blockNumber uint64) protocol.MessageSentEvent {
	t.Helper()
	message := verifier.CreateTestMessage(t, sequenceNumber, sourceChainSelector, destChainSelector, finality, gasLimit)
	messageID, _ := message.MessageID()

	// Create test CCV and executor addresses matching those in CreateTestMessage
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11 // Must match CreateTestMessage

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22 // Must match CreateTestMessage

	return protocol.MessageSentEvent{
		DestChainSelector: message.DestChainSelector,
		SequenceNumber:    uint64(message.SequenceNumber),
		MessageID:         messageID,
		Message:           message,
		Receipts: []protocol.ReceiptWithBlob{
			{
				Issuer:            protocol.UnknownAddress(ccvAddr),
				DestGasLimit:      300000,
				DestBytesOverhead: 100,
				Blob:              []byte("test-blob"),
				ExtraArgs:         []byte("test-extra-args"),
			},
			{
				// Executor receipt - always at the end
				Issuer:            protocol.UnknownAddress(executorAddr),
				DestGasLimit:      0,
				DestBytesOverhead: 0,
				Blob:              []byte{},
				ExtraArgs:         []byte{},
			},
		},
		BlockNumber: blockNumber,
	}
}
