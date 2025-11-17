package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"strings"
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

// testSetup contains common test dependencies.
type testSetup struct {
	t          *testing.T
	ctx        context.Context
	cancel     context.CancelFunc
	logger     logger.Logger
	storage    *common.InMemoryOffchainStorage
	signerAddr protocol.UnknownAddress
	signer     verifier.MessageSigner
}

const (
	latestBlockHeight    = 1000
	finalizedBlockHeight = 950
)

// setupMockHeadTracker creates a mock head tracker with expectations.
func setupMockHeadTracker(t *testing.T) *protocol_mocks.MockHeadTracker {
	mockHeadTracker := protocol_mocks.NewMockHeadTracker(t)

	latestHeader := &protocol.BlockHeader{
		Number:               latestBlockHeight,
		Hash:                 protocol.Bytes32{byte(latestBlockHeight % 256)},
		ParentHash:           protocol.Bytes32{byte((latestBlockHeight - 1) % 256)},
		Timestamp:            time.Now(),
		FinalizedBlockNumber: finalizedBlockHeight,
	}
	finalizedHeader := &protocol.BlockHeader{
		Number:               finalizedBlockHeight,
		Hash:                 protocol.Bytes32{byte(finalizedBlockHeight % 256)},
		ParentHash:           protocol.Bytes32{byte((finalizedBlockHeight - 1) % 256)},
		Timestamp:            time.Now(),
		FinalizedBlockNumber: finalizedBlockHeight,
	}
	mockHeadTracker.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latestHeader, finalizedHeader, nil).Maybe()

	return mockHeadTracker
}

// newTestSetup creates common test dependencies.
func newTestSetup(t *testing.T) *testSetup {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	storage := common.NewInMemoryOffchainStorage(lggr)
	signer, addr := createTestSigner(t)

	return &testSetup{
		t:          t,
		ctx:        ctx,
		cancel:     cancel,
		logger:     lggr,
		storage:    storage,
		signerAddr: addr,
		signer:     signer,
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
func createCoordinatorConfig(coordinatorID string, sources map[protocol.ChainSelector]string) verifier.CoordinatorConfig {
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for chainSelector, address := range sources {
		sourceConfigs[chainSelector] = verifier.SourceConfig{
			VerifierAddress: protocol.UnknownAddress([]byte(address)),
		}
	}

	return verifier.CoordinatorConfig{
		VerifierID:    coordinatorID,
		SourceConfigs: sourceConfigs,
	}
}

func TestNewVerifierCoordinator(t *testing.T) {
	config := createCoordinatorConfig("test-custom-mockery-verifier", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
	})

	mockSetup := verifier.SetupMockSourceReader(t)
	mockReader := mockSetup.Reader
	mockSetup.ExpectFetchMessageSentEvent(true)

	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1: mockReader,
	}
	ts := newTestSetup(t)

	noopMonitoring := monitoring.NewNoopVerifierMonitoring()
	commitVerifier, err := commit.NewCommitVerifier(config, ts.signerAddr, ts.signer, ts.logger, noopMonitoring)
	require.NoError(t, err)

	testcases := []struct {
		name    string
		options []verifier.Option
		err     []string
	}{
		{
			name:    "missing every option",
			options: []verifier.Option{},
			err: []string{
				"verifier is not set",
				"storage is not set",
				"logger is not set",
				"at least one source reader is required",
				"monitoring is not set",
				"coordinator ID cannot be empty",
			},
		},
		{
			name: "happy",
			options: []verifier.Option{
				verifier.WithConfig(config),
				verifier.WithSourceReaders(sourceReaders),
				verifier.WithVerifier(commitVerifier),
				verifier.WithStorage(ts.storage),
				verifier.WithLogger(ts.logger),
				verifier.WithMonitoring(noopMonitoring),
			},
			err: nil,
		},
		{
			name: "missing config",
			options: []verifier.Option{
				verifier.WithSourceReaders(sourceReaders),
				verifier.WithVerifier(commitVerifier),
				verifier.WithStorage(ts.storage),
				verifier.WithLogger(ts.logger),
				verifier.WithMonitoring(noopMonitoring),
			},
			err: []string{"coordinator ID cannot be empty"},
		},
		{
			name: "missing source readers",
			options: []verifier.Option{
				verifier.WithConfig(config),
				verifier.WithVerifier(commitVerifier),
				verifier.WithStorage(ts.storage),
				verifier.WithLogger(ts.logger),
				verifier.WithMonitoring(noopMonitoring),
			},
			err: []string{
				"at least one source reader is required",
				"source reader not found for chain selector 42",
			},
		},
		{
			name: "missing verifier",
			options: []verifier.Option{
				verifier.WithConfig(config),
				verifier.WithSourceReaders(sourceReaders),
				verifier.WithStorage(ts.storage),
				verifier.WithLogger(ts.logger),
				verifier.WithMonitoring(noopMonitoring),
			},
			err: []string{"verifier is not set"},
		},
		{
			name: "missing storage",
			options: []verifier.Option{
				verifier.WithConfig(config),
				verifier.WithSourceReaders(sourceReaders),
				verifier.WithVerifier(commitVerifier),
				verifier.WithLogger(ts.logger),
				verifier.WithMonitoring(noopMonitoring),
			},
			err: []string{"storage is not set"},
		},
		{
			name: "missing logger",
			options: []verifier.Option{
				verifier.WithConfig(config),
				verifier.WithSourceReaders(sourceReaders),
				verifier.WithVerifier(commitVerifier),
				verifier.WithStorage(ts.storage),
				verifier.WithMonitoring(noopMonitoring),
			},
			err: []string{"logger is not set"},
		},
		{
			name: "missing monitoring",
			options: []verifier.Option{
				verifier.WithConfig(config),
				verifier.WithSourceReaders(sourceReaders),
				verifier.WithVerifier(commitVerifier),
				verifier.WithLogger(ts.logger),
				verifier.WithStorage(ts.storage),
			},
			err: []string{"monitoring is not set"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ec, err := verifier.NewCoordinator(tc.options...)

			if len(tc.err) > 0 {
				require.Error(t, err)
				require.Nil(t, ec)
				joinedError := err.Error()

				for _, errStr := range tc.err {
					require.ErrorContains(t, err, errStr)
				}

				require.Len(t, tc.err, len(strings.Split(joinedError, "\n")), "unexpected number of errors")
			} else {
				require.NoError(t, err)
				require.NotNil(t, ec)
			}
		})
	}
}

// createVerificationCoordinator creates a verification coordinator with the given setup.
func createVerificationCoordinator(ts *testSetup, config verifier.CoordinatorConfig, sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader, headTrackers map[protocol.ChainSelector]chainaccess.HeadTracker) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewNoopVerifierMonitoring()
	commitVerifier, err := commit.NewCommitVerifier(config, ts.signerAddr, ts.signer, ts.logger, noopMonitoring)
	require.NoError(ts.t, err)

	return verifier.NewCoordinator(
		verifier.WithConfig(config),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithHeadTrackers(headTrackers),
		verifier.WithVerifier(commitVerifier),
		verifier.WithStorage(ts.storage),
		verifier.WithLogger(ts.logger),
		verifier.WithMonitoring(noopMonitoring),
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
func verifyStoredTasks(t *testing.T, storedData []protocol.CCVData, expectedTasks []protocol.MessageSentEvent, expectedChain protocol.ChainSelector) {
	expectedIDs := make(map[[32]byte]bool)
	for _, task := range expectedTasks {
		messageID, err := task.Message.MessageID()
		require.NoError(t, err)
		expectedIDs[messageID] = true
	}
	for _, data := range storedData {
		assert.True(t, expectedIDs[data.MessageID], "Unexpected message ID: %s", data.MessageID.String())
		assert.Equal(t, expectedChain, data.SourceChainSelector)
	}
}

func TestVerifier(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-custom-mockery-verifier", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
	})

	// Set up mock source reader
	mockSetup := verifier.SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1: mockSetup.Reader,
	}

	// Set up mock head tracker
	mockHeadTracker := setupMockHeadTracker(t)
	headTrackers := map[protocol.ChainSelector]chainaccess.HeadTracker{
		sourceChain1: mockHeadTracker,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders, headTrackers)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create and send test events
	testEvents := []protocol.MessageSentEvent{
		createTestMessageSentEvent(t, 100, sourceChain1, defaultDestChain, 0, 300_000, 100),
		createTestMessageSentEvent(t, 200, sourceChain1, defaultDestChain, 0, 300_000, 200),
	}

	var messagesSent atomic.Int32
	sendEventsAsync(testEvents, mockSetup.Channel, &messagesSent, 10*time.Millisecond)

	// Wait for processing and verify results
	verifier.WaitForMessagesInStorage(ts.t, ts.storage, len(testEvents))

	err = v.Close()
	require.NoError(t, err)

	// Verify stored data
	storedData, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
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

	config := createCoordinatorConfig("test-multi-source-verifier", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		sourceChain2: "0x5678",
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

	// Set up mock head trackers
	mockHeadTracker1 := setupMockHeadTracker(t)
	mockHeadTracker2 := setupMockHeadTracker(t)
	headTrackers := map[protocol.ChainSelector]chainaccess.HeadTracker{
		sourceChain1: mockHeadTracker1,
		sourceChain2: mockHeadTracker2,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders, headTrackers)
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
	storedDataSource1, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	storedDataSource2, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain2].VerifierAddress)
	require.NoError(t, err)

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

	config := createCoordinatorConfig("test-failure-verifier", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		sourceChain2: "0x5678",
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

	// Set up mock head trackers
	mockHeadTracker1 := setupMockHeadTracker(t)
	mockHeadTracker2 := setupMockHeadTracker(t)
	headTrackers := map[protocol.ChainSelector]chainaccess.HeadTracker{
		sourceChain1: mockHeadTracker1,
		sourceChain2: mockHeadTracker2,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders, headTrackers)
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
	storedDataSource1, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	storedDataSource2, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain2].VerifierAddress)
	require.NoError(t, err)

	assert.Len(t, storedDataSource1, len(eventsSource1))
	assert.Len(t, storedDataSource2, 0) // No messages from failed source
}

func TestMultiSourceVerifier_ValidationErrors(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	tests := []struct {
		readers     map[protocol.ChainSelector]chainaccess.SourceReader
		name        string
		expectError string
		config      verifier.CoordinatorConfig
	}{
		{
			name:        "no source readers",
			config:      createCoordinatorConfig("test-no-sources", map[protocol.ChainSelector]string{}),
			readers:     map[protocol.ChainSelector]chainaccess.SourceReader{},
			expectError: "at least one source reader is required",
		},
		{
			name: "mismatched source config and readers",
			config: createCoordinatorConfig("test-mismatch", map[protocol.ChainSelector]string{
				sourceChain1: "0x1234",
				sourceChain2: "0x5678",
			}),
			readers: func() map[protocol.ChainSelector]chainaccess.SourceReader {
				// Create a mock that only expects FetchMessageSentEvents call
				mockSetup := verifier.SetupMockSourceReader(t)
				mockSetup.ExpectFetchMessageSentEvent(true)

				return map[protocol.ChainSelector]chainaccess.SourceReader{
					sourceChain1: mockSetup.Reader, // Missing reader for sourceChain2
				}
			}(),
			expectError: "source reader not found for chain selector 84",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For error tests, provide empty head trackers to trigger validation errors
			headTrackers := map[protocol.ChainSelector]chainaccess.HeadTracker{}
			_, err := createVerificationCoordinator(ts, tt.config, tt.readers, headTrackers)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestMultiSourceVerifier_HealthReporter(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-health-check", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		sourceChain2: "0x5678",
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

	// Set up mock head trackers
	mockHeadTracker1 := setupMockHeadTracker(t)
	mockHeadTracker2 := setupMockHeadTracker(t)
	headTrackers := map[protocol.ChainSelector]chainaccess.HeadTracker{
		sourceChain1: mockHeadTracker1,
		sourceChain2: mockHeadTracker2,
	}

	v, err := createVerificationCoordinator(ts, config, sourceReaders, headTrackers)
	require.NoError(t, err)

	// Before starting, should not be ready
	err = v.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service is \"Unstarted\", not started")

	// Start the verifier
	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// After starting, should be ready
	err = v.Ready()
	require.NoError(t, err)

	// HealthReport should show coordinator is healthy
	report := v.HealthReport()
	require.NotNil(t, report)
	require.Contains(t, report, v.Name())
	require.NoError(t, report[v.Name()])

	// Close the verifier
	err = v.Close()
	require.NoError(t, err)

	// After stopping, should not be ready
	err = v.Ready()
	require.Error(t, err)
}

func TestVerificationErrorHandling(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	// Create config with only one source chain configured
	config := createCoordinatorConfig("test-error-handling", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		// unconfiguredChain is intentionally not included in the config
	})

	// Set up mock source readers for both chains.
	mockSetup1 := verifier.SetupMockSourceReader(t)
	mockSetup1.ExpectFetchMessageSentEvent(false)
	mockSetup2 := verifier.SetupMockSourceReader(t)
	mockSetup2.ExpectFetchMessageSentEvent(true)

	// Create source readers map that includes the unconfigured chain
	// This simulates having a reader for a chain that's not in the coordinator config
	sourceReaders := map[protocol.ChainSelector]chainaccess.SourceReader{
		sourceChain1:      mockSetup1.Reader,
		unconfiguredChain: mockSetup2.Reader,
	}

	// Set up mock head trackers - only for sourceChain1 since unconfiguredChain won't be started
	mockHeadTracker1 := setupMockHeadTracker(t)
	headTrackers := map[protocol.ChainSelector]chainaccess.HeadTracker{
		sourceChain1: mockHeadTracker1,
		// unconfiguredChain doesn't get a head tracker since it's not in config
	}

	// Create and start verifier - this should succeed even with extra readers
	v, err := createVerificationCoordinator(ts, config, sourceReaders, headTrackers)
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
	storedData, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	assert.Len(t, storedData, 1)
	assert.Equal(t, validEvent.MessageID, storedData[0].MessageID)

	// The unconfigured chain is not in the config, so we can't check its data
	// The test validates that events from unconfigured chains don't cause crashes
	// and that configured chains continue to work properly
}

// createTestMessageSentEvent creates a single MessageSentEvent for testing.
func createTestMessageSentEvent(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16, gasLimit uint32, blockNumber uint64) protocol.MessageSentEvent {
	t.Helper()
	message := verifier.CreateTestMessage(t, nonce, sourceChainSelector, destChainSelector, finality, gasLimit)
	messageID, _ := message.MessageID()

	// Determine the correct verifier address based on source chain
	var verifierAddress string
	switch sourceChainSelector {
	case sourceChain1:
		verifierAddress = "0x1234"
	case sourceChain2:
		verifierAddress = "0x5678"
	default:
		verifierAddress = "0x1234" // Default fallback
	}

	return protocol.MessageSentEvent{
		DestChainSelector: message.DestChainSelector,
		SequenceNumber:    uint64(message.Nonce),
		MessageID:         messageID,
		Message:           message,
		Receipts: []protocol.ReceiptWithBlob{
			{
				Issuer:            []byte(verifierAddress),
				DestGasLimit:      300000,
				DestBytesOverhead: 100,
				Blob:              []byte("test-blob"),
				ExtraArgs:         []byte("test-extra-args"),
			},
		},
		BlockNumber: blockNumber,
	}
}
