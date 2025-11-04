package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
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
	t       *testing.T
	ctx     context.Context
	cancel  context.CancelFunc
	logger  logger.Logger
	storage *common.InMemoryOffchainStorage
	signer  verifier.MessageSigner
}

// mockSourceReaderSetup contains a mock source reader and its channel.
type mockSourceReaderSetup struct {
	reader  *verifier_mocks.MockSourceReader
	channel chan verifier.VerificationTask
}

const (
	latestBlockHeight    = 1000
	finalizedBlockHeight = 950
)

// setupMockSourceReader creates a mock source reader with expectations.
func setupMockSourceReader(t *testing.T) *mockSourceReaderSetup {
	mockReader := verifier_mocks.NewMockSourceReader(t)
	channel := make(chan verifier.VerificationTask, 10)

	mockReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(time.Now().UnixMilli()), nil).Maybe()

	return &mockSourceReaderSetup{
		reader:  mockReader,
		channel: channel,
	}
}

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

func (msrs *mockSourceReaderSetup) ExpectVerificationTask(maybeVerificationTask bool) {
	call := msrs.reader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]verifier.VerificationTask, error) {
		var tasks []verifier.VerificationTask
		for {
			select {
			case task := <-msrs.channel:
				tasks = append(tasks, task)
			default:
				return tasks, nil
			}
		}
	})
	if maybeVerificationTask {
		call.Maybe()
	}
}

// newTestSetup creates common test dependencies.
func newTestSetup(t *testing.T) *testSetup {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	storage := common.NewInMemoryOffchainStorage(lggr)
	signer := createTestSigner(t)

	return &testSetup{
		t:       t,
		ctx:     ctx,
		cancel:  cancel,
		logger:  lggr,
		storage: storage,
		signer:  signer,
	}
}

// cleanup should be called in defer.
func (ts *testSetup) cleanup() {
	ts.cancel()
}

// createTestSigner generates a test ECDSA message signer.
func createTestSigner(t *testing.T) verifier.MessageSigner {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, err := commit.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)
	return signer
}

func createTestMessage(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16, gasLimit uint32) protocol.Message {
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

	return createTestMessageWithVerifier(t, nonce, sourceChainSelector, destChainSelector, verifierAddress, finality, gasLimit)
}

func createTestMessageWithVerifier(t *testing.T,
	nonce protocol.Nonce,
	sourceChainSelector,
	destChainSelector protocol.ChainSelector,
	verifierAddress string, finality uint16,
	gasLimit uint32,
) protocol.Message {
	// Create empty token transfer
	tokenTransfer := protocol.NewEmptyTokenTransfer()

	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		nonce,
		onRampAddr,
		offRampAddr,
		finality,
		gasLimit,
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
	require.NoError(t, err)
	return *message
}

func createTestVerificationTask(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16, gasLimit uint32) verifier.VerificationTask {
	message := createTestMessage(t, nonce, sourceChainSelector, destChainSelector, finality, gasLimit)

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

	return verifier.VerificationTask{
		Message: message,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{
				Issuer:            []byte(verifierAddress),
				DestGasLimit:      300000, // Test gas limit
				DestBytesOverhead: 100,    // Test bytes overhead
				Blob:              []byte("test-blob"),
				ExtraArgs:         []byte("test-extra-args"), // Test extra args
			},
		},
	}
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

	mockReader := verifier_mocks.NewMockSourceReader(t)
	channel := make(chan verifier.VerificationTask, 10)
	mockReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]verifier.VerificationTask, error) {
		var tasks []verifier.VerificationTask
		for {
			select {
			case task := <-channel:
				tasks = append(tasks, task)
			default:
				return tasks, nil
			}
		}
	}).Maybe()

	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockReader,
	}
	ts := newTestSetup(t)

	noopMonitoring := monitoring.NewNoopVerifierMonitoring()
	commitVerifier, err := commit.NewCommitVerifier(config, ts.signer, ts.logger, noopMonitoring)
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
func createVerificationCoordinator(ts *testSetup, config verifier.CoordinatorConfig, sourceReaders map[protocol.ChainSelector]verifier.SourceReader, headTrackers map[protocol.ChainSelector]chainaccess.HeadTracker) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewNoopVerifierMonitoring()
	commitVerifier, err := commit.NewCommitVerifier(config, ts.signer, ts.logger, noopMonitoring)
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

// waitForMessages waits for the specified number of messages to be processed.
// Since messages are batched, we can't rely on one notification per message.
// Instead, we poll the storage to check if the expected count has been reached.
func waitForMessages(ts *testSetup, count int) {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			require.FailNow(ts.t, "Timeout waiting for messages", "expected %d messages, got %d", count, ts.storage.GetTotalCount())
		case <-ticker.C:
			if ts.storage.GetTotalCount() >= count {
				return
			}
		}
	}
}

// sendTasksAsync sends verification tasks asynchronously with a delay.
func sendTasksAsync(tasks []verifier.VerificationTask, channel chan<- verifier.VerificationTask, counter *atomic.Int32, delay time.Duration) {
	go func() {
		for _, task := range tasks {
			channel <- task
			if counter != nil {
				counter.Add(1)
			}
			time.Sleep(delay)
		}
	}()
}

// verifyStoredTasks is a helper to verify stored data matches expected tasks.
func verifyStoredTasks(t *testing.T, storedData []protocol.CCVData, expectedTasks []verifier.VerificationTask, expectedChain protocol.ChainSelector) {
	expectedIDs := make(map[[32]byte]bool)
	for _, task := range expectedTasks {
		messageID, err := task.Message.MessageID()
		require.NoError(t, err)
		expectedIDs[messageID] = true
	}
	for _, data := range storedData {
		assert.True(t, expectedIDs[data.MessageID], "Unexpected message ID: %x", data.MessageID)
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
	mockSetup := setupMockSourceReader(t)
	mockSetup.ExpectVerificationTask(false)
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup.reader,
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

	// Create and send test tasks
	testTasks := []verifier.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0, 300_000),
		createTestVerificationTask(t, 200, sourceChain1, defaultDestChain, 0, 300_000),
	}

	var messagesSent atomic.Int32
	sendTasksAsync(testTasks, mockSetup.channel, &messagesSent, 10*time.Millisecond)

	// Wait for processing and verify results
	waitForMessages(ts, len(testTasks))

	err = v.Close()
	require.NoError(t, err)

	// Verify stored data
	storedData, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	assert.Len(t, storedData, len(testTasks))
	assert.Equal(t, int(messagesSent.Load()), len(testTasks))

	// Verify message IDs
	expectedIDs := make(map[[32]byte]bool)
	for _, task := range testTasks {
		messageID, err := task.Message.MessageID()
		require.NoError(t, err)
		expectedIDs[messageID] = true
	}
	for _, data := range storedData {
		assert.True(t, expectedIDs[data.MessageID], "Unexpected message ID: %x", data.MessageID)
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
	mockSetup1 := setupMockSourceReader(t)
	mockSetup1.ExpectVerificationTask(false)
	mockSetup2 := setupMockSourceReader(t)
	mockSetup2.ExpectVerificationTask(false)
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
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

	// Create test tasks for both sources
	tasksSource1 := []verifier.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0, 300_000),
		createTestVerificationTask(t, 101, sourceChain1, defaultDestChain, 0, 300_000),
	}
	tasksSource2 := []verifier.VerificationTask{
		createTestVerificationTask(t, 200, sourceChain2, defaultDestChain, 0, 300_000),
		createTestVerificationTask(t, 201, sourceChain2, defaultDestChain, 0, 300_000),
	}

	// Send tasks from both sources
	var messagesSent1, messagesSent2 atomic.Int32
	sendTasksAsync(tasksSource1, mockSetup1.channel, &messagesSent1, 5*time.Millisecond)
	sendTasksAsync(tasksSource2, mockSetup2.channel, &messagesSent2, 7*time.Millisecond)

	// Wait for all messages to be processed
	totalMessages := len(tasksSource1) + len(tasksSource2)
	waitForMessages(ts, totalMessages)

	err = v.Close()
	require.NoError(t, err)

	// Verify stored data for both sources
	storedDataSource1, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	storedDataSource2, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain2].VerifierAddress)
	require.NoError(t, err)

	assert.Len(t, storedDataSource1, len(tasksSource1))
	assert.Len(t, storedDataSource2, len(tasksSource2))
	assert.Equal(t, int(messagesSent1.Load()), len(tasksSource1))
	assert.Equal(t, int(messagesSent2.Load()), len(tasksSource2))

	// Verify message IDs and chain selectors
	verifyStoredTasks(t, storedDataSource1, tasksSource1, sourceChain1)
	verifyStoredTasks(t, storedDataSource2, tasksSource2, sourceChain2)
}

func TestMultiSourceVerifier_SingleSourceFailure(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-failure-verifier", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		sourceChain2: "0x5678",
	})

	// Set up mock source readers.
	mockSetup1 := setupMockSourceReader(t)
	mockSetup1.ExpectVerificationTask(false)

	// Generate an error on source 2.
	mockSetup2 := setupMockSourceReader(t)
	sentinelError := errors.New("The Terminator")
	mockSetup2.reader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).Return(nil, sentinelError)

	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
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

	// Send verification tasks only to source 1
	tasksSource1 := []verifier.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0, 300_000),
		createTestVerificationTask(t, 101, sourceChain1, defaultDestChain, 0, 300_000),
	}

	sendTasksAsync(tasksSource1, mockSetup1.channel, nil, 5*time.Millisecond)
	waitForMessages(ts, len(tasksSource1))

	err = v.Close()
	require.NoError(t, err)

	// Verify only source 1 data was stored
	storedDataSource1, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	storedDataSource2, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain2].VerifierAddress)
	require.NoError(t, err)

	assert.Len(t, storedDataSource1, len(tasksSource1))
	assert.Len(t, storedDataSource2, 0) // No messages from failed source
}

func TestMultiSourceVerifier_ValidationErrors(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	tests := []struct {
		readers     map[protocol.ChainSelector]verifier.SourceReader
		name        string
		expectError string
		config      verifier.CoordinatorConfig
	}{
		{
			name:        "no source readers",
			config:      createCoordinatorConfig("test-no-sources", map[protocol.ChainSelector]string{}),
			readers:     map[protocol.ChainSelector]verifier.SourceReader{},
			expectError: "at least one source reader is required",
		},
		{
			name: "mismatched source config and readers",
			config: createCoordinatorConfig("test-mismatch", map[protocol.ChainSelector]string{
				sourceChain1: "0x1234",
				sourceChain2: "0x5678",
			}),
			readers: func() map[protocol.ChainSelector]verifier.SourceReader {
				// Create a mock that only expects VerificationTaskChannel call
				mockReader := verifier_mocks.NewMockSourceReader(t)
				mockCh := make(chan verifier.VerificationTask)
				mockReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]verifier.VerificationTask, error) {
					var tasks []verifier.VerificationTask
					for {
						select {
						case task := <-mockCh:
							tasks = append(tasks, task)
						default:
							return tasks, nil
						}
					}
				}).Maybe()

				return map[protocol.ChainSelector]verifier.SourceReader{
					sourceChain1: mockReader, // Missing reader for sourceChain2
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
	mockSetup1 := setupMockSourceReader(t)
	mockSetup1.ExpectVerificationTask(true)
	mockSetup2 := setupMockSourceReader(t)
	mockSetup2.ExpectVerificationTask(true)

	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
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
	assert.Contains(t, err.Error(), "coordinator not running")

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
	mockSetup1 := setupMockSourceReader(t)
	mockSetup1.ExpectVerificationTask(false)
	mockSetup2 := setupMockSourceReader(t)
	mockSetup2.ExpectVerificationTask(true)

	// Create source readers map that includes the unconfigured chain
	// This simulates having a reader for a chain that's not in the coordinator config
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1:      mockSetup1.reader,
		unconfiguredChain: mockSetup2.reader,
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

	// Create test verification tasks
	validTask := createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0, 300_000)
	invalidTask := createTestVerificationTask(t, 200, unconfiguredChain, defaultDestChain, 0, 300_000)

	// Send tasks
	sendTasksAsync([]verifier.VerificationTask{validTask}, mockSetup1.channel, nil, 10*time.Millisecond)
	sendTasksAsync([]verifier.VerificationTask{invalidTask}, mockSetup2.channel, nil, 10*time.Millisecond)

	// Wait for valid task to be processed
	waitForMessages(ts, 1)

	// Give some time for error processing
	time.Sleep(200 * time.Millisecond)

	err = v.Close()
	require.NoError(t, err)

	// Verify results - only the configured source chain should have stored data
	storedData, err := ts.storage.GetAllCCVData(config.SourceConfigs[sourceChain1].VerifierAddress)
	require.NoError(t, err)
	assert.Len(t, storedData, 1)
	expectedMessageID, err := validTask.Message.MessageID()
	require.NoError(t, err)
	assert.Equal(t, expectedMessageID, storedData[0].MessageID)

	// The unconfigured chain is not in the config, so we can't check its data
	// The test validates that tasks from unconfigured chains don't cause crashes
	// and that configured chains continue to work properly
}
