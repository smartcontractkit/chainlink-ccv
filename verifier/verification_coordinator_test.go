package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Test constants.
const (
	defaultProcessingChannelSize = 10
	defaultProcessingTimeout     = time.Second
	defaultMaxBatchSize          = 100
	defaultDestChain             = protocol.ChainSelector(100)
	sourceChain1                 = protocol.ChainSelector(42)
	sourceChain2                 = protocol.ChainSelector(84)
	unconfiguredChain            = protocol.ChainSelector(999)
)

// testSetup contains common test dependencies.
type testSetup struct {
	t       *testing.T
	ctx     context.Context
	cancel  context.CancelFunc
	logger  logger.Logger
	storage *storageaccess.InMemoryOffchainStorage
	signer  verifier.MessageSigner
}

// mockSourceReaderSetup contains a mock source reader and its channel.
type mockSourceReaderSetup struct {
	reader  *verifier_mocks.MockSourceReader
	channel chan verifier.VerificationTask
}

// newTestSetup creates common test dependencies.
func newTestSetup(t *testing.T) *testSetup {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	storage := storageaccess.NewInMemoryOffchainStorage(lggr)
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

func createTestMessage(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16) protocol.Message {
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

	return createTestMessageWithVerifier(t, nonce, sourceChainSelector, destChainSelector, verifierAddress, finality)
}

func createTestMessageWithVerifier(t *testing.T,
	nonce protocol.Nonce,
	sourceChainSelector,
	destChainSelector protocol.ChainSelector,
	verifierAddress string, finality uint16,
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
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
	require.NoError(t, err)
	return *message
}

func createTestVerificationTask(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16) verifier.VerificationTask {
	message := createTestMessage(t, nonce, sourceChainSelector, destChainSelector, finality)

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
		VerifierID:            coordinatorID,
		SourceConfigs:         sourceConfigs,
		ProcessingChannelSize: defaultProcessingChannelSize,
		ProcessingTimeout:     defaultProcessingTimeout,
		MaxBatchSize:          defaultMaxBatchSize,
	}
}

// setupMockSourceReader creates a mock source reader with expectations.
func setupMockSourceReader(t *testing.T) *mockSourceReaderSetup {
	return setupMockSourceReaderMaybe(t, false)
}

// setupMockSourceReaderMaybe creates a mock source reader with expectations, whether or not .Maybe() is used for the
// VerificationTasks call is configurable
func setupMockSourceReaderMaybe(t *testing.T, maybeVerificationTasks bool) *mockSourceReaderSetup {
	mockReader := verifier_mocks.NewMockSourceReader(t)
	channel := make(chan verifier.VerificationTask, 10)

	call := mockReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]verifier.VerificationTask, error) {
		var tasks []verifier.VerificationTask
		for {
			select {
			case task := <-channel:
				tasks = append(tasks, task)
			default:
				return tasks, nil
			}
		}
	})
	if maybeVerificationTasks {
		call.Maybe()
	}

	// Add missing LatestBlockHeight expectation to prevent timeout
	mockReader.EXPECT().LatestBlockHeight(mock.Anything).Return(big.NewInt(1000), nil).Maybe()
	mockReader.EXPECT().LatestFinalizedBlockHeight(mock.Anything).Return(big.NewInt(950), nil).Maybe()

	mockReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(time.Now().Unix()), nil).Maybe()

	return &mockSourceReaderSetup{
		reader:  mockReader,
		channel: channel,
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
			ec, err := verifier.NewVerificationCoordinator(tc.options...)

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
func createVerificationCoordinator(ts *testSetup, config verifier.CoordinatorConfig, sourceReaders map[protocol.ChainSelector]verifier.SourceReader) (*verifier.Coordinator, error) {
	noopMonitoring := monitoring.NewNoopVerifierMonitoring()
	commitVerifier, err := commit.NewCommitVerifier(config, ts.signer, ts.logger, noopMonitoring)
	require.NoError(ts.t, err)

	return verifier.NewVerificationCoordinator(
		verifier.WithConfig(config),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithVerifier(commitVerifier),
		verifier.WithStorage(ts.storage),
		verifier.WithLogger(ts.logger),
		verifier.WithMonitoring(noopMonitoring),
	)
}

// waitForMessages waits for the specified number of messages to be processed.
func waitForMessages(ts *testSetup, count int) {
	for i := 0; i < count; i++ {
		err := ts.storage.WaitForStore(ts.ctx)
		require.NoError(ts.t, err)
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
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup.reader,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create and send test tasks
	testTasks := []verifier.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0),
		createTestVerificationTask(t, 200, sourceChain1, defaultDestChain, 0),
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
	mockSetup2 := setupMockSourceReader(t)
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create test tasks for both sources
	tasksSource1 := []verifier.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0),
		createTestVerificationTask(t, 101, sourceChain1, defaultDestChain, 0),
	}
	tasksSource2 := []verifier.VerificationTask{
		createTestVerificationTask(t, 200, sourceChain2, defaultDestChain, 0),
		createTestVerificationTask(t, 201, sourceChain2, defaultDestChain, 0),
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

	// Set up mock source readers - source 2 will fail by closing its channel immediately
	mockSetup1 := setupMockSourceReader(t)
	mockSetup2 := setupMockSourceReader(t)
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Close source 2 channel immediately to simulate failure
	close(mockSetup2.channel)

	// Send verification tasks only to source 1
	tasksSource1 := []verifier.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0),
		createTestVerificationTask(t, 101, sourceChain1, defaultDestChain, 0),
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
			_, err := createVerificationCoordinator(ts, tt.config, tt.readers)
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
	mockSetup1 := setupMockSourceReaderMaybe(t, true)
	mockSetup2 := setupMockSourceReaderMaybe(t, true)

	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
	}

	v, err := createVerificationCoordinator(ts, config, sourceReaders)
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
	mockSetup2 := setupMockSourceReaderMaybe(t, true) // this one is skipped.

	// Create source readers map that includes the unconfigured chain
	// This simulates having a reader for a chain that's not in the coordinator config
	sourceReaders := map[protocol.ChainSelector]verifier.SourceReader{
		sourceChain1:      mockSetup1.reader,
		unconfiguredChain: mockSetup2.reader,
	}

	// Create and start verifier - this should succeed even with extra readers
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create test verification tasks
	validTask := createTestVerificationTask(t, 100, sourceChain1, defaultDestChain, 0)
	invalidTask := createTestVerificationTask(t, 200, unconfiguredChain, defaultDestChain, 0)

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
