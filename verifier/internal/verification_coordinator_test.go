package internal_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
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
	signer  pkg.MessageSigner
}

// mockSourceReaderSetup contains a mock source reader and its channel.
type mockSourceReaderSetup struct {
	reader  *verifier_mocks.MockSourceReader
	channel chan types.VerificationTask
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
func createTestSigner(t *testing.T) pkg.MessageSigner {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, err := commit.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)
	return signer
}

func createTestMessage(t *testing.T, seqNum protocol.SeqNum, sourceChainSelector, destChainSelector protocol.ChainSelector) protocol.Message {
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

	return createTestMessageWithVerifier(t, seqNum, sourceChainSelector, destChainSelector, verifierAddress)
}

func createTestMessageWithVerifier(t *testing.T, seqNum protocol.SeqNum, sourceChainSelector, destChainSelector protocol.ChainSelector, verifierAddress string) protocol.Message {
	// Create empty token transfer
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

func createTestVerificationTask(t *testing.T, seqNum protocol.SeqNum, sourceChainSelector, destChainSelector protocol.ChainSelector) types.VerificationTask {
	message := createTestMessage(t, seqNum, sourceChainSelector, destChainSelector)

	// Create receipt blob with nonce using canonical encoding
	nonce := uint64(seqNum)
	receiptBlob, err := commit.EncodeVerifierBlob(nonce)
	require.NoError(t, err)

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

	return types.VerificationTask{
		Message: message,
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{
				Issuer:            []byte(verifierAddress),
				DestGasLimit:      300000, // Test gas limit
				DestBytesOverhead: 100,    // Test bytes overhead
				Blob:              receiptBlob,
				ExtraArgs:         []byte("test-extra-args"), // Test extra args
			},
		},
	}
}

// createCoordinatorConfig creates a coordinator config with the given sources.
func createCoordinatorConfig(coordinatorID string, sources map[protocol.ChainSelector]string) types.CoordinatorConfig {
	sourceConfigs := make(map[protocol.ChainSelector]types.SourceConfig)
	for chainSelector, address := range sources {
		sourceConfigs[chainSelector] = types.SourceConfig{
			VerifierAddress: protocol.UnknownAddress([]byte(address)),
		}
	}

	return types.CoordinatorConfig{
		VerifierID:            coordinatorID,
		SourceConfigs:         sourceConfigs,
		ProcessingChannelSize: defaultProcessingChannelSize,
		ProcessingTimeout:     defaultProcessingTimeout,
		MaxBatchSize:          defaultMaxBatchSize,
	}
}

// setupMockSourceReader creates a mock source reader with expectations.
func setupMockSourceReader(t *testing.T, shouldClose bool) *mockSourceReaderSetup {
	mockReader := verifier_mocks.NewMockSourceReader(t)
	channel := make(chan types.VerificationTask, 10)

	mockReader.EXPECT().Start(mock.Anything).Return(nil)
	mockReader.EXPECT().VerificationTaskChannel().Return((<-chan types.VerificationTask)(channel))

	// Add missing LatestBlock expectation to prevent timeout
	mockReader.EXPECT().LatestBlock(mock.Anything).Return(big.NewInt(1000), nil).Maybe()
	mockReader.EXPECT().LatestFinalizedBlock(mock.Anything).Return(big.NewInt(950), nil).Maybe()

	if shouldClose {
		mockReader.EXPECT().Stop().Run(func() {
			close(channel)
		}).Return(nil)
	} else {
		mockReader.EXPECT().Stop().Return(nil)
	}

	return &mockSourceReaderSetup{
		reader:  mockReader,
		channel: channel,
	}
}

// createVerificationCoordinator creates a verification coordinator with the given setup.
func createVerificationCoordinator(ts *testSetup, config types.CoordinatorConfig, sourceReaders map[protocol.ChainSelector]reader.SourceReader) (*internal.VerificationCoordinator, error) {
	commitVerifier := commit.NewCommitVerifier(config, ts.signer, ts.logger)

	return internal.NewVerificationCoordinator(
		internal.WithConfig(config),
		internal.WithSourceReaders(sourceReaders),
		internal.WithVerifier(commitVerifier),
		internal.WithStorage(ts.storage),
		internal.WithLogger(ts.logger),
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
func sendTasksAsync(tasks []types.VerificationTask, channel chan<- types.VerificationTask, counter *atomic.Int32, delay time.Duration) {
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
func verifyStoredTasks(t *testing.T, storedData []protocol.CCVData, expectedTasks []types.VerificationTask, expectedChain protocol.ChainSelector) {
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
	mockSetup := setupMockSourceReader(t, true)
	sourceReaders := map[protocol.ChainSelector]reader.SourceReader{
		sourceChain1: mockSetup.reader,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create and send test tasks
	testTasks := []types.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain),
		createTestVerificationTask(t, 200, sourceChain1, defaultDestChain),
	}

	var messagesSent atomic.Int32
	sendTasksAsync(testTasks, mockSetup.channel, &messagesSent, 10*time.Millisecond)

	// Wait for processing and verify results
	waitForMessages(ts, len(testTasks))

	err = v.Stop()
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
	mockSetup1 := setupMockSourceReader(t, true)
	mockSetup2 := setupMockSourceReader(t, true)
	sourceReaders := map[protocol.ChainSelector]reader.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
	}

	// Create and start verifier
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create test tasks for both sources
	tasksSource1 := []types.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain),
		createTestVerificationTask(t, 101, sourceChain1, defaultDestChain),
	}
	tasksSource2 := []types.VerificationTask{
		createTestVerificationTask(t, 200, sourceChain2, defaultDestChain),
		createTestVerificationTask(t, 201, sourceChain2, defaultDestChain),
	}

	// Send tasks from both sources
	var messagesSent1, messagesSent2 atomic.Int32
	sendTasksAsync(tasksSource1, mockSetup1.channel, &messagesSent1, 5*time.Millisecond)
	sendTasksAsync(tasksSource2, mockSetup2.channel, &messagesSent2, 7*time.Millisecond)

	// Wait for all messages to be processed
	totalMessages := len(tasksSource1) + len(tasksSource2)
	waitForMessages(ts, totalMessages)

	err = v.Stop()
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
	mockSetup1 := setupMockSourceReader(t, true)
	mockSetup2 := setupMockSourceReader(t, false)
	sourceReaders := map[protocol.ChainSelector]reader.SourceReader{
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
	tasksSource1 := []types.VerificationTask{
		createTestVerificationTask(t, 100, sourceChain1, defaultDestChain),
		createTestVerificationTask(t, 101, sourceChain1, defaultDestChain),
	}

	sendTasksAsync(tasksSource1, mockSetup1.channel, nil, 5*time.Millisecond)
	waitForMessages(ts, len(tasksSource1))

	err = v.Stop()
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
		readers     map[protocol.ChainSelector]reader.SourceReader
		name        string
		expectError string
		config      types.CoordinatorConfig
	}{
		{
			name:        "no source readers",
			config:      createCoordinatorConfig("test-no-sources", map[protocol.ChainSelector]string{}),
			readers:     map[protocol.ChainSelector]reader.SourceReader{},
			expectError: "at least one source reader is required",
		},
		{
			name: "mismatched source config and readers",
			config: createCoordinatorConfig("test-mismatch", map[protocol.ChainSelector]string{
				sourceChain1: "0x1234",
				sourceChain2: "0x5678",
			}),
			readers: func() map[protocol.ChainSelector]reader.SourceReader {
				// Create a mock that only expects VerificationTaskChannel call
				mockReader := verifier_mocks.NewMockSourceReader(t)
				mockCh := make(chan types.VerificationTask)
				mockReader.EXPECT().VerificationTaskChannel().Return((<-chan types.VerificationTask)(mockCh))
				return map[protocol.ChainSelector]reader.SourceReader{
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

func TestMultiSourceVerifier_HealthCheck(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	config := createCoordinatorConfig("test-health-check", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		sourceChain2: "0x5678",
	})

	// Create mock source readers with health check expectations
	mockSetup1 := setupMockSourceReader(t, false)
	mockSetup2 := setupMockSourceReader(t, false)

	// Set up health check expectations - one healthy, one unhealthy
	mockSetup1.reader.EXPECT().HealthCheck(mock.Anything).Return(nil).Maybe()
	mockSetup2.reader.EXPECT().HealthCheck(mock.Anything).Return(assert.AnError).Maybe()

	sourceReaders := map[protocol.ChainSelector]reader.SourceReader{
		sourceChain1: mockSetup1.reader,
		sourceChain2: mockSetup2.reader,
	}

	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	// Start the verifier
	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Health check should fail if any source reader is unhealthy
	err = v.HealthCheck(ts.ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source reader unhealthy for chain")

	// Stop the verifier
	err = v.Stop()
	require.NoError(t, err)
}

func TestVerificationErrorHandling(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.cleanup()

	// Create config with only one source chain configured
	config := createCoordinatorConfig("test-error-handling", map[protocol.ChainSelector]string{
		sourceChain1: "0x1234",
		// unconfiguredChain is intentionally not included in the config
	})

	// Set up mock source readers for both chains
	mockSetup1 := setupMockSourceReader(t, true)
	mockSetup2 := setupMockSourceReader(t, true)

	// Create source readers map that includes the unconfigured chain
	// This simulates having a reader for a chain that's not in the coordinator config
	sourceReaders := map[protocol.ChainSelector]reader.SourceReader{
		sourceChain1:      mockSetup1.reader,
		unconfiguredChain: mockSetup2.reader,
	}

	// Create and start verifier - this should succeed even with extra readers
	v, err := createVerificationCoordinator(ts, config, sourceReaders)
	require.NoError(t, err)

	err = v.Start(ts.ctx)
	require.NoError(t, err)

	// Create test verification tasks
	validTask := createTestVerificationTask(t, 100, sourceChain1, defaultDestChain)
	invalidTask := createTestVerificationTask(t, 200, unconfiguredChain, defaultDestChain)

	// Send tasks
	sendTasksAsync([]types.VerificationTask{validTask}, mockSetup1.channel, nil, 10*time.Millisecond)
	sendTasksAsync([]types.VerificationTask{invalidTask}, mockSetup2.channel, nil, 10*time.Millisecond)

	// Wait for valid task to be processed
	waitForMessages(ts, 1)

	// Give some time for error processing
	time.Sleep(50 * time.Millisecond)

	err = v.Stop()
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
