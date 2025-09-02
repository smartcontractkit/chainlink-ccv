package verifier_test

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

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol/verifier"
	"github.com/smartcontractkit/chainlink-ccv/protocol/verifier/mocks"
)

func createTestMessage(messageID [32]byte, seqNum cciptypes.SeqNum, sourceChainSelector, destChainSelector cciptypes.ChainSelector) common.Any2AnyVerifierMessage {
	return common.Any2AnyVerifierMessage{
		Header: common.MessageHeader{
			MessageID:           messageID,
			SourceChainSelector: sourceChainSelector,
			DestChainSelector:   destChainSelector,
			SequenceNumber:      seqNum,
		},
		Sender:         common.UnknownAddress([]byte("0x9999")),
		OnRampAddress:  common.UnknownAddress([]byte("0x8888")),
		Data:           []byte("test data"),
		Receiver:       common.UnknownAddress([]byte("0x7777")),
		FeeToken:       common.UnknownAddress([]byte("0x6666")),
		FeeTokenAmount: big.NewInt(1000),
		FeeValueJuels:  big.NewInt(500),
		TokenTransfer: common.TokenTransfer{
			SourceTokenAddress: common.UnknownAddress([]byte("0x5555")),
			DestTokenAddress:   common.UnknownAddress([]byte("0x4444")),
			ExtraData:          []byte("token data"),
			Amount:             big.NewInt(2000),
		},
		VerifierReceipts: []common.Receipt{
			{
				Issuer:            common.UnknownAddress([]byte("0x3333")),
				FeeTokenAmount:    big.NewInt(100),
				DestGasLimit:      50000,
				DestBytesOverhead: 1024,
				ExtraArgs:         []byte("receipt args"),
			},
		},
		ExecutorReceipt: &common.Receipt{
			Issuer:            common.UnknownAddress([]byte("0x2222")),
			FeeTokenAmount:    big.NewInt(200),
			DestGasLimit:      60000,
			DestBytesOverhead: 2048,
			ExtraArgs:         []byte("executor args"),
		},
		TokenReceipt: &common.Receipt{
			Issuer:            common.UnknownAddress([]byte("0x1111")),
			FeeTokenAmount:    big.NewInt(300),
			DestGasLimit:      70000,
			DestBytesOverhead: 4096,
			ExtraArgs:         []byte("token args"),
		},
		ExtraArgs: []byte("extra args"),
	}
}

func createTestVerificationTask(messageID [32]byte, seqNum cciptypes.SeqNum, sourceChainSelector, destChainSelector cciptypes.ChainSelector) common.VerificationTask {
	message := createTestMessage(messageID, seqNum, sourceChainSelector, destChainSelector)
	return common.VerificationTask{
		Message:      message,
		ReceiptBlobs: [][]byte{[]byte("receipt blob 1"), []byte("receipt blob 2")},
	}
}

func TestVerifier(t *testing.T) {
	lggr := logger.Test(t)
	storage := storageaccess.NewInMemoryOffchainStorage(lggr)

	// Generate test signing key
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, err := verifier.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)

	coordinatorConfig := verifier.CoordinatorConfig{
		CoordinatorID: "test-custom-mockery-verifier",
		SourceConfigs: []verifier.SourceConfig{
			{
				ChainSelector:   cciptypes.ChainSelector(42),
				VerifierAddress: common.UnknownAddress([]byte("0x1234")),
			},
		},
		ProcessingChannelSize: 10,
		ProcessingTimeout:     time.Second,
		MaxBatchSize:          100,
	}

	// Create mockery-generated mock
	mockSourceReader := mocks.NewMockSourceReader(t)

	// Set up channels for async behavior
	verificationTaskCh := make(chan common.VerificationTask, 10)
	var messagesSent atomic.Int32 // Use atomic for thread safety

	// Set up expectations with custom behavior
	mockSourceReader.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader.EXPECT().Stop().Run(func() {
		close(verificationTaskCh)
	}).Return(nil)
	mockSourceReader.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(verificationTaskCh))

	// Create verifier implementation
	commitVerifier := verifier.NewCommitVerifier(coordinatorConfig, signer, lggr)

	// Create coordinator
	sourceReaders := map[cciptypes.ChainSelector]verifier.SourceReader{
		cciptypes.ChainSelector(42): mockSourceReader,
	}
	v, err := verifier.NewVerificationCoordinator(
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithVerifier(commitVerifier),
		verifier.WithStorage(storage),
		verifier.WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start verifier
	err = v.Start(ctx)
	require.NoError(t, err)

	// Create test verification tasks
	testTasks := []common.VerificationTask{
		createTestVerificationTask([32]byte{1, 2, 3}, 100, 42, 100),
		createTestVerificationTask([32]byte{4, 5, 6}, 200, 42, 100),
	}

	// Send verification tasks asynchronously
	go func() {
		for _, task := range testTasks {
			verificationTaskCh <- task
			messagesSent.Add(1)
			time.Sleep(10 * time.Millisecond) // Small delay between messages
		}
	}()

	// Wait for all messages to be processed
	for i := 0; i < len(testTasks); i++ {
		err = storage.WaitForStore(ctx)
		require.NoError(t, err)
	}

	// Stop verifier
	err = v.Stop()
	require.NoError(t, err)

	// Verify all data was stored
	storedData, err := storage.GetAllCCVData(coordinatorConfig.SourceConfigs[0].VerifierAddress)
	require.NoError(t, err)
	assert.Len(t, storedData, len(testTasks))
	assert.Equal(t, int(messagesSent.Load()), len(testTasks))

	// Verify message IDs match
	expectedIDs := make(map[[32]byte]bool)
	for _, task := range testTasks {
		expectedIDs[task.Message.Header.MessageID] = true
	}

	for _, data := range storedData {
		assert.True(t, expectedIDs[data.MessageID], "Unexpected message ID: %x", data.MessageID)
	}
}

func TestMultiSourceVerifier_TwoSources(t *testing.T) {
	lggr := logger.Test(t)
	storage := storageaccess.NewInMemoryOffchainStorage(lggr)

	// Generate test signing key
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, err := verifier.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)

	// Define source chains
	sourceChain1 := cciptypes.ChainSelector(42)
	sourceChain2 := cciptypes.ChainSelector(84)
	destChain := cciptypes.ChainSelector(100)

	coordinatorConfig := verifier.CoordinatorConfig{
		CoordinatorID: "test-multi-source-verifier",
		SourceConfigs: []verifier.SourceConfig{
			{
				ChainSelector:   sourceChain1,
				VerifierAddress: common.UnknownAddress([]byte("0x1234")),
			},
			{
				ChainSelector:   sourceChain2,
				VerifierAddress: common.UnknownAddress([]byte("0x5678")),
			},
		},
		ProcessingChannelSize: 10,
		ProcessingTimeout:     time.Second,
		MaxBatchSize:          100,
	}

	// Create mock source readers
	mockSourceReader1 := mocks.NewMockSourceReader(t)
	mockSourceReader2 := mocks.NewMockSourceReader(t)

	// Set up channels for async behavior
	taskCh1 := make(chan common.VerificationTask, 10)
	taskCh2 := make(chan common.VerificationTask, 10)
	var messagesSent1, messagesSent2 atomic.Int32

	// Set up expectations for source reader 1
	mockSourceReader1.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader1.EXPECT().Stop().Run(func() {
		close(taskCh1)
	}).Return(nil)
	mockSourceReader1.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(taskCh1))

	// Set up expectations for source reader 2
	mockSourceReader2.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader2.EXPECT().Stop().Run(func() {
		close(taskCh2)
	}).Return(nil)
	mockSourceReader2.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(taskCh2))

	// Create verifier implementation
	commitVerifier := verifier.NewCommitVerifier(coordinatorConfig, signer, lggr)

	// Create verifier with multiple source readers
	sourceReaders := map[cciptypes.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSourceReader1,
		sourceChain2: mockSourceReader2,
	}

	v, err := verifier.NewVerificationCoordinator(
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithVerifier(commitVerifier),
		verifier.WithStorage(storage),
		verifier.WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start verifier
	err = v.Start(ctx)
	require.NoError(t, err)

	// Create test verification tasks for both sources
	tasksSource1 := []common.VerificationTask{
		createTestVerificationTask([32]byte{1, 1, 1}, 100, sourceChain1, destChain),
		createTestVerificationTask([32]byte{1, 2, 3}, 101, sourceChain1, destChain),
	}

	tasksSource2 := []common.VerificationTask{
		createTestVerificationTask([32]byte{2, 1, 1}, 200, sourceChain2, destChain),
		createTestVerificationTask([32]byte{2, 2, 3}, 201, sourceChain2, destChain),
	}

	// Send verification tasks from both sources concurrently
	go func() {
		for _, task := range tasksSource1 {
			taskCh1 <- task
			messagesSent1.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		for _, task := range tasksSource2 {
			taskCh2 <- task
			messagesSent2.Add(1)
			time.Sleep(7 * time.Millisecond)
		}
	}()

	// Wait for all messages to be processed
	totalMessages := len(tasksSource1) + len(tasksSource2)
	for i := 0; i < totalMessages; i++ {
		err = storage.WaitForStore(ctx)
		require.NoError(t, err)
	}

	// Stop verifier
	err = v.Stop()
	require.NoError(t, err)

	// Verify all data was stored
	storedDataSource1, err := storage.GetAllCCVData(coordinatorConfig.SourceConfigs[0].VerifierAddress)
	require.NoError(t, err)
	storedDataSource2, err := storage.GetAllCCVData(coordinatorConfig.SourceConfigs[1].VerifierAddress)
	require.NoError(t, err)

	assert.Len(t, storedDataSource1, len(tasksSource1))
	assert.Len(t, storedDataSource2, len(tasksSource2))
	assert.Equal(t, int(messagesSent1.Load()), len(tasksSource1))
	assert.Equal(t, int(messagesSent2.Load()), len(tasksSource2))

	// Verify message IDs match for source 1
	expectedIDs1 := make(map[[32]byte]bool)
	for _, task := range tasksSource1 {
		expectedIDs1[task.Message.Header.MessageID] = true
	}
	for _, data := range storedDataSource1 {
		assert.True(t, expectedIDs1[data.MessageID], "Unexpected message ID from source 1: %x", data.MessageID)
		assert.Equal(t, sourceChain1, data.SourceChainSelector)
	}

	// Verify message IDs match for source 2
	expectedIDs2 := make(map[[32]byte]bool)
	for _, task := range tasksSource2 {
		expectedIDs2[task.Message.Header.MessageID] = true
	}
	for _, data := range storedDataSource2 {
		assert.True(t, expectedIDs2[data.MessageID], "Unexpected message ID from source 2: %x", data.MessageID)
		assert.Equal(t, sourceChain2, data.SourceChainSelector)
	}
}

func TestMultiSourceVerifier_SingleSourceFailure(t *testing.T) {
	lggr := logger.Test(t)
	storage := storageaccess.NewInMemoryOffchainStorage(lggr)

	// Generate test signing key
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, err := verifier.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)

	// Define source chains
	sourceChain1 := cciptypes.ChainSelector(42)
	sourceChain2 := cciptypes.ChainSelector(84)
	destChain := cciptypes.ChainSelector(100)

	coordinatorConfig := verifier.CoordinatorConfig{
		CoordinatorID: "test-failure-verifier",
		SourceConfigs: []verifier.SourceConfig{
			{
				ChainSelector:   sourceChain1,
				VerifierAddress: common.UnknownAddress([]byte("0x1234")),
			},
			{
				ChainSelector:   sourceChain2,
				VerifierAddress: common.UnknownAddress([]byte("0x5678")),
			},
		},
		ProcessingChannelSize: 10,
		ProcessingTimeout:     time.Second,
		MaxBatchSize:          100,
	}

	// Create mock source readers
	mockSourceReader1 := mocks.NewMockSourceReader(t)
	mockSourceReader2 := mocks.NewMockSourceReader(t)

	// Set up channels
	taskCh1 := make(chan common.VerificationTask, 10)
	taskCh2 := make(chan common.VerificationTask, 10)

	// Source 1 works normally
	mockSourceReader1.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader1.EXPECT().Stop().Run(func() {
		close(taskCh1)
	}).Return(nil)
	mockSourceReader1.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(taskCh1))

	// Source 2 closes its channel immediately (simulating failure)
	mockSourceReader2.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader2.EXPECT().Stop().Return(nil)
	mockSourceReader2.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(taskCh2))

	// Create verifier implementation
	commitVerifier := verifier.NewCommitVerifier(coordinatorConfig, signer, lggr)

	// Create verifier
	sourceReaders := map[cciptypes.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSourceReader1,
		sourceChain2: mockSourceReader2,
	}

	v, err := verifier.NewVerificationCoordinator(
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithVerifier(commitVerifier),
		verifier.WithStorage(storage),
		verifier.WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start verifier
	err = v.Start(ctx)
	require.NoError(t, err)

	// Close source 2 channel immediately to simulate failure
	close(taskCh2)

	// Send verification tasks only to source 1
	tasksSource1 := []common.VerificationTask{
		createTestVerificationTask([32]byte{1, 1, 1}, 100, sourceChain1, destChain),
		createTestVerificationTask([32]byte{1, 2, 3}, 101, sourceChain1, destChain),
	}

	go func() {
		for _, task := range tasksSource1 {
			taskCh1 <- task
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Wait for verification tasks from source 1 to be processed
	for i := 0; i < len(tasksSource1); i++ {
		err = storage.WaitForStore(ctx)
		require.NoError(t, err)
	}

	// Stop verifier
	err = v.Stop()
	require.NoError(t, err)

	// Verify only source 1 data was stored
	storedDataSource1, err := storage.GetAllCCVData(coordinatorConfig.SourceConfigs[0].VerifierAddress)
	require.NoError(t, err)
	storedDataSource2, err := storage.GetAllCCVData(coordinatorConfig.SourceConfigs[1].VerifierAddress)
	require.NoError(t, err)

	assert.Len(t, storedDataSource1, len(tasksSource1))
	assert.Len(t, storedDataSource2, 0) // No messages from failed source
}

func TestMultiSourceVerifier_ValidationErrors(t *testing.T) {
	lggr := logger.Test(t)

	tests := []struct {
		name        string
		config      verifier.CoordinatorConfig
		readers     map[cciptypes.ChainSelector]verifier.SourceReader
		expectError string
	}{
		{
			name: "no source readers",
			config: verifier.CoordinatorConfig{
				CoordinatorID: "test-no-sources",
				SourceConfigs: []verifier.SourceConfig{},
			},
			readers:     map[cciptypes.ChainSelector]verifier.SourceReader{},
			expectError: "at least one source reader is required",
		},
		{
			name: "mismatched source config and readers",
			config: verifier.CoordinatorConfig{
				CoordinatorID: "test-mismatch",
				SourceConfigs: []verifier.SourceConfig{
					{ChainSelector: 42, VerifierAddress: common.UnknownAddress([]byte("0x1234"))},
					{ChainSelector: 84, VerifierAddress: common.UnknownAddress([]byte("0x5678"))},
				},
			},
			readers: func() map[cciptypes.ChainSelector]verifier.SourceReader {
				mockReader := mocks.NewMockSourceReader(t)
				mockCh := make(chan common.VerificationTask)
				mockReader.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(mockCh))
				return map[cciptypes.ChainSelector]verifier.SourceReader{
					42: mockReader, // Missing reader for chain 84
				}
			}(),
			expectError: "source reader not found for chain selector 84",
		},
		{
			name: "duplicate chain selectors in config",
			config: verifier.CoordinatorConfig{
				CoordinatorID: "test-duplicates",
				SourceConfigs: []verifier.SourceConfig{
					{ChainSelector: 42, VerifierAddress: common.UnknownAddress([]byte("0x1234"))},
					{ChainSelector: 42, VerifierAddress: common.UnknownAddress([]byte("0x5678"))}, // Duplicate
				},
			},
			readers: func() map[cciptypes.ChainSelector]verifier.SourceReader {
				mockReader := mocks.NewMockSourceReader(t)
				mockCh := make(chan common.VerificationTask)
				mockReader.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(mockCh))
				return map[cciptypes.ChainSelector]verifier.SourceReader{
					42: mockReader,
				}
			}(),
			expectError: "duplicate chain selector 42 in source configs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test signing key
			privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
			require.NoError(t, err)
			privateKeyBytes := crypto.FromECDSA(privateKey)
			signer, err := verifier.NewECDSAMessageSigner(privateKeyBytes)
			require.NoError(t, err)

			storage := storageaccess.NewInMemoryOffchainStorage(lggr)

			// Create verifier implementation
			commitVerifier := verifier.NewCommitVerifier(tt.config, signer, lggr)

			_, err = verifier.NewVerificationCoordinator(
				verifier.WithConfig(tt.config),
				verifier.WithSourceReaders(tt.readers),
				verifier.WithVerifier(commitVerifier),
				verifier.WithStorage(storage),
				verifier.WithLogger(lggr),
			)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestMultiSourceVerifier_HealthCheck(t *testing.T) {
	lggr := logger.Test(t)
	storage := storageaccess.NewInMemoryOffchainStorage(lggr)

	// Generate test signing key
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	signer, err := verifier.NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)

	// Define source chains
	sourceChain1 := cciptypes.ChainSelector(42)
	sourceChain2 := cciptypes.ChainSelector(84)

	coordinatorConfig := verifier.CoordinatorConfig{
		CoordinatorID: "test-health-check",
		SourceConfigs: []verifier.SourceConfig{
			{ChainSelector: sourceChain1, VerifierAddress: common.UnknownAddress([]byte("0x1234"))},
			{ChainSelector: sourceChain2, VerifierAddress: common.UnknownAddress([]byte("0x5678"))},
		},
	}

	// Create mock source readers
	mockSourceReader1 := mocks.NewMockSourceReader(t)
	mockSourceReader2 := mocks.NewMockSourceReader(t)

	// Set up channel expectations (required for sourceState creation)
	mockCh1 := make(chan common.VerificationTask)
	mockCh2 := make(chan common.VerificationTask)
	mockSourceReader1.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(mockCh1))
	mockSourceReader2.EXPECT().MessagesChannel().Return((<-chan common.VerificationTask)(mockCh2))

	// Set up health check expectations - one will be healthy, one unhealthy
	// The health check will fail on the first unhealthy reader it encounters
	mockSourceReader1.EXPECT().HealthCheck(mock.Anything).Return(nil).Maybe()
	mockSourceReader2.EXPECT().HealthCheck(mock.Anything).Return(assert.AnError).Maybe()

	sourceReaders := map[cciptypes.ChainSelector]verifier.SourceReader{
		sourceChain1: mockSourceReader1,
		sourceChain2: mockSourceReader2,
	}

	// Create verifier implementation
	commitVerifier := verifier.NewCommitVerifier(coordinatorConfig, signer, lggr)

	v, err := verifier.NewVerificationCoordinator(
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithVerifier(commitVerifier),
		verifier.WithStorage(storage),
		verifier.WithLogger(lggr),
	)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the verifier first
	mockSourceReader1.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader2.EXPECT().Start(mock.Anything).Return(nil)
	err = v.Start(ctx)
	require.NoError(t, err)

	// Health check should fail if any source reader is unhealthy
	err = v.HealthCheck(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source reader unhealthy for chain")

	// Stop the verifier
	mockSourceReader1.EXPECT().Stop().Return(nil)
	mockSourceReader2.EXPECT().Stop().Return(nil)
	err = v.Stop()
	require.NoError(t, err)
}
