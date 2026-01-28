package executionchecker

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// mockDestinationReader is a mock implementation of chainaccess.DestinationReader.
type mockDestinationReader struct {
	mock.Mock
}

// Start implements services.Service interface.
func (m *mockDestinationReader) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Close implements services.Service interface.
func (m *mockDestinationReader) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Name implements services.Service interface.
func (m *mockDestinationReader) Name() string {
	args := m.Called()
	return args.String(0)
}

// Ready implements services.Service interface.
func (m *mockDestinationReader) Ready() error {
	args := m.Called()
	return args.Error(0)
}

// HealthReport implements services.Service interface.
func (m *mockDestinationReader) HealthReport() map[string]error {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(map[string]error)
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (protocol.CCVAddressInfo, error) {
	args := m.Called(ctx, message)
	return args.Get(0).(protocol.CCVAddressInfo), args.Error(1)
}

func (m *mockDestinationReader) GetMessageSuccess(ctx context.Context, message protocol.Message) (bool, error) {
	args := m.Called(ctx, message)
	return args.Bool(0), args.Error(1)
}

func (m *mockDestinationReader) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]protocol.Bytes16), args.Error(1)
}

func (m *mockDestinationReader) GetExecutionAttempts(ctx context.Context, message protocol.Message) ([]protocol.ExecutionAttempt, error) {
	args := m.Called(ctx, message)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]protocol.ExecutionAttempt), args.Error(1)
}

const (
	testSourceChain = protocol.ChainSelector(1)
	testDestChain   = protocol.ChainSelector(2)
)

// newTestExecutionCheckerService creates a new ExecutionCheckerService for testing.
func newTestExecutionCheckerService(destReaders map[protocol.ChainSelector]chainaccess.DestinationReader) *AttemptCheckerService {
	return &AttemptCheckerService{
		destinationReaders: destReaders,
		lggr:               logger.Nop(),
	}
}

// createTestMessage creates a test message with the given parameters.
func createTestMessage(t *testing.T, sequenceNumber protocol.SequenceNumber, sourceChain, destChain protocol.ChainSelector, gasLimit uint32) protocol.Message {
	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	// Create test CCV and executor addresses for computing the hash
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22

	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{protocol.UnknownAddress(ccvAddr)},
		protocol.UnknownAddress(executorAddr),
	)
	require.NoError(t, err)

	message, err := protocol.NewMessage(
		sourceChain,
		destChain,
		sequenceNumber,
		onRampAddr,
		offRampAddr,
		0,                  // finality
		gasLimit,           // executionGasLimit
		gasLimit,           // ccipReceiveGasLimit
		ccvAndExecutorHash, // ccvAndExecutorHash
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		nil,                 // token transfer
	)
	require.NoError(t, err)
	return *message
}

// createTestVerifierResult creates a test verifier result.
func createTestVerifierResult(t *testing.T, message protocol.Message, verifierDestAddr protocol.UnknownAddress, ccvData []byte) protocol.VerifierResult {
	messageID, err := message.MessageID()
	require.NoError(t, err)

	return protocol.VerifierResult{
		MessageID:              messageID,
		Message:                message,
		MessageCCVAddresses:    []protocol.UnknownAddress{verifierDestAddr},
		MessageExecutorAddress: protocol.UnknownAddress([]byte("executor_address")),
		CCVData:                protocol.ByteSlice(ccvData),
		Timestamp:              time.Now(),
		VerifierSourceAddress:  protocol.UnknownAddress([]byte("verifier_source")),
		VerifierDestAddress:    verifierDestAddr,
	}
}

// createTestExecutionAttempt creates a test execution attempt.
func createTestExecutionAttempt(message protocol.Message, ccvs []protocol.UnknownAddress, ccvData [][]byte, gasLimit *big.Int) protocol.ExecutionAttempt {
	return protocol.ExecutionAttempt{
		Report: protocol.AbstractAggregatedReport{
			CCVS:    ccvs,
			CCVData: ccvData,
			Message: message,
		},
		TransactionGasLimit: gasLimit,
	}
}

func TestExecutionCheckerService_HasHonestAttempt(t *testing.T) {
	t.Run("no execution attempts returns false", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		verifierResults := []protocol.VerifierResult{}
		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return([]protocol.ExecutionAttempt{}, nil)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})

	t.Run("honest execution attempt found returns true", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_ccv_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)
		verifierResults := []protocol.VerifierResult{verifierResult}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{ccvAddr},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(100000),
		)

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return([]protocol.ExecutionAttempt{attempt}, nil)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})

	t.Run("dishonest execution attempt returns false", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_ccv_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)
		verifierResults := []protocol.VerifierResult{verifierResult}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{ccvAddr},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		// Create attempt with wrong CCV data
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{[]byte("wrong_ccv_data")},
			big.NewInt(100000),
		)

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return([]protocol.ExecutionAttempt{attempt}, nil)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})

	t.Run("dishonest gas limit returns false", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_ccv_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)
		verifierResults := []protocol.VerifierResult{verifierResult}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{ccvAddr},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		// Create attempt with gas limit less than execution gas limit (dishonest)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(50000), // Less than message.ExecutionGasLimit (100000)
		)

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return([]protocol.ExecutionAttempt{attempt}, nil)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})

	t.Run("error from GetExecutionAttempts returns error", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		verifierResults := []protocol.VerifierResult{}
		ccvInfo := protocol.CCVAddressInfo{}

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return(nil, assert.AnError)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.Error(t, err)
		assert.False(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})

	t.Run("multiple attempts with mixed honesty", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_ccv_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)
		verifierResults := []protocol.VerifierResult{verifierResult}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{ccvAddr},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		// First attempt is dishonest (wrong CCV data)
		dishonestAttempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{[]byte("wrong_data")},
			big.NewInt(100000),
		)

		// Second attempt is honest
		honestAttempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(100000),
		)

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return([]protocol.ExecutionAttempt{dishonestAttempt, honestAttempt}, nil)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})

	t.Run("attempt with mismatched message ID is skipped", func(t *testing.T) {
		mockReader := new(mockDestinationReader)
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{
			testDestChain: mockReader,
		})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		otherMessage := createTestMessage(t, 2, testSourceChain, testDestChain, 100000) // Different sequence number

		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_ccv_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)
		verifierResults := []protocol.VerifierResult{verifierResult}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{ccvAddr},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		// Attempt with different message ID
		attempt := createTestExecutionAttempt(
			otherMessage, // Different message
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(100000),
		)

		mockReader.On("GetExecutionAttempts", mock.Anything, message).
			Return([]protocol.ExecutionAttempt{attempt}, nil)

		ctx := context.Background()
		hasAttempt, err := service.HasHonestAttempt(ctx, message, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, hasAttempt)
		mockReader.AssertExpectations(t)
	})
}

func TestExecutionCheckerService_isHonestCallData(t *testing.T) {
	t.Run("valid required and optional CCVs", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		optionalCCV, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		optionalCCVData := []byte("optional_data")

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
			createTestVerifierResult(t, message, optionalCCV, optionalCCVData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{optionalCCV},
			OptionalThreshold: 1,
		}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV},
			[][]byte{requiredCCVData, optionalCCVData},
			big.NewInt(100000),
		)

		honest, err := service.isHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest)
	})

	t.Run("invalid required CCVs", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		// Attempt with wrong CCV data
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV},
			[][]byte{[]byte("wrong_data")},
			big.NewInt(100000),
		)

		honest, err := service.isHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest)
	})

	t.Run("invalid optional CCVs", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		optionalCCV, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		optionalCCVData := []byte("optional_data")

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
			createTestVerifierResult(t, message, optionalCCV, optionalCCVData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{optionalCCV},
			OptionalThreshold: 1, // Need at least 1 valid optional CCV
		}

		// Attempt with wrong optional CCV data
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV},
			[][]byte{requiredCCVData, []byte("wrong_optional_data")},
			big.NewInt(100000),
		)

		honest, err := service.isHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest)
	})

	t.Run("message IDs don't match", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		otherMessage := createTestMessage(t, 2, testSourceChain, testDestChain, 100000)

		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_data")
		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, ccvAddr, ccvData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{ccvAddr},
			OptionalCCVs:      []protocol.UnknownAddress{},
			OptionalThreshold: 0,
		}

		attempt := createTestExecutionAttempt(
			otherMessage, // Different message
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(100000),
		)

		honest, err := service.isHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.Error(t, err)
		assert.False(t, honest)
	})

	t.Run("optional CCV threshold met", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		optionalCCV1, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)
		optionalCCV2, err := protocol.NewUnknownAddressFromHex("0x3333333333333333333333333333333333333333")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		optionalCCV1Data := []byte("optional1_data")
		optionalCCV2Data := []byte("optional2_data")

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
			createTestVerifierResult(t, message, optionalCCV1, optionalCCV1Data),
			createTestVerifierResult(t, message, optionalCCV2, optionalCCV2Data),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{optionalCCV1, optionalCCV2},
			OptionalThreshold: 1, // Need at least 1 valid optional CCV
		}

		// Attempt with only one valid optional CCV (meets threshold)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV1, optionalCCV2},
			[][]byte{requiredCCVData, optionalCCV1Data, []byte("wrong_optional2_data")},
			big.NewInt(100000),
		)

		honest, err := service.isHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest) // Should be honest because threshold is met
	})
}

func TestExecutionCheckerService_isHonestGasLimit(t *testing.T) {
	t.Run("gas limit less than execution gas limit", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(50000), // Less than 100000 (executionGasLimit > transactionGasLimit, so dishonest)
		)

		honest := service.isHonestGasLimit(message, attempt)

		assert.False(t, honest) // Transaction gas limit must be >= executionGasLimit to be honest
	})

	t.Run("gas limit equal to execution gas limit", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(100000), // Equal to execution gas limit
		)

		honest := service.isHonestGasLimit(message, attempt)

		assert.True(t, honest)
	})

	t.Run("gas limit greater than execution gas limit", func(t *testing.T) {
		service := newTestExecutionCheckerService(map[protocol.ChainSelector]chainaccess.DestinationReader{})

		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(150000), // Greater than 100000 (executionGasLimit < transactionGasLimit, so honest)
		)

		honest := service.isHonestGasLimit(message, attempt)

		assert.True(t, honest) // Transaction gas limit >= executionGasLimit is honest
	})
}

func Test_honestCCVs(t *testing.T) {
	t.Run("meets threshold", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)

		// mapResultsToCCVs uses string keys (address.String())
		ccvToKnownResults := map[string][]protocol.VerifierResult{
			verifierResult.VerifierDestAddress.String(): {verifierResult},
		}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(100000),
		)

		attemptCCVs := []string{ccvAddr.String()}
		messageCCVs := []string{ccvAddr.String()}
		threshold := 1

		honest := honestCCVs(attempt, attemptCCVs, messageCCVs, threshold, ccvToKnownResults)

		assert.True(t, honest)
	})

	t.Run("does not meet threshold", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)

		// mapResultsToCCVs uses string keys (address.String())
		ccvToKnownResults := map[string][]protocol.VerifierResult{
			verifierResult.VerifierDestAddress.String(): {verifierResult},
		}

		// Attempt with wrong CCV data
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{[]byte("wrong_data")},
			big.NewInt(100000),
		)

		attemptCCVs := []string{ccvAddr.String()}
		messageCCVs := []string{ccvAddr.String()}
		threshold := 1

		honest := honestCCVs(attempt, attemptCCVs, messageCCVs, threshold, ccvToKnownResults)

		assert.False(t, honest)
	})

	t.Run("CCV not in attempt", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr1, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		ccvAddr2, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)

		ccvToKnownResults := map[string][]protocol.VerifierResult{}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr1},
			[][]byte{[]byte("data")},
			big.NewInt(100000),
		)

		attemptCCVs := []string{ccvAddr1.String()}
		messageCCVs := []string{ccvAddr2.String()} // Different CCV
		threshold := 1

		honest := honestCCVs(attempt, attemptCCVs, messageCCVs, threshold, ccvToKnownResults)

		assert.False(t, honest)
	})

	t.Run("CCV index out of bounds", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvToKnownResults := map[string][]protocol.VerifierResult{}

		// Attempt with CCVS but no CCVData
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{}, // Empty CCVData
			big.NewInt(100000),
		)

		attemptCCVs := []string{ccvAddr.String()}
		messageCCVs := []string{ccvAddr.String()}
		threshold := 1

		honest := honestCCVs(attempt, attemptCCVs, messageCCVs, threshold, ccvToKnownResults)

		assert.False(t, honest)
	})
}

func Test_mapResultsToCCVs(t *testing.T) {
	t.Run("maps verifier results correctly", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr1, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		ccvAddr2, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, ccvAddr1, []byte("data1")),
			createTestVerifierResult(t, message, ccvAddr1, []byte("data2")), // Same CCV, different data
			createTestVerifierResult(t, message, ccvAddr2, []byte("data3")),
		}

		result := mapResultsToCCVs(verifierResults)

		// mapResultsToCCVs uses string keys (address.String())
		// Since verifierResults[0] and verifierResults[1] have the same VerifierDestAddress value,
		// they should be grouped together under the same key
		addr1Key := verifierResults[0].VerifierDestAddress.String()
		addr2Key := verifierResults[2].VerifierDestAddress.String()

		assert.Len(t, result[addr1Key], 2, "Should have 2 results for ccvAddr1")
		assert.Len(t, result[addr2Key], 1, "Should have 1 result for ccvAddr2")
	})

	t.Run("empty verifier results", func(t *testing.T) {
		verifierResults := []protocol.VerifierResult{}
		result := mapResultsToCCVs(verifierResults)
		assert.Empty(t, result)
	})
}

func Test_assertMessageIDsMatch(t *testing.T) {
	t.Run("matching message IDs", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(100000),
		)

		err := assertMessageIDsMatch(message, attempt)

		assert.NoError(t, err)
	})

	t.Run("non-matching message IDs", func(t *testing.T) {
		message1 := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		message2 := createTestMessage(t, 2, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message2,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(100000),
		)

		err := assertMessageIDsMatch(message1, attempt)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "message ids do not match")
	})
}

func Test_unknownAddressArrayToStrings(t *testing.T) {
	t.Run("converts addresses correctly", func(t *testing.T) {
		addr1, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		addr2, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)

		addresses := []protocol.UnknownAddress{addr1, addr2}
		result := unknownAddressArrayToStrings(addresses)

		// After fixing the bug, the function now returns the correct length
		assert.Len(t, result, len(addresses))
		assert.Equal(t, addr1.String(), result[0])
		assert.Equal(t, addr2.String(), result[1])
	})

	t.Run("empty array", func(t *testing.T) {
		addresses := []protocol.UnknownAddress{}
		result := unknownAddressArrayToStrings(addresses)

		assert.Empty(t, result)
	})
}
