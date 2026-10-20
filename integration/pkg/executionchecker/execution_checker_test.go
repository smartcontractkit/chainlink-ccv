package executionchecker

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	testSourceChain = protocol.ChainSelector(1)
	testDestChain   = protocol.ChainSelector(2)
)

// createTestMessage creates a test message with the given parameters.
func createTestMessage(t *testing.T, sequenceNumber protocol.SequenceNumber, sourceChain, destChain protocol.ChainSelector, gasLimit uint32) protocol.Message {
	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

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
		0,
		gasLimit,
		gasLimit,
		ccvAndExecutorHash,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		nil,
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

func TestIsHonestCallData(t *testing.T) {
	t.Run("valid required and optional CCVs", func(t *testing.T) {
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

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest)
	})

	t.Run("invalid required CCVs", func(t *testing.T) {
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

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV},
			[][]byte{[]byte("wrong_data")},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest)
	})

	t.Run("invalid optional CCVs", func(t *testing.T) {
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
			[][]byte{requiredCCVData, []byte("wrong_optional_data")},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest)
	})

	t.Run("message IDs don't match", func(t *testing.T) {
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
			otherMessage,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{ccvData},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.Error(t, err)
		assert.False(t, honest)
	})

	t.Run("optional CCV threshold met", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		optionalCCV1, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)
		optionalCCV2, err := protocol.NewUnknownAddressFromHex("0x3333333333333333333333333333333333333333")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		optionalCCV1Data := []byte("optional1_data")

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
			createTestVerifierResult(t, message, optionalCCV1, optionalCCV1Data),
			createTestVerifierResult(t, message, optionalCCV2, []byte("optional2_data")),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{optionalCCV1, optionalCCV2},
			OptionalThreshold: 1,
		}

		// optionalCCV2 is not submitted, because optionalCCV1 already meets the threshold.
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV1},
			[][]byte{requiredCCVData, optionalCCV1Data},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest)
	})

	// A submitted entry that the OffRamp selection does not use is not honest.
	t.Run("unused optional CCV entry with unknown data is not honest", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		optionalCCV1, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)
		optionalCCV2, err := protocol.NewUnknownAddressFromHex("0x3333333333333333333333333333333333333333")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		optionalCCV1Data := []byte("optional1_data")

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
			createTestVerifierResult(t, message, optionalCCV1, optionalCCV1Data),
			// No known result for optionalCCV2.
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{optionalCCV1, optionalCCV2},
			OptionalThreshold: 1,
		}

		// optionalCCV1 already meets the threshold, so the OffRamp does not use the optionalCCV2 entry.
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV1, optionalCCV2},
			[][]byte{requiredCCVData, optionalCCV1Data, bytes.Repeat([]byte{0xAB}, 4096)},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest, "an entry that the OffRamp selection does not use is not part of an honest attempt")
	})

	// A valid optional CCV entry beyond the threshold is not used by the OffRamp selection.
	t.Run("unused valid optional CCV entry beyond threshold is not honest", func(t *testing.T) {
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
			OptionalThreshold: 1,
		}

		// optionalCCV1 already meets the threshold, so the OffRamp does not use the optionalCCV2 entry.
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV1, optionalCCV2},
			[][]byte{requiredCCVData, optionalCCV1Data, optionalCCV2Data},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest, "an entry that the OffRamp selection does not use is not part of an honest attempt")
	})

	// A node that knew only B's result submits B. The attempt stays honest after A's result is known.
	t.Run("valid optional CCV that this node would not select is honest", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)
		optionalA, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)
		optionalB, err := protocol.NewUnknownAddressFromHex("0x3333333333333333333333333333333333333333")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		optionalAData := []byte("optionalA_data")
		optionalBData := []byte("optionalB_data")

		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
			createTestVerifierResult(t, message, optionalA, optionalAData),
			createTestVerifierResult(t, message, optionalB, optionalBData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{requiredCCV},
			OptionalCCVs:      []protocol.UnknownAddress{optionalA, optionalB}, // configured order: A before B
			OptionalThreshold: 1,
		}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalB},
			[][]byte{requiredCCVData, optionalBData},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest, "the OffRamp selects optionalB from this submission, and its data is known")
	})

	// The OffRamp selects the first present optional CCVs in configured order, so it selects A here.
	t.Run("optional CCV ordering: invalid CCV precedes valid one", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		optionalA, err := protocol.NewUnknownAddressFromHex("0x2222222222222222222222222222222222222222")
		require.NoError(t, err)
		optionalB, err := protocol.NewUnknownAddressFromHex("0x3333333333333333333333333333333333333333")
		require.NoError(t, err)

		validBData := []byte("optionalB_valid_data")

		verifierResults := []protocol.VerifierResult{
			// No valid result registered for optionalA: any data submitted for it is invalid.
			createTestVerifierResult(t, message, optionalB, validBData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs:      []protocol.UnknownAddress{},
			OptionalCCVs:      []protocol.UnknownAddress{optionalA, optionalB}, // configured order: A before B
			OptionalThreshold: 1,
		}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{optionalA, optionalB},
			[][]byte{[]byte("unknown_data_for_A"), validBData},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest, "the OffRamp selects optionalA, and its data is not known")
	})

	t.Run("submission order does not matter", func(t *testing.T) {
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
			[]protocol.UnknownAddress{optionalCCV, requiredCCV},
			[][]byte{optionalCCVData, requiredCCVData},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest)
	})

	t.Run("duplicate CCV entry is not honest", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs: []protocol.UnknownAddress{requiredCCV},
		}

		// The OffRamp uses only the first entry for a CCV, so the second entry is not used.
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, requiredCCV},
			[][]byte{requiredCCVData, requiredCCVData},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest)
	})

	t.Run("CCV and CCV data counts differ", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		requiredCCV, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		requiredCCVData := []byte("required_data")
		verifierResults := []protocol.VerifierResult{
			createTestVerifierResult(t, message, requiredCCV, requiredCCVData),
		}

		ccvInfo := protocol.CCVAddressInfo{
			RequiredCCVs: []protocol.UnknownAddress{requiredCCV},
		}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV},
			[][]byte{requiredCCVData, requiredCCVData},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.False(t, honest)
	})
}

func TestIsHonestGasLimit(t *testing.T) {
	abiError := func(signature string, payload ...byte) []byte {
		return append(crypto.Keccak256([]byte(signature))[:4], payload...)
	}
	padded := make([]byte, 64)

	tests := []struct {
		name             string
		failed           bool
		failureData      []byte
		gasLimit         int64
		gasLimitOverride int64
		nonCanonical     bool
		honest           bool
	}{
		{name: "succeeded", honest: true, gasLimit: 100000},
		{name: "succeeded with a low gas limit", honest: true, gasLimit: 1},
		{name: "succeeded with a nonzero override", gasLimitOverride: 1, honest: false, gasLimit: 100000},
		{name: "succeeded with a maximum override", gasLimitOverride: 4_294_967_295, honest: false, gasLimit: 100000},
		{name: "receiver error", failed: true, failureData: abiError("ReceiverError(bytes)", padded...), honest: true, gasLimit: 100000},
		{name: "receiver error below the old gas floor", failed: true, failureData: abiError("ReceiverError(bytes)", padded...), honest: true, gasLimit: 1},
		{name: "receiver error with a nonzero override", failed: true, failureData: abiError("ReceiverError(bytes)", padded...), gasLimitOverride: 300000, honest: false, gasLimit: 100000},
		{name: "empty failure data", failed: true, failureData: nil, honest: false, gasLimit: 100000},
		{name: "NotEnoughGasForCall", failed: true, failureData: abiError("NotEnoughGasForCall()"), honest: false, gasLimit: 100000},
		{name: "NoGasForCallExactCheck", failed: true, failureData: abiError("NoGasForCallExactCheck()"), honest: false, gasLimit: 100000},
		{name: "token handling error with empty data", failed: true, failureData: abiError("TokenHandlingError(address,bytes)", padded...), honest: false, gasLimit: 100000},
		{name: "token handling error with custom data", failed: true, failureData: abiError("TokenHandlingError(address,bytes)", append(make([]byte, 64), 0x01)...), honest: false, gasLimit: 100000},
		{name: "unknown error", failed: true, failureData: abiError("Unknown()"), honest: false, gasLimit: 100000},
		{name: "failure data shorter than a selector", failed: true, failureData: []byte{0x01}, honest: false, gasLimit: 100000},
		{name: "non-canonical envelope with a receiver error", failed: true, failureData: abiError("ReceiverError(bytes)", padded...), nonCanonical: true, honest: false, gasLimit: 100000},
		{name: "non-canonical envelope that succeeded", nonCanonical: true, honest: false, gasLimit: 100000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
			attempt := createTestExecutionAttempt(message, []protocol.UnknownAddress{}, [][]byte{}, big.NewInt(tc.gasLimit))
			attempt.GasLimitOverride = big.NewInt(tc.gasLimitOverride)
			attempt.HasNonCanonicalGasEnvelope = tc.nonCanonical
			attempt.Failed = tc.failed
			attempt.FailureData = tc.failureData

			assert.Equal(t, tc.honest, IsHonestGasLimit(message, attempt))
		})
	}
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
