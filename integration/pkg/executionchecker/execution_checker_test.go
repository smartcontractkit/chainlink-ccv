package executionchecker

import (
	"math/big"
	"testing"
	"time"

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

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{requiredCCV, optionalCCV1, optionalCCV2},
			[][]byte{requiredCCVData, optionalCCV1Data, []byte("wrong_optional2_data")},
			big.NewInt(100000),
		)

		honest, err := IsHonestCallData(message, attempt, verifierResults, ccvInfo)

		assert.NoError(t, err)
		assert.True(t, honest)
	})
}

func TestIsHonestGasLimit(t *testing.T) {
	t.Run("gas limit less than execution gas limit", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(50000),
		)

		honest := IsHonestGasLimit(message, attempt)
		assert.False(t, honest)
	})

	t.Run("gas limit equal to execution gas limit", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(100000),
		)

		honest := IsHonestGasLimit(message, attempt)
		assert.True(t, honest)
	})

	t.Run("gas limit greater than execution gas limit", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{},
			[][]byte{},
			big.NewInt(150000),
		)

		honest := IsHonestGasLimit(message, attempt)
		assert.True(t, honest)
	})
}

func Test_honestCCVs(t *testing.T) {
	t.Run("meets threshold", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvData := []byte("test_data")
		verifierResult := createTestVerifierResult(t, message, ccvAddr, ccvData)

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

		ccvToKnownResults := map[string][]protocol.VerifierResult{
			verifierResult.VerifierDestAddress.String(): {verifierResult},
		}

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
		messageCCVs := []string{ccvAddr2.String()}
		threshold := 1

		honest := honestCCVs(attempt, attemptCCVs, messageCCVs, threshold, ccvToKnownResults)

		assert.False(t, honest)
	})

	t.Run("CCV index out of bounds", func(t *testing.T) {
		message := createTestMessage(t, 1, testSourceChain, testDestChain, 100000)
		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1111111111111111111111111111111111111111")
		require.NoError(t, err)

		ccvToKnownResults := map[string][]protocol.VerifierResult{}

		attempt := createTestExecutionAttempt(
			message,
			[]protocol.UnknownAddress{ccvAddr},
			[][]byte{},
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
			createTestVerifierResult(t, message, ccvAddr1, []byte("data2")),
			createTestVerifierResult(t, message, ccvAddr2, []byte("data3")),
		}

		result := mapResultsToCCVs(verifierResults)

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
