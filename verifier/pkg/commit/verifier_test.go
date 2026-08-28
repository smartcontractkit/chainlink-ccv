package commit

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// newTestSigner generates an ECDSA key and returns a ready-to-use signer with its address.
func newTestSigner(t *testing.T) (*ECDSASigner, protocol.UnknownAddress) {
	t.Helper()
	pk, err := crypto.GenerateKey()
	require.NoError(t, err)
	signer, _, addr, err := NewECDSAMessageSigner(crypto.FromECDSA(pk))
	require.NoError(t, err)
	return signer, addr
}

// newSingleChainConfig returns a CoordinatorConfig configured for one source chain.
func newSingleChainConfig(
	sourceChain protocol.ChainSelector,
	verifierAddr protocol.UnknownAddress,
	defaultExecutorAddr protocol.UnknownAddress,
) verifier.CoordinatorConfig {
	return verifier.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			sourceChain: {
				VerifierAddress:        verifierAddr,
				DefaultExecutorAddress: defaultExecutorAddr,
				ChainSelector:          sourceChain,
			},
		},
	}
}

// newVerifiableTask builds a VerificationTask with a valid 3-receipt structure
// (CCV receipt, executor receipt, network-fee receipt) so that CreateVerifierNodeResult
// can parse it successfully.
func newVerifiableTask(
	t *testing.T,
	sourceChain, destChain protocol.ChainSelector,
	ccvIssuer protocol.UnknownAddress,
	ccvBlob []byte,
	executorAddr protocol.UnknownAddress,
) verifier.VerificationTask {
	t.Helper()

	sender := protocol.UnknownAddress([]byte{0x01})
	receiver := protocol.UnknownAddress([]byte{0x02})
	msg := protocol.Message{
		Version:             protocol.MessageVersion,
		SourceChainSelector: sourceChain,
		DestChainSelector:   destChain,
		Sender:              sender,
		SenderLength:        uint8(len(sender)),
		Receiver:            receiver,
		ReceiverLength:      uint8(len(receiver)),
	}

	msgID, err := msg.MessageID()
	require.NoError(t, err)

	// Receipt layout: [CCV(ccvIssuer, ccvBlob), Executor, NetworkFee]
	// numCCVBlobs = 3 - 0 - 2 = 1
	receipts := []protocol.ReceiptWithBlob{
		{
			Issuer:       ccvIssuer,
			Blob:         ccvBlob,
			DestGasLimit: 50_000,
		},
		{
			Issuer:       executorAddr,
			DestGasLimit: 100_000,
		},
		{
			// Network-fee receipt (always last)
			Issuer:         protocol.UnknownAddress([]byte{0xFF}),
			FeeTokenAmount: big.NewInt(0),
		},
	}

	return verifier.VerificationTask{
		MessageID:    msgID.String(),
		Message:      msg,
		ReceiptBlobs: receipts,
	}
}

func TestNewCommitVerifier_Success(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))

	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)
	require.NotNil(t, cv)
}

func TestNewCommitVerifier_NilSigner(t *testing.T) {
	_, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))

	_, err := NewCommitVerifier(config, addr, nil, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer")
}

func TestNewCommitVerifier_NilLogger(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))

	_, err := NewCommitVerifier(config, addr, signer, nil, monitoring.NewFakeVerifierMonitoring())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lggr")
}

func TestNewCommitVerifier_NilMonitoring(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))

	_, err := NewCommitVerifier(config, addr, signer, logger.Test(t), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "monitoring")
}

func TestVerifyMessages_NilTasks_ReturnsNil(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	assert.Nil(t, cv.VerifyMessages(context.Background(), nil))
}

func TestVerifyMessages_EmptyTasks_ReturnsNil(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	assert.Nil(t, cv.VerifyMessages(context.Background(), []verifier.VerificationTask{}))
}

func TestVerifyMessages_SuccessWithVerifierBlob(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	// blob must be at least 4 bytes (VerifierVersionLength) for NewSignableHash to succeed.
	blob := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	task := newVerifiableTask(t, sourceChain, destChain, addr, blob, executorAddr)

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
	require.Len(t, results, 1)
	assert.Nil(t, results[0].Error)
	require.NotNil(t, results[0].Result)
	assert.Equal(t, blob, []byte(results[0].Result.CCVVersion))
	assert.Equal(t, addr.Bytes(), results[0].Result.CCVAddresses[0].Bytes())
	assert.Equal(t, executorAddr.Bytes(), results[0].Result.ExecutorAddress.Bytes())
}

func TestVerifyMessages_SuccessWithDefaultExecutorBlob(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	// Use the default executor address as the CCV issuer.
	// The verifier should fall back to MessageDiscoveryVersion.
	task := newVerifiableTask(t, sourceChain, destChain, executorAddr, nil, executorAddr)

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
	require.Len(t, results, 1)
	assert.Nil(t, results[0].Error)
	require.NotNil(t, results[0].Result)
	assert.Equal(t, protocol.MessageDiscoveryVersion, []byte(results[0].Result.CCVVersion))
}

func TestVerifyMessages_ErrorUnconfiguredSourceChain(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	// Configure only chain 1; send a task from chain 99.
	config := newSingleChainConfig(1, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	task := newVerifiableTask(t, 99, 2, addr, []byte{0xAA}, executorAddr)

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error.Error(), "not configured")
}

func TestVerifyMessages_ErrorNoMatchingBlob(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	// Use a random issuer for the CCV receipt AND a different address for the executor
	// receipt slot, so neither the verifier address nor the defaultExecutorAddress is found
	// in any receipt — forcing the "neither verifier nor default executor blob found" error.
	unknownIssuer := protocol.UnknownAddress([]byte{0x99})
	differentExecutorSlot := protocol.UnknownAddress([]byte{0xBB}) // not 0xEE
	task := newVerifiableTask(t, sourceChain, destChain, unknownIssuer, []byte{0xAA}, differentExecutorSlot)

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error.Error(), "neither verifier nor default executor blob found")
}

func TestVerifyMessages_InvalidMessageID(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const sourceChain protocol.ChainSelector = 1
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	task := newVerifiableTask(t, sourceChain, 2, addr, []byte{0xAA}, executorAddr)
	task.MessageID = "not-valid-hex"

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error.Error(), "failed to convert messageID to Bytes32")
}

func TestVerifyMessages_MultipleTasks(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	// blob must be at least 4 bytes (VerifierVersionLength) for NewSignableHash to succeed.
	blob := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	task1 := newVerifiableTask(t, sourceChain, destChain, addr, blob, executorAddr)
	task2 := newVerifiableTask(t, sourceChain, destChain, addr, blob, executorAddr)
	// Give task2 a different sequence number so the message IDs differ.
	task2.Message.SequenceNumber = 99
	msgID2, err := task2.Message.MessageID()
	require.NoError(t, err)
	task2.MessageID = msgID2.String()

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task1, task2})
	require.Len(t, results, 2)
	for i, res := range results {
		assert.Nilf(t, res.Error, "task %d should succeed", i)
		require.NotNilf(t, res.Result, "task %d result should be non-nil", i)
	}
}

func TestVerifyMessages_ErrorInvalidMessageFormat(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const sourceChain protocol.ChainSelector = 1
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	// Message with unsupported version triggers ValidateMessage failure inside verifyMessage.
	task := newVerifiableTask(t, sourceChain, 2, addr, []byte{0xAA}, executorAddr)
	task.Message.Version = 99 // unsupported

	results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error.Error(), "unsupported message version")
}

// TestValidateTask_AgreesWithVerifyMessages is the test that makes the policy gate's skip safe.
// The gate asks ValidateTask which tasks are worth an endpoint call and forwards the rest
// unevaluated, so a task ValidateTask accepts and VerifyMessages then rejects only costs a
// wasted call, but a task ValidateTask rejects and VerifyMessages would have signed would be
// signed without the operator's endpoint ever seeing it. The two must agree on every shape.
func TestValidateTask_AgreesWithVerifyMessages(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	// The gate discovers this through a type assertion on the verifier it wraps, so the
	// production type has to satisfy it.
	validator, ok := cv.(verifier.TaskValidator)
	require.True(t, ok, "the commit verifier must satisfy vtypes.TaskValidator")

	tests := []struct {
		name  string
		task  func() verifier.VerificationTask
		valid bool
	}{
		{
			name: "signs on the verifier's own receipt",
			task: func() verifier.VerificationTask {
				return newVerifiableTask(t, sourceChain, destChain, addr, []byte{0xAA}, executorAddr)
			},
			valid: true,
		},
		{
			name: "signs on the default executor receipt",
			task: func() verifier.VerificationTask {
				// No receipt is issued by this verifier, so signing falls back to the
				// message discovery version, as TestVerifyMessages_SuccessWithDefaultExecutorBlob covers.
				return newVerifiableTask(t, sourceChain, destChain, executorAddr, nil, executorAddr)
			},
			valid: true,
		},
		{
			name: "source chain is not configured",
			task: func() verifier.VerificationTask {
				return newVerifiableTask(t, 99, destChain, addr, []byte{0xAA}, executorAddr)
			},
		},
		{
			name: "unsupported message version",
			task: func() verifier.VerificationTask {
				task := newVerifiableTask(t, sourceChain, destChain, addr, []byte{0xAA}, executorAddr)
				task.Message.Version = 99
				return task
			},
		},
		{
			name: "no receipt this verifier can sign over",
			task: func() verifier.VerificationTask {
				return newVerifiableTask(t, sourceChain, destChain,
					protocol.UnknownAddress([]byte{0x99}), []byte{0xAA}, protocol.UnknownAddress([]byte{0xBB}))
			},
		},
		{
			name: "message ID is not hex",
			task: func() verifier.VerificationTask {
				task := newVerifiableTask(t, sourceChain, destChain, addr, []byte{0xAA}, executorAddr)
				task.MessageID = "not-valid-hex"
				return task
			},
		},
		{
			name: "receipt blobs are missing entirely",
			task: func() verifier.VerificationTask {
				task := newVerifiableTask(t, sourceChain, destChain, addr, []byte{0xAA}, executorAddr)
				task.ReceiptBlobs = nil
				return task
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			task := tc.task()

			validateErr := validator.ValidateTask(&task)

			results := cv.VerifyMessages(context.Background(), []verifier.VerificationTask{task})
			require.Len(t, results, 1)

			if tc.valid {
				require.NoError(t, validateErr)
				require.Nil(t, results[0].Error, "ValidateTask accepted a task VerifyMessages rejected")
				return
			}

			require.Error(t, validateErr)
			require.NotNil(t, results[0].Error,
				"ValidateTask rejected a task VerifyMessages accepts, so the gate would skip the endpoint on a message that then gets signed")
			assert.Equal(t, results[0].Error.Error.Error(), validateErr.Error(),
				"the gate reports the verifier's own error, so the two have to be the same error")
		})
	}
}
