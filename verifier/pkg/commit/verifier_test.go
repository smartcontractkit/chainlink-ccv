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
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
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

func TestCommitVerifier_ValidateMessage_Success(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	msg := protocol.Message{
		Version:  protocol.MessageVersion,
		Sender:   protocol.UnknownAddress([]byte{0x01}),
		Receiver: protocol.UnknownAddress([]byte{0x02}),
	}
	require.NoError(t, cv.(*Verifier).ValidateMessage(msg))
}

func TestCommitVerifier_ValidateMessage_UnsupportedVersion(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	err = cv.(*Verifier).ValidateMessage(protocol.Message{Version: 99})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported message version")
}

func TestCommitVerifier_ValidateMessage_EmptySender(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	err = cv.(*Verifier).ValidateMessage(protocol.Message{
		Version:  protocol.MessageVersion,
		Sender:   nil,
		Receiver: protocol.UnknownAddress([]byte{0x02}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sender cannot be empty")
}

func TestCommitVerifier_ValidateMessage_EmptyReceiver(t *testing.T) {
	signer, addr := newTestSigner(t)
	config := newSingleChainConfig(1, addr, protocol.UnknownAddress([]byte{0xEE}))
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	err = cv.(*Verifier).ValidateMessage(protocol.Message{
		Version:  protocol.MessageVersion,
		Sender:   protocol.UnknownAddress([]byte{0x01}),
		Receiver: nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "receiver cannot be empty")
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
