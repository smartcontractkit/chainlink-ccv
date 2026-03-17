package commit

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
)

// validMessageID returns a valid 32-byte message ID hex string.
func validMessageID() string {
	return "0x" + "aa" + "0000000000000000000000000000000000000000000000000000000000000000"[:62]
}

// buildMinimalReceipts returns a 3-receipt slice representing the minimal valid structure:
//
//	[CCV(issuer, blob), Executor(executorIssuer), NetworkFee]
//
// numCCVBlobs = 3 - 0 - 2 = 1, numTokenTransfers = 0.
func buildMinimalReceipts(ccvIssuer protocol.UnknownAddress, ccvBlob []byte, executorIssuer protocol.UnknownAddress) []protocol.ReceiptWithBlob {
	return []protocol.ReceiptWithBlob{
		{Issuer: ccvIssuer, Blob: ccvBlob, DestGasLimit: 50_000},
		{Issuer: executorIssuer, DestGasLimit: 100_000},
		{Issuer: protocol.UnknownAddress([]byte{0xFF}), FeeTokenAmount: big.NewInt(0)},
	}
}

func TestCreateVerifierNodeResult_Success(t *testing.T) {
	ccvIssuer := protocol.UnknownAddress([]byte{0xCC, 0x01})
	executorIssuer := protocol.UnknownAddress([]byte{0xEE, 0x01})
	ccvBlob := []byte{0xAA, 0xBB, 0xCC}
	signature := []byte("test-signature")

	task := &verifier.VerificationTask{
		MessageID: validMessageID(),
		Message: protocol.Message{
			Version:             protocol.MessageVersion,
			SourceChainSelector: 1,
			DestChainSelector:   2,
			Sender:              protocol.UnknownAddress([]byte{0x01}),
			SenderLength:        1,
			Receiver:            protocol.UnknownAddress([]byte{0x02}),
			ReceiverLength:      1,
		},
		ReceiptBlobs: buildMinimalReceipts(ccvIssuer, ccvBlob, executorIssuer),
	}

	result, err := CreateVerifierNodeResult(task, signature, ccvBlob)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ccvBlob, []byte(result.CCVVersion))
	assert.Equal(t, signature, []byte(result.Signature))
	assert.Equal(t, task.Message, result.Message)
	require.Len(t, result.CCVAddresses, 1)
	assert.Equal(t, ccvIssuer.Bytes(), result.CCVAddresses[0].Bytes())
	assert.Equal(t, executorIssuer.Bytes(), result.ExecutorAddress.Bytes())
}

func TestCreateVerifierNodeResult_InvalidMessageID(t *testing.T) {
	task := &verifier.VerificationTask{
		MessageID: "not-a-valid-hex-id",
		Message:   protocol.Message{},
		ReceiptBlobs: buildMinimalReceipts(
			protocol.UnknownAddress([]byte{0x01}),
			[]byte{0xAA},
			protocol.UnknownAddress([]byte{0x02}),
		),
	}

	result, err := CreateVerifierNodeResult(task, []byte("sig"), []byte("blob"))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to convert messageID to Bytes32")
}

func TestCreateVerifierNodeResult_InsufficientReceiptsNoToken(t *testing.T) {
	// Only 1 receipt; need at least 2 (executor + network-fee) when no token and no CCVs.
	task := &verifier.VerificationTask{
		MessageID: validMessageID(),
		Message: protocol.Message{
			Version:             protocol.MessageVersion,
			TokenTransferLength: 0,
		},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: protocol.UnknownAddress([]byte{0x01})},
		},
	}

	result, err := CreateVerifierNodeResult(task, []byte("sig"), []byte("blob"))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "insufficient receipts")
}

func TestCreateVerifierNodeResult_InsufficientReceiptsWithToken(t *testing.T) {
	// With TokenTransferLength != 0 numTokenTransfers=1, need at least 3 receipts.
	// Providing only 2 causes numCCVBlobs = 2 - 1 - 2 = -1.
	task := &verifier.VerificationTask{
		MessageID: validMessageID(),
		Message: protocol.Message{
			Version:             protocol.MessageVersion,
			TokenTransferLength: 100,
		},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: protocol.UnknownAddress([]byte{0x01})},
			{Issuer: protocol.UnknownAddress([]byte{0x02})},
		},
	}

	result, err := CreateVerifierNodeResult(task, []byte("sig"), []byte("blob"))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "insufficient receipts")
}

func TestCreateVerifierNodeResult_WithTokenTransfer(t *testing.T) {
	ccvIssuer := protocol.UnknownAddress([]byte{0xCC, 0x01})
	executorIssuer := protocol.UnknownAddress([]byte{0xEE, 0x01})
	tokenIssuer := protocol.UnknownAddress([]byte{0xAA, 0x01})
	ccvBlob := []byte{0xBB}
	signature := []byte("sig")

	// Receipt layout with token: [CCV, Token, Executor, NetworkFee]
	// numCCVBlobs = 4 - 1 - 2 = 1, numTokenTransfers = 1
	receipts := []protocol.ReceiptWithBlob{
		{Issuer: ccvIssuer, Blob: ccvBlob, DestGasLimit: 50_000},
		{Issuer: tokenIssuer, DestGasLimit: 75_000},
		{Issuer: executorIssuer, DestGasLimit: 100_000},
		{Issuer: protocol.UnknownAddress([]byte{0xFF}), FeeTokenAmount: big.NewInt(0)},
	}

	task := &verifier.VerificationTask{
		MessageID: validMessageID(),
		Message: protocol.Message{
			Version:             protocol.MessageVersion,
			TokenTransferLength: 100, // signals a token transfer
		},
		ReceiptBlobs: receipts,
	}

	result, err := CreateVerifierNodeResult(task, signature, ccvBlob)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ccvBlob, []byte(result.CCVVersion))
	assert.Equal(t, signature, []byte(result.Signature))
	require.Len(t, result.CCVAddresses, 1)
	assert.Equal(t, ccvIssuer.Bytes(), result.CCVAddresses[0].Bytes())
	assert.Equal(t, executorIssuer.Bytes(), result.ExecutorAddress.Bytes())
}

func TestCreateVerifierNodeResult_NoCCVBlobs(t *testing.T) {
	// No CCV blobs: [Executor, NetworkFee]
	// numCCVBlobs = 2 - 0 - 2 = 0
	executorIssuer := protocol.UnknownAddress([]byte{0xEE, 0x01})
	signature := []byte("sig")
	verifierBlob := []byte{0xBB}

	task := &verifier.VerificationTask{
		MessageID: validMessageID(),
		Message: protocol.Message{
			Version:             protocol.MessageVersion,
			TokenTransferLength: 0,
		},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: executorIssuer, DestGasLimit: 100_000},
			{Issuer: protocol.UnknownAddress([]byte{0xFF}), FeeTokenAmount: big.NewInt(0)},
		},
	}

	result, err := CreateVerifierNodeResult(task, signature, verifierBlob)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Empty(t, result.CCVAddresses)
	assert.Equal(t, executorIssuer.Bytes(), result.ExecutorAddress.Bytes())
	assert.Equal(t, verifierBlob, []byte(result.CCVVersion))
	assert.Equal(t, signature, []byte(result.Signature))
}

func TestCreateVerifierNodeResult_MultipleCCVBlobs(t *testing.T) {
	ccvIssuer1 := protocol.UnknownAddress([]byte{0xCC, 0x01})
	ccvIssuer2 := protocol.UnknownAddress([]byte{0xCC, 0x02})
	executorIssuer := protocol.UnknownAddress([]byte{0xEE, 0x01})
	signature := []byte("sig")
	verifierBlob := []byte{0xBB}

	// Receipt layout: [CCV1, CCV2, Executor, NetworkFee]
	// numCCVBlobs = 4 - 0 - 2 = 2, numTokenTransfers = 0
	task := &verifier.VerificationTask{
		MessageID: validMessageID(),
		Message: protocol.Message{
			Version:             protocol.MessageVersion,
			TokenTransferLength: 0,
		},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: ccvIssuer1, Blob: []byte{0x01}, DestGasLimit: 50_000},
			{Issuer: ccvIssuer2, Blob: []byte{0x02}, DestGasLimit: 51_000},
			{Issuer: executorIssuer, DestGasLimit: 100_000},
			{Issuer: protocol.UnknownAddress([]byte{0xFF}), FeeTokenAmount: big.NewInt(0)},
		},
	}

	result, err := CreateVerifierNodeResult(task, signature, verifierBlob)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.CCVAddresses, 2)
	assert.Equal(t, ccvIssuer1.Bytes(), result.CCVAddresses[0].Bytes())
	assert.Equal(t, ccvIssuer2.Bytes(), result.CCVAddresses[1].Bytes())
	assert.Equal(t, executorIssuer.Bytes(), result.ExecutorAddress.Bytes())
}
