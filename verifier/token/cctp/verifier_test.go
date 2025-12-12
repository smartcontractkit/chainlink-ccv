package cctp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewMockAttestationService(t)

	task := createTestVerificationTask()
	tasks := []verifier.VerificationTask{task}

	testAttestation := createTestAttestation()

	mockAttestationService.EXPECT().
		Fetch(ctx, task.TxHash, task.Message).
		Return(testAttestation, nil).
		Once()

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 100, 1*time.Second, outCh)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	cancel()
	_ = ccvDataBatcher.Close()

	assert.NoError(t, result.Error, "Expected no batch-level error")
	assert.Empty(t, result.Items, "Expected no verification errors")
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_AttestationServiceFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewMockAttestationService(t)

	task := createTestVerificationTask()
	tasks := []verifier.VerificationTask{task}

	expectedErr := errors.New("attestation service unavailable")
	mockAttestationService.EXPECT().
		Fetch(ctx, task.TxHash, task.Message).
		Return(cctp.Attestation{}, expectedErr).
		Once()

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 100, 1*time.Second, outCh)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	cancel()
	_ = ccvDataBatcher.Close()

	assert.NoError(t, result.Error, "Expected no batch-level error")
	require.Len(t, result.Items, 1, "Expected one verification error")

	verificationError := result.Items[0]
	assert.Equal(t, expectedErr, verificationError.Error)
	assert.Equal(t, task.MessageID, verificationError.Task.MessageID)
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_BatcherFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewMockAttestationService(t)

	task := createTestVerificationTask()
	tasks := []verifier.VerificationTask{task}

	testAttestation := createTestAttestation()

	mockAttestationService.EXPECT().
		Fetch(mock.Anything, task.TxHash, task.Message).
		Return(testAttestation, nil).
		Once()

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 100, 1*time.Second, outCh)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(context.Background(), tasks, ccvDataBatcher)

	_ = ccvDataBatcher.Close()

	assert.NoError(t, result.Error, "Expected no batch-level error")
	require.Len(t, result.Items, 1, "Expected one verification error")

	verificationError := result.Items[0]
	assert.Error(t, verificationError.Error, "Expected error from batcher.Add")
	assert.Contains(t, verificationError.Error.Error(), "context canceled")
	assert.Equal(t, task.MessageID, verificationError.Task.MessageID)
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_MultipleTasksWithMixedResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewMockAttestationService(t)

	task1 := createTestVerificationTask()
	task1.Message.SequenceNumber = 100

	task2 := createTestVerificationTask()
	task2.Message.SequenceNumber = 101

	task3 := createTestVerificationTask()
	task3.Message.SequenceNumber = 102

	tasks := []verifier.VerificationTask{task1, task2, task3}

	// task1: success
	testAttestation := createTestAttestation()
	mockAttestationService.EXPECT().
		Fetch(ctx, task1.TxHash, task1.Message).
		Return(testAttestation, nil).
		Once()

	// task2: attestation service failure
	expectedErr := errors.New("network timeout")
	mockAttestationService.EXPECT().
		Fetch(ctx, task2.TxHash, task2.Message).
		Return(cctp.Attestation{}, expectedErr).
		Once()

	// task3: success
	mockAttestationService.EXPECT().
		Fetch(ctx, task3.TxHash, task3.Message).
		Return(testAttestation, nil).
		Once()

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 100, 1*time.Second, outCh)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	cancel()
	_ = ccvDataBatcher.Close()

	assert.NoError(t, result.Error, "Expected no batch-level error")
	require.Len(t, result.Items, 1, "Expected one verification error (task2)")

	verificationError := result.Items[0]
	assert.Equal(t, expectedErr, verificationError.Error)
	assert.Equal(t, task2.MessageID, verificationError.Task.MessageID)

	mockAttestationService.AssertExpectations(t)
}

func createTestVerificationTask() verifier.VerificationTask {
	sourceChain := protocol.ChainSelector(1)
	destChain := protocol.ChainSelector(2)

	message := protocol.Message{
		Version:              1,
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		SequenceNumber:       protocol.SequenceNumber(100),
		OnRampAddress:        protocol.UnknownAddress{0x01, 0x02},
		Sender:               protocol.UnknownAddress{0x03, 0x04},
		OffRampAddress:       protocol.UnknownAddress{0x05, 0x06},
		Receiver:             protocol.UnknownAddress{0x07, 0x08},
		Finality:             10,
		ExecutionGasLimit:    100000,
		CcipReceiveGasLimit:  50000,
		OnRampAddressLength:  2,
		SenderLength:         2,
		OffRampAddressLength: 2,
		ReceiverLength:       2,
	}

	messageID := message.MustMessageID()

	// Create receipt structure: [CCV1, CCV2, Executor]
	ccvAddress1 := protocol.UnknownAddress{0x11, 0x12, 0x13}
	ccvAddress2 := protocol.UnknownAddress{0x21, 0x22, 0x23}
	executorAddress := protocol.UnknownAddress{0x31, 0x32, 0x33}

	return verifier.VerificationTask{
		MessageID: messageID.String(),
		Message:   message,
		TxHash:    protocol.ByteSlice{0xaa, 0xbb, 0xcc},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			{Issuer: ccvAddress1, Blob: []byte("ccv1-blob")},
			{Issuer: ccvAddress2, Blob: []byte("ccv2-blob")},
			{Issuer: executorAddress, Blob: []byte("executor-blob")},
		},
		BlockNumber: 12345,
		FirstSeenAt: time.Now(),
		QueuedAt:    time.Now(),
	}
}

func createTestAttestation() cctp.Attestation {
	msg := cctp.Message{
		Message:     "0x1234567890",
		Attestation: "0xabcdef",
		DecodedMessage: cctp.DecodedMessage{
			Sender: "0x1122334455",
		},
	}

	ccvVerifierVersion := protocol.ByteSlice{0x00, 0x00, 0x00, 0x01}
	attestation, _ := cctp.NewAttestation(ccvVerifierVersion, msg)
	return attestation
}
