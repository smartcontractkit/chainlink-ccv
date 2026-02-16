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
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/internal"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var ccvVerifierVersion = protocol.ByteSlice{0x00, 0x00, 0x00, 0x01}

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	testAttestation := createTestAttestation()

	mockAttestationService.EXPECT().
		Fetch(ctx, task.TxHash, task.Message).
		Return(testAttestation, nil).
		Once()

	ccvDataBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](1, 1*time.Minute, 10)
	ccvDataBatcher.Start(ctx)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	vErrors := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	assert.NoError(t, vErrors.Error, "Expected no batch-level error")
	assert.Empty(t, vErrors.Items, "Expected no verification errors")
	mockAttestationService.AssertExpectations(t)

	t.Cleanup(func() {
		cancel()
		_ = ccvDataBatcher.Close()
	})

	results := internal.ReadResultsFromChannel(t, ccvDataBatcher.OutChannel())
	require.Len(t, results, 1, "Expected one result in batcher")

	attestation, err := testAttestation.ToVerifierFormat()
	require.NoError(t, err)
	assert.Equal(t, task.MessageID, results[0].MessageID.String())
	assert.Equal(t, attestation, results[0].Signature)
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].ExecutorAddress)
	assert.Equal(t, ccvVerifierVersion, results[0].CCVVersion)
}

func TestVerifier_VerifyMessages_AttestationServiceFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	expectedErr := errors.New("attestation service unavailable")
	mockAttestationService.EXPECT().
		Fetch(ctx, task.TxHash, task.Message).
		Return(cctp.Attestation{}, expectedErr).
		Once()

	ccvDataBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](100, 1*time.Minute, 10)
	ccvDataBatcher.Start(ctx)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	t.Cleanup(func() {
		cancel()
		_ = ccvDataBatcher.Close()
	})

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
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	testAttestation := createTestAttestation()

	mockAttestationService.EXPECT().
		Fetch(mock.Anything, task.TxHash, task.Message).
		Return(testAttestation, nil).
		Once()

	ccvDataBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](100, 1*time.Minute, 10)
	ccvDataBatcher.Start(ctx)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	t.Cleanup(func() {
		_ = ccvDataBatcher.Close()
	})

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
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task1 := internal.CreateTestVerificationTask(100)
	task2 := internal.CreateTestVerificationTask(101)
	task3 := internal.CreateTestVerificationTask(102)

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

	ccvDataBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](2, 1*time.Minute, 10)
	ccvDataBatcher.Start(ctx)

	v := cctp.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	t.Cleanup(func() {
		cancel()
		_ = ccvDataBatcher.Close()
	})

	assert.NoError(t, result.Error, "Expected no batch-level error")
	require.Len(t, result.Items, 1, "Expected one verification error (task2)")

	verificationError := result.Items[0]
	assert.Equal(t, expectedErr, verificationError.Error)
	assert.Equal(t, task2.MessageID, verificationError.Task.MessageID)
	mockAttestationService.AssertExpectations(t)

	results := internal.ReadResultsFromChannel(t, ccvDataBatcher.OutChannel())
	require.Len(t, results, 2, "Expected two results in batcher")
	assert.Equal(t, task1.MessageID, results[0].MessageID.String())
	assert.Equal(t, task3.MessageID, results[1].MessageID.String())
}

func createTestAttestation() cctp.Attestation {
	msg := cctp.Message{
		Message:     "0x1234567890",
		Attestation: "0xabcdef",
		DecodedMessage: cctp.DecodedMessage{
			Sender: "0x1122334455",
		},
		Status: "complete",
	}

	attestation := cctp.NewAttestation(ccvVerifierVersion, msg)
	return attestation
}
