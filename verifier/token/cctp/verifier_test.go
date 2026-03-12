package cctp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	v := cctp.NewVerifier(lggr, mockAttestationService)
	results := v.VerifyMessages(ctx, tasks)

	require.Len(t, results, 1, "Expected one result")
	assert.Nil(t, results[0].Error, "Expected no error")
	assert.NotNil(t, results[0].Result, "Expected successful result")
	mockAttestationService.AssertExpectations(t)

	t.Cleanup(func() {
		cancel()
	})

	attestation, err := testAttestation.ToVerifierFormat()
	require.NoError(t, err)
	assert.Equal(t, task.MessageID, results[0].Result.MessageID.String())
	assert.Equal(t, attestation, results[0].Result.Signature)
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].Result.ExecutorAddress)
	assert.Equal(t, ccvVerifierVersion, results[0].Result.CCVVersion)
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

	v := cctp.NewVerifier(lggr, mockAttestationService)
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 1, "Expected one result")
	assert.Nil(t, results[0].Result, "Expected no successful result")
	assert.NotNil(t, results[0].Error, "Expected an error")

	verificationError := results[0].Error
	assert.Equal(t, expectedErr, verificationError.Error)
	assert.Equal(t, task.MessageID, verificationError.Task.MessageID)
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_AttestationNotReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	notReadyAttestation := cctp.Attestation{} // Empty attestation (not ready)

	mockAttestationService.EXPECT().
		Fetch(mock.Anything, task.TxHash, task.Message).
		Return(notReadyAttestation, nil).
		Once()

	v := cctp.NewVerifier(lggr, mockAttestationService)
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 1, "Expected one result")
	assert.Nil(t, results[0].Result, "Expected no successful result")
	assert.NotNil(t, results[0].Error, "Expected an error")

	verificationError := results[0].Error
	assert.Error(t, verificationError.Error, "Expected error for attestation not ready")
	assert.Contains(t, verificationError.Error.Error(), "not ready")
	assert.Equal(t, task.MessageID, verificationError.Task.MessageID)
	assert.True(t, verificationError.Retryable, "Should be retryable")
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

	v := cctp.NewVerifier(lggr, mockAttestationService)
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 3, "Expected three results")

	// task1 should succeed
	assert.Nil(t, results[0].Error, "Expected no error for task1")
	assert.NotNil(t, results[0].Result, "Expected successful result for task1")
	assert.Equal(t, task1.MessageID, results[0].Result.MessageID.String())

	// task2 should fail
	assert.Nil(t, results[1].Result, "Expected no result for task2")
	assert.NotNil(t, results[1].Error, "Expected error for task2")
	assert.Equal(t, expectedErr, results[1].Error.Error)
	assert.Equal(t, task2.MessageID, results[1].Error.Task.MessageID)

	// task3 should succeed
	assert.Nil(t, results[2].Error, "Expected no error for task3")
	assert.NotNil(t, results[2].Result, "Expected successful result for task3")
	assert.Equal(t, task3.MessageID, results[2].Result.MessageID.String())

	mockAttestationService.AssertExpectations(t)
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
