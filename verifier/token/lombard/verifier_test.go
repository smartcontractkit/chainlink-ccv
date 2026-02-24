package lombard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLombardAttestationService(t)

	task1 := internal.CreateTestVerificationTask(1)
	task2 := internal.CreateTestVerificationTask(2)
	tasks := []verifier.VerificationTask{task1, task2}

	attestations := map[string]lombard.Attestation{
		task1.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        "0xabcdef",
			},
		),
		task2.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        "0x123456",
			},
		),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, []protocol.Message{task1.Message, task2.Message}).
		Return(attestations, nil).
		Once()

	config := lombard.LombardConfig{
		VerifierVersion: lombard.DefaultVerifierVersion,
	}
	v, err := lombard.NewVerifier(lggr, config, mockAttestationService)
	require.NoError(t, err)
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 2, "Expected two results")

	// Both should succeed
	assert.Nil(t, results[0].Error, "Expected no error for task1")
	assert.NotNil(t, results[0].Result, "Expected successful result for task1")
	assert.Nil(t, results[1].Error, "Expected no error for task2")
	assert.NotNil(t, results[1].Result, "Expected successful result for task2")

	mockAttestationService.AssertExpectations(t)

	assert.Equal(t, task1.MessageID, results[0].Result.MessageID.String())
	assert.Equal(t, "0xf0f3a135abcdef", results[0].Result.Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].Result.ExecutorAddress)
	assert.Equal(t, lombard.DefaultVerifierVersion, results[0].Result.CCVVersion)

	assert.Equal(t, task2.MessageID, results[1].Result.MessageID.String())
	assert.Equal(t, "0xf0f3a135123456", results[1].Result.Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[1].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[1].Result.ExecutorAddress)
	assert.Equal(t, lombard.DefaultVerifierVersion, results[1].Result.CCVVersion)
}

func TestVerifier_VerifyMessages_NotReadyMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLombardAttestationService(t)

	task1 := internal.CreateTestVerificationTask(1)
	task2 := internal.CreateTestVerificationTask(2)
	task3 := internal.CreateTestVerificationTask(3)
	tasks := []verifier.VerificationTask{task1, task2, task3}

	attestations := map[string]lombard.Attestation{
		task1.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        "0xabcdef",
			},
		),
		task2.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusPending,
				Data:        "0x123456",
			},
		),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, []protocol.Message{task1.Message, task2.Message, task3.Message}).
		Return(attestations, nil).
		Once()

	config := lombard.LombardConfig{
		VerifierVersion: lombard.DefaultVerifierVersion,
	}
	v, err := lombard.NewVerifier(lggr, config, mockAttestationService)
	require.NoError(t, err)
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	// Task1 should pass, Task2 is not ready, Task3 not found
	require.Len(t, results, 3, "Expected three results")

	// task1 should succeed
	assert.Nil(t, results[0].Error, "Expected no error for task1")
	assert.NotNil(t, results[0].Result, "Expected successful result for task1")
	assert.Equal(t, task1.MessageID, results[0].Result.MessageID.String())

	// task2 should fail - not ready
	assert.Nil(t, results[1].Result, "Expected no result for task2")
	assert.NotNil(t, results[1].Error, "Expected error for task2")
	assert.Equal(t, task2.MessageID, results[1].Error.Task.MessageID)
	assert.EqualError(t, results[1].Error.Error, "attestation not ready for message ID: "+task2.MessageID)

	// task3 should fail - not found
	assert.Nil(t, results[2].Result, "Expected no result for task3")
	assert.NotNil(t, results[2].Error, "Expected error for task3")
	assert.Equal(t, task3.MessageID, results[2].Error.Task.MessageID)
	assert.EqualError(t, results[2].Error.Error, "attestation not found for message ID: "+task3.MessageID)

	mockAttestationService.AssertExpectations(t)
}
