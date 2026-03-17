package lombard_test

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func createABIEncodedAttestation(rawPayload, proof []byte) string {
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		panic(err)
	}
	args := abi.Arguments{
		{Type: bytesType},
		{Type: bytesType},
	}
	encoded, err := args.Pack(rawPayload, proof)
	if err != nil {
		panic(err)
	}
	return protocol.ByteSlice(encoded).String()
}

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLombardAttestationService(t)

	task1 := internal.CreateTestVerificationTask(1)
	task2 := internal.CreateTestVerificationTask(2)
	tasks := []verifier.VerificationTask{task1, task2}

	// Create properly ABI-encoded attestation data with proof
	attestationData1 := createABIEncodedAttestation([]byte{0xab, 0xcd, 0xef}, []byte{0x11, 0x22})
	attestationData2 := createABIEncodedAttestation([]byte{0x12, 0x34, 0x56}, []byte{0x33, 0x44, 0x55})

	attestations := map[string]lombard.Attestation{
		task1.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        attestationData1,
			},
		),
		task2.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        attestationData2,
			},
		),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, tasks).
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

	// Verify results - the signature should be [versionTag (4)][len (2)][payload][len (2)][proof]
	assert.Equal(t, task1.MessageID, results[0].Result.MessageID.String())
	// Version tag (0xeba55588) + length prefix (0x0003) + payload (0xabcdef) + length prefix (0x0002) + proof (0x1122)
	expectedSig1 := "0xeba555880003abcdef00021122"
	assert.Equal(t, expectedSig1, results[0].Result.Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].Result.ExecutorAddress)
	assert.Equal(t, lombard.DefaultVerifierVersion, results[0].Result.CCVVersion)

	assert.Equal(t, task2.MessageID, results[1].Result.MessageID.String())
	// Version tag (0xeba55588) + length prefix (0x0003) + payload (0x123456) + length prefix (0x0003) + proof (0x334455)
	expectedSig2 := "0xeba5558800031234560003334455"
	assert.Equal(t, expectedSig2, results[1].Result.Signature.String())
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

	// Create properly ABI-encoded attestation data with proof
	attestationData1 := createABIEncodedAttestation([]byte{0xab, 0xcd, 0xef}, []byte{0xaa, 0xbb})

	attestations := map[string]lombard.Attestation{
		task1.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        attestationData1,
			},
		),
		task2.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusPending,
				Data:        "0x123456", // This won't be used since status is pending
			},
		),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, tasks).
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
