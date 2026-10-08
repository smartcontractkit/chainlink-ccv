package lombard_test

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
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

func TestVerifier_VerifyMessages_EmptyBatch(t *testing.T) {
	service := mocks.NewLombardAttestationService(t)
	v, err := lombard.NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", lombard.LombardConfig{}, service)
	require.NoError(t, err)

	assert.Empty(t, v.VerifyMessages(t.Context(), nil))
	service.AssertNotCalled(t, "Fetch", mock.Anything, mock.Anything)
}

func TestVerifier_VerifyMessages_UnknownDestination(t *testing.T) {
	task := internal.CreateTestVerificationTask(1)
	task.Message.DestChainSelector = protocol.ChainSelector(1)
	task.MessageID = task.Message.MustMessageID().String()
	tasks := []verifier.VerificationTask{task}
	service := mocks.NewLombardAttestationService(t)
	service.EXPECT().Fetch(mock.Anything, tasks).Return(map[string]lombard.Attestation{
		task.MessageID: lombard.NewAttestation(lombard.DefaultVerifierVersion, lombard.AttestationResponse{
			Status: lombard.AttestationStatusApproved,
		}, nil),
	}, nil).Once()
	v, err := lombard.NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", lombard.LombardConfig{}, service)
	require.NoError(t, err)

	results := v.VerifyMessages(t.Context(), tasks)
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.False(t, results[0].Error.Retryable)
}

// A FAILED response can change to APPROVED after Lombard repairs its infrastructure.
func TestVerifier_VerifyMessages_RetryAfterFailedAttestation(t *testing.T) {
	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}
	service := mocks.NewLombardAttestationService(t)
	service.EXPECT().Fetch(mock.Anything, tasks).Return(map[string]lombard.Attestation{
		task.MessageID: lombard.NewAttestation(lombard.DefaultVerifierVersion, lombard.AttestationResponse{
			Status: lombard.AttestationStatusFailed,
		}, nil),
	}, nil).Once()
	service.EXPECT().Fetch(mock.Anything, tasks).Return(map[string]lombard.Attestation{
		task.MessageID: lombard.NewAttestation(lombard.DefaultVerifierVersion, lombard.AttestationResponse{
			Status: lombard.AttestationStatusApproved,
			Data:   createABIEncodedAttestation([]byte{1}, []byte{2}),
		}, nil),
	}, nil).Once()
	v, err := lombard.NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", lombard.LombardConfig{VerifierVersion: lombard.DefaultVerifierVersion}, service)
	require.NoError(t, err)

	first := v.VerifyMessages(t.Context(), tasks)
	require.Len(t, first, 1)
	require.NotNil(t, first[0].Error)
	assert.True(t, first[0].Error.Retryable)

	second := v.VerifyMessages(t.Context(), tasks)
	require.Len(t, second, 1)
	assert.Nil(t, second[0].Error)
	assert.NotNil(t, second[0].Result)
}

// EVM needs API attestation data; Solana sends a payload hash for a delivered message.
// Lombard's Mailbox requires the Delivered state before it handles that hash.
// See https://github.com/lombard-finance/sol-svm-contracts/blob/09d5e768e6791c3e05325b3dd93dfdfec6d89a56/programs/mailbox/src/instructions/handle_message.rs#L30-L47.
func TestVerifier_VerifyMessages_ApprovedWithoutData(t *testing.T) {
	for _, test := range []struct {
		name      string
		destChain protocol.ChainSelector
		wantError bool
	}{
		{"EVM", protocol.ChainSelector(chainsel.ETHEREUM_TESTNET_SEPOLIA_ARBITRUM_1.Selector), true},
		{"Solana", protocol.ChainSelector(chainsel.SOLANA_DEVNET.Selector), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			task := internal.CreateTestVerificationTask(1)
			task.Message.DestChainSelector = test.destChain
			messageID := task.Message.MustMessageID()
			task.MessageID = messageID.String()
			tasks := []verifier.VerificationTask{task}
			service := mocks.NewLombardAttestationService(t)
			service.EXPECT().Fetch(mock.Anything, tasks).Return(map[string]lombard.Attestation{
				task.MessageID: lombard.NewAttestation(lombard.DefaultVerifierVersion, lombard.AttestationResponse{
					Status: lombard.AttestationStatusApproved,
				}, messageID[:]),
			}, nil).Once()
			v, err := lombard.NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", lombard.LombardConfig{VerifierVersion: lombard.DefaultVerifierVersion}, service)
			require.NoError(t, err)

			results := v.VerifyMessages(t.Context(), tasks)
			require.Len(t, results, 1)
			if test.wantError {
				require.NotNil(t, results[0].Error)
				assert.True(t, results[0].Error.Retryable)
				assert.ErrorContains(t, results[0].Error.Error, "attestation")
				assert.Nil(t, results[0].Result)
			} else {
				assert.Nil(t, results[0].Error)
				assert.NotNil(t, results[0].Result)
			}
		})
	}
}

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLombardAttestationService(t)

	task1 := internal.CreateTestVerificationTask(1)
	task2 := internal.CreateTestVerificationTask(2)
	task3 := internal.CreateTestVerificationTask(3)
	task3.Message.DestChainSelector = protocol.ChainSelector(chainsel.SOLANA_DEVNET.Selector)
	task3.MessageID = task3.Message.MustMessageID().String()
	task3ID := task3.Message.MustMessageID()

	tasks := []verifier.VerificationTask{task1, task2, task3}

	// Create properly ABI-encoded attestation data with proof
	attestationData1 := createABIEncodedAttestation([]byte{0xab, 0xcd, 0xef}, []byte{0x11, 0x22})
	attestationData2 := createABIEncodedAttestation([]byte{0x12, 0x34, 0x56}, []byte{0x33, 0x44, 0x55})
	attestationData3 := createABIEncodedAttestation([]byte{0x11, 0x22, 0x33}, []byte{0x33, 0x44, 0x55})

	attestations := map[string]lombard.Attestation{
		task1.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        attestationData1,
			},
			nil,
		),
		task2.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        attestationData2,
			},
			nil,
		),
		task3.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusApproved,
				Data:        attestationData3,
			},
			task3ID[:],
		),
	}

	mockAttestationService.EXPECT().
		Fetch(mock.Anything, tasks).
		Return(attestations, nil).
		Once()

	config := lombard.LombardConfig{
		VerifierVersion: lombard.DefaultVerifierVersion,
	}
	v, err := lombard.NewVerifier(lggr, monitoring.NewFakeVerifierMonitoring(), "test-verifier", config, mockAttestationService)
	require.NoError(t, err)
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 3, "Expected two results")

	// All should succeed
	assert.Nil(t, results[0].Error, "Expected no error for task1")
	assert.NotNil(t, results[0].Result, "Expected successful result for task1")
	assert.Nil(t, results[1].Error, "Expected no error for task2")
	assert.NotNil(t, results[1].Result, "Expected successful result for task2")
	assert.Nil(t, results[2].Error, "Expected no error for task3")
	assert.NotNil(t, results[2].Result, "Expected successful result for task3")

	mockAttestationService.AssertExpectations(t)

	// Verify results - the signature should be [versionTag (4)][len (2)][payload][len (2)][proof]
	assert.Equal(t, task1.MessageID, results[0].Result.MessageID.String())
	// Version tag (0x5b9253ce) + length prefix (0x0003) + payload (0xabcdef) + length prefix (0x0002) + proof (0x1122)
	expectedSig1 := "0x5b9253ce0003abcdef00021122"
	assert.Equal(t, expectedSig1, results[0].Result.Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].Result.ExecutorAddress)
	assert.Equal(t, lombard.DefaultVerifierVersion, results[0].Result.CCVVersion)

	assert.Equal(t, task2.MessageID, results[1].Result.MessageID.String())
	// Version tag (0x5b9253ce) + length prefix (0x0003) + payload (0x123456) + length prefix (0x0003) + proof (0x334455)
	expectedSig2 := "0x5b9253ce00031234560003334455"
	assert.Equal(t, expectedSig2, results[1].Result.Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[1].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[1].Result.ExecutorAddress)
	assert.Equal(t, lombard.DefaultVerifierVersion, results[1].Result.CCVVersion)

	assert.Equal(t, task3.MessageID, results[2].Result.MessageID.String())
	assert.Equal(t, task3.MessageID, results[2].Result.Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[2].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[2].Result.ExecutorAddress)
	assert.Equal(t, lombard.DefaultVerifierVersion, results[2].Result.CCVVersion)
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
			nil,
		),
		task2.Message.MustMessageID().String(): lombard.NewAttestation(
			lombard.DefaultVerifierVersion,
			lombard.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lombard.AttestationStatusPending,
				Data:        "0x123456", // This won't be used since status is pending
			},
			nil,
		),
	}

	mockAttestationService.EXPECT().
		Fetch(mock.Anything, tasks).
		Return(attestations, nil).
		Once()

	config := lombard.LombardConfig{
		VerifierVersion: lombard.DefaultVerifierVersion,
	}
	v, err := lombard.NewVerifier(lggr, monitoring.NewFakeVerifierMonitoring(), "test-verifier", config, mockAttestationService)
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
