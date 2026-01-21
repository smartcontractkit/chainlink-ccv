package lbtc_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/internal"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lbtc"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLBTCAttestationService(t)

	task1 := internal.CreateTestVerificationTask(1)
	task2 := internal.CreateTestVerificationTask(2)
	tasks := []verifier.VerificationTask{task1, task2}

	attestations := map[string]lbtc.Attestation{
		task1.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.VerifierVersion,
			lbtc.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lbtc.AttestationStatusApproved,
				Data:        "0xabcdef",
			},
		),
		task2.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.VerifierVersion,
			lbtc.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lbtc.AttestationStatusApproved,
				Data:        "0x123456",
			},
		),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, []protocol.Message{task1.Message, task2.Message}).
		Return(attestations, nil).
		Once()

	ccvDataBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](ctx, 2, 1*time.Minute, 10)

	v := lbtc.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	t.Cleanup(func() {
		cancel()
		_ = ccvDataBatcher.Close()
	})

	assert.NoError(t, result.Error, "Expected no batch-level error")
	assert.Empty(t, result.Items, "Expected no verification errors")
	mockAttestationService.AssertExpectations(t)

	results := internal.ReadResultsFromChannel(t, ccvDataBatcher.OutChannel())
	require.Len(t, results, 2, "Expected two results in batcher")

	assert.Equal(t, task1.MessageID, results[0].MessageID.String())
	assert.Equal(t, "0xf0f3a135abcdef", results[0].Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].ExecutorAddress)
	assert.Equal(t, lbtc.VerifierVersion, results[0].CCVVersion)

	assert.Equal(t, task2.MessageID, results[1].MessageID.String())
	assert.Equal(t, "0xf0f3a135123456", results[1].Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[1].CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[1].ExecutorAddress)
	assert.Equal(t, lbtc.VerifierVersion, results[1].CCVVersion)
}

func TestVerifier_VerifyMessages_NotReadyMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLBTCAttestationService(t)

	task1 := internal.CreateTestVerificationTask(1)
	task2 := internal.CreateTestVerificationTask(2)
	task3 := internal.CreateTestVerificationTask(3)
	tasks := []verifier.VerificationTask{task1, task2, task3}

	attestations := map[string]lbtc.Attestation{
		task1.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.VerifierVersion,
			lbtc.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lbtc.AttestationStatusApproved,
				Data:        "0xabcdef",
			},
		),
		task2.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.VerifierVersion,
			lbtc.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lbtc.AttestationStatusPending,
				Data:        "0x123456",
			},
		),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, []protocol.Message{task1.Message, task2.Message, task3.Message}).
		Return(attestations, nil).
		Once()

	ccvDataBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](ctx, 1, 1*time.Minute, 10)

	v := lbtc.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	t.Cleanup(func() {
		cancel()
		_ = ccvDataBatcher.Close()
	})

	// Task1 should pass, Task2 is not ready, Task3 not found
	assert.NoError(t, result.Error, "Expected no batch-level error")
	require.Len(t, result.Items, 2)

	assert.Equal(t, result.Items[0].Task.MessageID, task2.MessageID)
	assert.EqualError(t, result.Items[0].Error, "attestation not ready for message ID: "+task2.MessageID)
	assert.Equal(t, result.Items[1].Task.MessageID, task3.MessageID)
	assert.EqualError(t, result.Items[1].Error, "attestation not found for message ID: "+task3.MessageID)

	mockAttestationService.AssertExpectations(t)
	results := internal.ReadResultsFromChannel(t, ccvDataBatcher.OutChannel())
	require.Len(t, results, 1, "Expected one result in batcher")

	assert.Equal(t, task1.MessageID, results[0].MessageID.String())
}
