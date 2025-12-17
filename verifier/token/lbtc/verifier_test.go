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

var (
	ccvAddress1     = protocol.UnknownAddress{0x11, 0x12, 0x13}
	ccvAddress2     = protocol.UnknownAddress{0x21, 0x22, 0x23}
	executorAddress = protocol.UnknownAddress{0x31, 0x32, 0x33}
)

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLBTCAttestationService(t)

	task1 := createTestVerificationTask(1)
	task2 := createTestVerificationTask(2)
	tasks := []verifier.VerificationTask{task1, task2}

	attestations := map[string]lbtc.Attestation{
		task1.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.CCVVerifierVersion,
			lbtc.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lbtc.AttestationStatusApproved,
				Data:        "0xabcdef",
			},
		),
		task2.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.CCVVerifierVersion,
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

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 2, 1*time.Millisecond, outCh)

	v := lbtc.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	cancel()
	_ = ccvDataBatcher.Close()

	assert.NoError(t, result.Error, "Expected no batch-level error")
	assert.Empty(t, result.Items, "Expected no verification errors")
	mockAttestationService.AssertExpectations(t)

	results := internal.ReadResultsFromChannel(t, outCh)
	require.Len(t, results, 2, "Expected one result in batcher")

	assert.Equal(t, task1.MessageID, results[0].MessageID.String())
	assert.Equal(t, "0xf0f3a135abcdef", results[0].Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{ccvAddress1, ccvAddress2}, results[0].CCVAddresses)
	assert.Equal(t, executorAddress, results[0].ExecutorAddress)
	assert.Equal(t, lbtc.CCVVerifierVersion, results[0].CCVVersion)

	assert.Equal(t, task2.MessageID, results[1].MessageID.String())
	assert.Equal(t, "0xf0f3a135123456", results[1].Signature.String())
	assert.Equal(t, []protocol.UnknownAddress{ccvAddress1, ccvAddress2}, results[1].CCVAddresses)
	assert.Equal(t, executorAddress, results[1].ExecutorAddress)
	assert.Equal(t, lbtc.CCVVerifierVersion, results[1].CCVVersion)
}

func TestVerifier_VerifyMessages_NotReadyMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLBTCAttestationService(t)

	task1 := createTestVerificationTask(1)
	task2 := createTestVerificationTask(2)
	task3 := createTestVerificationTask(3)
	tasks := []verifier.VerificationTask{task1, task2, task3}

	attestations := map[string]lbtc.Attestation{
		task1.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.CCVVerifierVersion,
			lbtc.AttestationResponse{
				MessageHash: "0xdeadbeef",
				Status:      lbtc.AttestationStatusApproved,
				Data:        "0xabcdef",
			},
		),
		task2.Message.MustMessageID().String(): lbtc.NewAttestation(
			lbtc.CCVVerifierVersion,
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

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 3, 1*time.Millisecond, outCh)

	v := lbtc.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	cancel()
	_ = ccvDataBatcher.Close()

	// Task1 should pass, Task2 is not ready, Task3 not found
	assert.NoError(t, result.Error, "Expected no batch-level error")
	require.Len(t, result.Items, 2)

	assert.Equal(t, result.Items[0].Task.MessageID, task2.MessageID)
	assert.EqualError(t, result.Items[0].Error, "attestation not ready for message ID: "+task2.MessageID)
	assert.Equal(t, result.Items[1].Task.MessageID, task3.MessageID)
	assert.EqualError(t, result.Items[1].Error, "attestation not found for message ID: "+task3.MessageID)

	mockAttestationService.AssertExpectations(t)
	results := internal.ReadResultsFromChannel(t, outCh)
	require.Len(t, results, 1, "Expected one result in batcher")

	assert.Equal(t, task1.MessageID, results[0].MessageID.String())
}

func createTestVerificationTask(sequenceNumber int) verifier.VerificationTask {
	message := protocol.Message{
		SourceChainSelector: protocol.ChainSelector(1),
		DestChainSelector:   protocol.ChainSelector(2),
		SequenceNumber:      protocol.SequenceNumber(sequenceNumber),
	}

	messageID := message.MustMessageID()
	return verifier.VerificationTask{
		MessageID: messageID.String(),
		Message:   message,
		TxHash:    protocol.ByteSlice{0xaa, 0xbb, 0xcc},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			// Create receipt structure: [CCV1, CCV2, Executor]
			{Issuer: ccvAddress1, Blob: []byte("ccv1-blob")},
			{Issuer: ccvAddress2, Blob: []byte("ccv2-blob")},
			{Issuer: executorAddress, Blob: []byte("executor-blob")},
		},
		BlockNumber: 12345,
		FirstSeenAt: time.Now(),
		QueuedAt:    time.Now(),
	}
}
