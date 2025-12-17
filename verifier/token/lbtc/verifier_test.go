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
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lbtc"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const verifierVersionHex = "f0f3a135"

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewLBTCAttestationService(t)

	ccvVersion, err := protocol.NewByteSliceFromHex(verifierVersionHex)
	require.NoError(t, err)
	task1 := createTestVerificationTask(1)
	task2 := createTestVerificationTask(2)
	tasks := []verifier.VerificationTask{task1, task2}

	attestations := map[string]lbtc.Attestation{
		task1.Message.MustMessageID().String(): lbtc.NewAttestationFields(ccvVersion, "0xabcdef", lbtc.AttestationStatusApproved),
		task2.Message.MustMessageID().String(): lbtc.NewAttestationFields(ccvVersion, "0xabcdef", lbtc.AttestationStatusApproved),
	}

	mockAttestationService.EXPECT().
		Fetch(ctx, []protocol.Message{task1.Message, task2.Message}).
		Return(attestations, nil).
		Once()

	outCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	ccvDataBatcher := batcher.NewBatcher(ctx, 100, 1*time.Second, outCh)

	v := lbtc.NewVerifier(lggr, mockAttestationService)
	result := v.VerifyMessages(ctx, tasks, ccvDataBatcher)

	cancel()
	_ = ccvDataBatcher.Close()

	assert.NoError(t, result.Error, "Expected no batch-level error")
	assert.Empty(t, result.Items, "Expected no verification errors")
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_AttestationServiceFailure(t *testing.T) {}

func TestVerifier_VerifyMessages_NotReadyMessages(t *testing.T) {}

func createTestVerificationTask(sequenceNumber int) verifier.VerificationTask {
	message := protocol.Message{
		SourceChainSelector: protocol.ChainSelector(1),
		DestChainSelector:   protocol.ChainSelector(2),
		SequenceNumber:      protocol.SequenceNumber(sequenceNumber),
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
