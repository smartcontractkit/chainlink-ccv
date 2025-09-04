// Package functionaltests contains functional tests for the aggregator service.
package functionaltests

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func createRandomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestReadWriteCommitVerification(t *testing.T) {
	config := map[string]model.Committee{
		"committee1": {
			QuorumConfigs: map[uint64]model.QuorumConfig{
				1: {
					F: 0,
				},
			},
		},
	}
	client, cleanup, err := CreateServerAndClient(t, config)
	if err != nil {
		t.Fatalf("failed to create server and client: %v", err)
	}
	t.Cleanup(cleanup)

	participantID := hex.EncodeToString(createRandomBytes(t, 32))
	committeeID := hex.EncodeToString(createRandomBytes(t, 32))
	messageID := createRandomBytes(t, 32)
	destVerifierAddr := createRandomBytes(t, 20)
	sourceVerifierAddr := createRandomBytes(t, 20)

	writeResp, err := client.WriteCommitVerification(t.Context(), &aggregator.WriteCommitVerificationRequest{
		ParticipantId: participantID,
		CommitteeId:   committeeID,
		CommitVerificationRecord: &aggregator.CommitVerificationRecord{
			MessageId:             messageID,
			BlobData:              []byte("test blob data"),
			CcvData:               []byte("test ccv data"),
			DestChainSelector:     uint64(1),
			DestVerifierAddress:   destVerifierAddr,
			SequenceNumber:        uint64(1),
			SourceChainSelector:   uint64(2),
			SourceVerifierAddress: sourceVerifierAddr,
			Timestamp:             uint32(1234567890),
			Message:               &aggregator.Any2AnyMessage{},
		},
	})

	require.NoError(t, err, "WriteCommitVerification failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, writeResp.Status, "expected WriteStatus_SUCCESS")

	readResp, err := client.ReadCommitVerification(t.Context(), &aggregator.ReadCommitVerificationRequest{
		ParticipantId: participantID,
		CommitteeId:   committeeID,
		MessageId:     messageID,
	})

	require.NoError(t, err, "ReadCommitVerification failed")
	require.NotNil(t, readResp, "expected non-nil response")
	require.Equal(t, messageID, readResp.CommitVerificationRecord.MessageId, "expected MessageId to match")

	queryResp, err := client.QueryAggregatedCommitRecords(t.Context(), &aggregator.QueryAggregatedCommitRecordsRequest{
		Start: timestamppb.New(timestamppb.Now().AsTime().Add(-1 * 60 * 60 * 1000000000)), // 1 hour ago
		End:   timestamppb.New(timestamppb.Now().AsTime()),
	})

	require.NoError(t, err, "QueryAggregatedCommitRecords failed")
	require.NotNil(t, queryResp, "expected non-nil response")
	require.Len(t, queryResp.Records, 1, "expected exactly 1 record")
	record := queryResp.Records[0]
	require.Equal(t, messageID, record.MessageId, "expected MessageId to match")
}
