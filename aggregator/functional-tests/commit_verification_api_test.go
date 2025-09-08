// Package functionaltests contains functional tests for the aggregator service.
package functionaltests

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
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
			QuorumConfigs: map[uint64]*model.QuorumConfig{
				1: {
					F: 0,
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, config)
	if err != nil {
		t.Fatalf("failed to create server and client: %v", err)
	}
	t.Cleanup(cleanup)

	messageID := createRandomBytes(t, 32)
	destVerifierAddr := createRandomBytes(t, 20)
	sourceVerifierAddr := createRandomBytes(t, 20)

	writeResp, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: &aggregator.MessageWithCCVNodeData{
			MessageId:             messageID,
			BlobData:              []byte("test blob data"),
			CcvData:               []byte("test ccv data"),
			DestVerifierAddress:   destVerifierAddr,
			SourceVerifierAddress: sourceVerifierAddr,
			Timestamp:             1234567890,
			Message: &aggregator.Message{
				Data:              []byte("test message data"),
				DestChainSelector: 1,
			},
		},
	})

	require.NoError(t, err, "WriteCommitVerification failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, writeResp.Status, "expected WriteStatus_SUCCESS")

	readResp, err := aggregatorClient.ReadCommitCCVNodeData(t.Context(), &aggregator.ReadCommitCCVNodeDataRequest{
		MessageId: messageID,
	})

	require.NoError(t, err, "ReadCommitCCVNodeData failed")
	require.NotNil(t, readResp, "expected non-nil response")
	require.Equal(t, messageID, readResp.CcvNodeData.MessageId, "expected MessageId to match")

	messagesSinceResponse, err := ccvDataClient.GetMessagesSince(t.Context(), &aggregator.GetMessagesSinceRequest{
		Since: time.Now().Add(-1 * time.Hour).Unix(),
	})

	require.NoError(t, err, "GetMessagesSince failed")
	require.NotNil(t, messagesSinceResponse, "expected non-nil response")
	require.Len(t, messagesSinceResponse.Results, 1, "expected exactly 1 record")
	require.Equal(t, []byte("test message data"), messagesSinceResponse.Results[0].Message.Data, "expected MessageId to match")

	getCCVDataResponse, err := ccvDataClient.GetCCVDataForMessage(t.Context(), &aggregator.GetCCVDataForMessageRequest{
		MessageId: messageID,
	})

	require.NoError(t, err, "GetCCVData failed")
	require.NotNil(t, getCCVDataResponse, "expected non-nil response")
	require.Equal(t, []byte("test message data"), getCCVDataResponse.Message.Data, "expected CCV data to match")
}
