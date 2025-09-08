// Package tests contains functional tests for the aggregator service.
package tests

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStubMode(true))
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
		Address:   make([]byte, 20),
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

func TestAggregationHappyPath(t *testing.T) {
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	config := map[string]model.Committee{
		"committee1": {
			QuorumConfigs: map[uint64]*model.QuorumConfig{
				2: {
					F: 1,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	messageId, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")
	ccvNodeData1 := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer1))

	resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer2))

	respCcvData, err := ccvDataClient.GetCCVDataForMessage(t.Context(), &aggregator.GetCCVDataForMessageRequest{
		MessageId: messageId[:],
	})
	require.Error(t, err, "GetCCVDataForMessage failed")
	require.Equal(t, codes.NotFound, status.Code(err), "expected NotFound error code")
	require.Nil(t, respCcvData, "expected nil response")

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)

	respCcvData, err = ccvDataClient.GetCCVDataForMessage(t.Context(), &aggregator.GetCCVDataForMessageRequest{
		MessageId: messageId[:],
	})
	require.NoError(t, err, "GetCCVDataForMessage failed")
	require.NotNil(t, respCcvData, "expected non-nil response")
}
