// Package tests contains functional tests for the aggregator service.
package tests

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func TestReadWriteCommitVerification(t *testing.T) {
	signer1 := NewSignerFixture(t, "node1")
	config := map[string]*model.Committee{
		"committee1": {
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 0,
					Signers: []model.Signer{
						signer1.Signer,
					},
					OfframpAddress: "0x00000000000000000000000000000000000000000",
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStubMode(true))
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

	assertCCVDataFound(t, ccvDataClient, messageId, ccvNodeData1.GetMessage())
}

func TestAggregationHappyPath(t *testing.T) {
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	config := map[string]*model.Committee{
		"committee1": {
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 1,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					OfframpAddress: "0x00000000000000000000000000000000000000000",
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

	require.NoError(t, err, "failed to compute message ID")
	assertCCVDataNotFound(t, ccvDataClient, messageId)

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)

	respCcvData, err := ccvDataClient.GetCCVDataForMessage(t.Context(), &aggregator.GetCCVDataForMessageRequest{
		MessageId: messageId[:],
	})
	require.NoError(t, err, "GetCCVDataForMessage failed")
	require.NotNil(t, respCcvData, "expected non-nil response")
}

func TestIdempotency(t *testing.T) {
	signer1 := NewSignerFixture(t, "node1")
	config := map[string]*model.Committee{
		"committee1": {
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 1,
					Signers: []model.Signer{
						signer1.Signer,
					},
					OfframpAddress: "0x00000000000000000000000000000000000000000",
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	ccvNodeData := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer1))

	for i := 0; i < 2; i++ {
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed")
		require.Equal(t, aggregator.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")
		assertCCVDataNotFound(t, ccvDataClient, messageId)
	}
}

func assertCCVDataNotFound(t *testing.T, ccvDataClient aggregator.CCVDataClient, messageId types.Bytes32) {
	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)
	respCcvData, err := ccvDataClient.GetCCVDataForMessage(t.Context(), &aggregator.GetCCVDataForMessageRequest{
		MessageId: messageId[:],
	})
	require.Error(t, err, "GetCCVDataForMessage failed")
	require.Equal(t, codes.NotFound, status.Code(err), "expected NotFound error code")
	require.Nil(t, respCcvData, "expected nil response")
}

func assertCCVDataFound(t *testing.T, ccvDataClient aggregator.CCVDataClient, messageId types.Bytes32, message *aggregator.Message) {
	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)
	respCcvData, err := ccvDataClient.GetCCVDataForMessage(t.Context(), &aggregator.GetCCVDataForMessageRequest{
		MessageId: messageId[:],
	})
	require.NoError(t, err, "GetCCVDataForMessage failed")
	require.NotNil(t, respCcvData, "expected non-nil response")
	require.Equal(t, message.DataLength, respCcvData.GetMessage().GetDataLength())
	require.Equal(t, message.Data, respCcvData.GetMessage().GetData())
	require.Equal(t, message.DestBlobLength, respCcvData.GetMessage().GetDestBlobLength())
	require.Equal(t, message.DestBlob, respCcvData.GetMessage().GetDestBlob())
	require.Equal(t, message.Finality, respCcvData.GetMessage().GetFinality())
	require.Equal(t, message.OffRampAddressLength, respCcvData.GetMessage().GetOffRampAddressLength())
	require.Equal(t, message.OffRampAddress, respCcvData.GetMessage().GetOffRampAddress())
	require.Equal(t, message.OnRampAddressLength, respCcvData.GetMessage().GetOnRampAddressLength())
	require.Equal(t, message.OnRampAddress, respCcvData.GetMessage().GetOnRampAddress())
	require.Equal(t, message.ReceiverLength, respCcvData.GetMessage().GetReceiverLength())
	require.Equal(t, message.Receiver, respCcvData.GetMessage().GetReceiver())
	require.Equal(t, message.SenderLength, respCcvData.GetMessage().GetSenderLength())
	require.Equal(t, message.Sender, respCcvData.GetMessage().GetSender())
	require.Equal(t, message.SequenceNumber, respCcvData.GetMessage().GetSequenceNumber())
	require.Equal(t, message.SourceChainSelector, respCcvData.GetMessage().GetSourceChainSelector())
	require.Equal(t, message.DestChainSelector, respCcvData.GetMessage().GetDestChainSelector())
	require.Equal(t, message.TokenTransferLength, respCcvData.GetMessage().GetTokenTransferLength())
	require.True(t, bytes.Equal(message.TokenTransfer, respCcvData.GetMessage().GetTokenTransfer()))
	require.Equal(t, message.Version, respCcvData.GetMessage().GetVersion())

	require.Equal(t, respCcvData.DestVerifierAddress, message.OffRampAddress)
	require.Equal(t, respCcvData.SourceVerifierAddress, message.OnRampAddress)
	// TODO: Validate signatures
	require.NotNil(t, respCcvData.CcvData)
}

// Test where a valid signer sign but is later removed from the committee and another valider signs but aggregation should not complete. Only when we sign with a third valid signer it succeeds.
func TestChangingCommitteeBeforeAggregation(t *testing.T) {
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	signer3 := NewSignerFixture(t, "node3")
	config := map[string]*model.Committee{
		"committee1": {
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 1,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					OfframpAddress: "0x00000000000000000000000000000000000000000",
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

	assertCCVDataNotFound(t, ccvDataClient, messageId)

	// Change committee to remove signer1 and add signer3
	config["committee1"].QuorumConfigs["2"] = &model.QuorumConfig{
		Threshold: 1,
		Signers: []model.Signer{
			signer2.Signer,
			signer3.Signer,
		},
		OfframpAddress: "0x00000000000000000000000000000000000000000",
	}

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer2))

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataNotFound(t, ccvDataClient, messageId)

	ccvNodeData3 := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer3))

	resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData3,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, ccvDataClient, messageId, ccvNodeData3.GetMessage())
}

func TestChangingCommitteeAfterAggregation(t *testing.T) {
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	signer3 := NewSignerFixture(t, "node3")
	config := map[string]*model.Committee{
		"committee1": {
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 1,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					OfframpAddress: "0x00000000000000000000000000000000000000000",
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

	assertCCVDataNotFound(t, ccvDataClient, messageId)

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer2))

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, ccvDataClient, messageId, ccvNodeData2.GetMessage())

	// Change committee to remove signer1 and add signer3
	config["committee1"].QuorumConfigs["2"] = &model.QuorumConfig{
		Threshold: 1,
		Signers: []model.Signer{
			signer2.Signer,
			signer3.Signer,
		},
		OfframpAddress: "0x00000000000000000000000000000000000000000",
	}

	assertCCVDataFound(t, ccvDataClient, messageId, ccvNodeData2.GetMessage())

	// Ensure that we can still write new signatures with the updated committee
	ccvNodeData3 := NewMessageWithCCVNodeData(t, message, WithSignatureFrom(t, signer3))

	resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData3,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, aggregator.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, ccvDataClient, messageId, ccvNodeData3.GetMessage())
}
