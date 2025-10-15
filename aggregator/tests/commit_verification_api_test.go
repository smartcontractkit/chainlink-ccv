// Package tests contains functional tests for the aggregator service.
package tests

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	ddbconstant "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb/constants"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestAggregationHappyPath(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	messageId, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")
	ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

	// ctxWithMetadata := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("committee", "default"))
	resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

	require.NoError(t, err, "failed to compute message ID")
	assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	// Example of signature validation: Verify that the aggregated CCV data contains
	// valid signatures from both signer1 and signer2
	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))
}

func TestAggregationHappyPathMultipleCommittees(t *testing.T) {
	sourceVerifierAddress1, destVerifierAddress1 := GenerateVerifierAddresses(t)
	sourceVerifierAddress2, destVerifierAddress2 := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	signer3 := NewSignerFixture(t, "node3")
	signer4 := NewSignerFixture(t, "node4")
	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress1),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress1).Hex(),
				},
			},
		},
		"secondary": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress2),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer3.Signer,
						signer4.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress2).Hex(),
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	messageId, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")

	// Node 1 from Committee "default" signs
	ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress1, WithSignatureFrom(t, signer1))

	ctxWithMetadataDefault := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("committee", "default"))
	resp1, err := aggregatorClient.WriteCommitCCVNodeData(ctxWithMetadataDefault, &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

	require.NoError(t, err, "failed to compute message ID")
	assertCCVDataNotFound(t, ctxWithMetadataDefault, ccvDataClient, messageId)

	// Node 3 from Committee "secondary" signs
	ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress2, WithSignatureFrom(t, signer3))
	ctxWithMetadataSecondary := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("committee", "secondary"))
	resp3, err := aggregatorClient.WriteCommitCCVNodeData(ctxWithMetadataSecondary, &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData3,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataNotFound(t, ctxWithMetadataSecondary, ccvDataClient, messageId)
	assertCCVDataNotFound(t, ctxWithMetadataDefault, ccvDataClient, messageId)

	// Node 2 from Committee "default" signs
	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress1, WithSignatureFrom(t, signer2))

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(ctxWithMetadataDefault, &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, ctxWithMetadataDefault, ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress1, destVerifierAddress1, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))
	assertCCVDataNotFound(t, ctxWithMetadataSecondary, ccvDataClient, messageId)

	// Node 4 from Committee "secondary" signs
	ccvNodeData4 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress2, WithSignatureFrom(t, signer4))
	resp4, err := aggregatorClient.WriteCommitCCVNodeData(ctxWithMetadataSecondary, &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData4,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp4.Status, "expected WriteStatus_SUCCESS")
	assertCCVDataFound(t, ctxWithMetadataSecondary, ccvDataClient, messageId, ccvNodeData4.GetMessage(), sourceVerifierAddress2, destVerifierAddress2, WithValidSignatureFrom(signer3), WithValidSignatureFrom(signer4))
}

func TestIdempotency(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	ccvNodeData := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

	for i := 0; i < 2; i++ {
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")
		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)
	}
}

// SignatureValidationOption defines options for signature validation in assertCCVDataFound.
type SignatureValidationOption func(*signatureValidationConfig)

type signatureValidationConfig struct {
	expectedSigners         []*SignerFixture
	exactNumberOfSignatures *int
	expectActualCCVData     [][]byte
}

func WithExactNumberOfSignatures(n int) SignatureValidationOption {
	return func(config *signatureValidationConfig) {
		config.exactNumberOfSignatures = &n
	}
}

// WithValidSignatureFrom validates that the CCV data contains a valid signature from the specified signer.
func WithValidSignatureFrom(signer *SignerFixture) SignatureValidationOption {
	return func(config *signatureValidationConfig) {
		config.expectedSigners = append(config.expectedSigners, signer)
	}
}

func assertCCVDataNotFound(t *testing.T, ctx context.Context, ccvDataClient pb.CCVDataClient, messageId protocol.Bytes32) {
	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)
	respCcvData, err := ccvDataClient.GetCCVDataForMessage(ctx, &pb.GetCCVDataForMessageRequest{
		MessageId: messageId[:],
	})
	require.Error(t, err, "GetCCVDataForMessage failed")
	require.Equal(t, codes.NotFound, status.Code(err), "expected NotFound error code")
	require.Nil(t, respCcvData, "expected nil response")
}

func assertCCVDataFound(
	t *testing.T,
	ctx context.Context,
	ccvDataClient pb.CCVDataClient,
	messageId protocol.Bytes32,
	message *pb.Message,
	sourceVerifierAddress []byte,
	destVerifierAddress []byte,
	options ...SignatureValidationOption,
) *pb.MessageWithCCVData {
	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)
	respCcvData, err := ccvDataClient.GetCCVDataForMessage(ctx, &pb.GetCCVDataForMessageRequest{
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
	require.Equal(t, message.Nonce, respCcvData.GetMessage().GetNonce())
	require.Equal(t, message.SourceChainSelector, respCcvData.GetMessage().GetSourceChainSelector())
	require.Equal(t, message.DestChainSelector, respCcvData.GetMessage().GetDestChainSelector())
	require.Equal(t, message.TokenTransferLength, respCcvData.GetMessage().GetTokenTransferLength())
	require.True(t, bytes.Equal(message.TokenTransfer, respCcvData.GetMessage().GetTokenTransfer()))
	require.Equal(t, message.Version, respCcvData.GetMessage().GetVersion())

	require.Equal(t, respCcvData.DestVerifierAddress, destVerifierAddress)
	require.Equal(t, respCcvData.SourceVerifierAddress, sourceVerifierAddress)

	// Validate signatures if options are provided
	require.NotNil(t, respCcvData.CcvData)
	if len(options) > 0 {
		validateSignatures(t, respCcvData.CcvData, messageId, options...)
	}

	return respCcvData
}

// validateSignatures decodes the CCV data and validates signatures from expected signers.
func validateSignatures(t *testing.T, ccvData []byte, messageId protocol.Bytes32, options ...SignatureValidationOption) {
	// Build configuration from options
	config := &signatureValidationConfig{}
	for _, opt := range options {
		opt(config)
	}

	if len(config.expectedSigners) == 0 {
		return // Nothing to validate
	}

	// Decode the signature data
	rs, ss, err := protocol.DecodeSignatures(ccvData)
	require.NoError(t, err, "failed to decode CCV signature data")
	require.Equal(t, len(rs), len(ss), "rs and ss arrays should have the same length")

	// Validate that we have at least one signature
	require.Greater(t, len(rs), 0, "should have at least one signature")

	// Validate that signatures are non-zero (basic sanity check)
	for i, r := range rs {
		require.NotEqual(t, [32]byte{}, r, "signature R[%d] should not be zero", i)
		require.NotEqual(t, [32]byte{}, ss[i], "signature S[%d] should not be zero", i)
	}

	// Recover signer addresses from the aggregated signatures
	recoveredAddresses, err := protocol.RecoverSigners(messageId, rs, ss)
	require.NoError(t, err, "failed to recover signer addresses")

	// Create a map of expected signer addresses for easier lookup
	expectedAddresses := make(map[common.Address]string)
	for _, expectedSigner := range config.expectedSigners {
		require.NotEmpty(t, expectedSigner.Signer.Addresses, "expected signer should have at least one address")
		addr := common.HexToAddress(expectedSigner.Signer.Addresses[0])
		expectedAddresses[addr] = expectedSigner.Signer.ParticipantID
	}

	// Verify that signature recovery works and produces valid addresses
	require.Equal(t, len(rs), len(recoveredAddresses), "should recover one address per signature")
	for _, addr := range recoveredAddresses {
		require.NotEqual(t, common.Address{}, addr, "recovered address should not be zero")
	}

	// Verify that all expected signers are present in the recovered addresses
	for expectedAddr, participantID := range expectedAddresses {
		found := false
		for _, recoveredAddr := range recoveredAddresses {
			if recoveredAddr == expectedAddr {
				found = true
				break
			}
		}
		require.True(t, found, "expected signer %s (participant %s) not found in recovered addresses", expectedAddr.Hex(), participantID)
	}

	if config.exactNumberOfSignatures != nil {
		require.Equal(t, *config.exactNumberOfSignatures, len(rs), "number of signatures does not match expected")
	}

	if len(config.expectActualCCVData) > 0 {
		for _, expectedSig := range config.expectActualCCVData {
			found := false
			expectedR, expectedS, err := protocol.DecodeSignatures(expectedSig)
			require.NoError(t, err, "failed to decode expected signature")
			for i := range rs {
				if rs[i] == expectedR[0] && ss[i] == expectedS[0] {
					found = true
					break
				}
			}
			require.True(t, found, "expected signature (R,S) pair not found")
		}
	}
}

// Test where a valid signer sign but is later removed from the committee and another valider signs but aggregation should not complete. Only when we sign with a third valid signer it succeeds.
func TestChangingCommitteeBeforeAggregation(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	signer3 := NewSignerFixture(t, "node3")
	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	messageId, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")
	ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

	resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

	// Change committee to remove signer1 and add signer3
	config["default"].QuorumConfigs["2"] = &model.QuorumConfig{
		Threshold: 2,
		Signers: []model.Signer{
			signer2.Signer,
			signer3.Signer,
		},
		CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
	}

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

	ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))

	resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData3,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer2), WithValidSignatureFrom(signer3))
}

func TestChangingCommitteeAfterAggregation(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")
	signer3 := NewSignerFixture(t, "node3")
	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	messageId, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")
	ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

	resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})

	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

	// Change committee to remove signer1 and add signer3
	config["default"].QuorumConfigs["2"] = &model.QuorumConfig{
		Threshold: 2,
		Signers: []model.Signer{
			signer2.Signer,
			signer3.Signer,
		},
		CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
	}

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(1))

	// Ensure that we can still write new signatures with the updated committee
	ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))

	resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData3,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer2), WithValidSignatureFrom(signer3), WithExactNumberOfSignatures(2))
}

// TestPaginationWithVariousPageSizes tests the GetMessagesSince API with pagination.
func TestPaginationWithVariousPageSizes(t *testing.T) {
	testCases := []struct {
		name        string
		numMessages int
		pageSize    int
		description string
	}{
		{
			name:        "basic_pagination",
			numMessages: 15,
			pageSize:    5,
			description: "Basic pagination with small dataset",
		},
		{
			name:        "single_page",
			numMessages: 8,
			pageSize:    10,
			description: "All messages fit in single page",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running test case: %s - %s", tc.name, tc.description)
			runPaginationTest(t, tc.numMessages, tc.pageSize)
		})
	}
}

func runPaginationTest(t *testing.T, numMessages, pageSize int) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")

	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}

	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(
		t,
		WithCommitteeConfig(config),
		WithStorageType("dynamodb"),
		WithPaginationConfig(pageSize),
	)
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	t.Logf("Creating and submitting %d messages with page size %d...", numMessages, pageSize)

	expectedMessageIds := make(map[string]bool)

	for i := 0; i < numMessages; i++ {
		message := NewProtocolMessage(t)
		message.Nonce = protocol.Nonce(i + 1)

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID for message %d", i)
		expectedMessageIds[common.Bytes2Hex(messageId[:])] = true

		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer1", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer2", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)
	}

	t.Logf("All %d messages submitted", numMessages)

	time.Sleep(2 * time.Second)

	t.Log("Paginating through all messages...")
	retrievedMessages := make(map[string]bool)
	var nextToken string
	pageCount := 0

	for {
		pageCount++
		req := &pb.GetMessagesSinceRequest{
			Since: 0,
		}
		if nextToken != "" {
			req.NextToken = nextToken
		}

		resp, err := ccvDataClient.GetMessagesSince(t.Context(), req)
		require.NoError(t, err, "GetMessagesSince failed on page %d", pageCount)
		require.NotNil(t, resp, "response should not be nil")

		t.Logf("Page %d: retrieved %d reports", pageCount, len(resp.Results))

		for _, report := range resp.Results {
			msg := &protocol.Message{
				Version:              uint8(report.Message.Version),
				SourceChainSelector:  protocol.ChainSelector(report.Message.SourceChainSelector),
				DestChainSelector:    protocol.ChainSelector(report.Message.DestChainSelector),
				Nonce:                protocol.Nonce(report.Message.Nonce),
				OnRampAddressLength:  uint8(report.Message.OnRampAddressLength),
				OnRampAddress:        report.Message.OnRampAddress,
				OffRampAddressLength: uint8(report.Message.OffRampAddressLength),
				OffRampAddress:       report.Message.OffRampAddress,
				Finality:             uint16(report.Message.Finality),
				SenderLength:         uint8(report.Message.SenderLength),
				Sender:               report.Message.Sender,
				ReceiverLength:       uint8(report.Message.ReceiverLength),
				Receiver:             report.Message.Receiver,
				DestBlobLength:       uint16(report.Message.DestBlobLength),
				DestBlob:             report.Message.DestBlob,
				TokenTransferLength:  uint16(report.Message.TokenTransferLength),
				TokenTransfer:        report.Message.TokenTransfer,
				DataLength:           uint16(report.Message.DataLength),
				Data:                 report.Message.Data,
			}

			messageId, err := msg.MessageID()
			require.NoError(t, err, "failed to compute message ID")
			messageIdHex := common.Bytes2Hex(messageId[:])

			require.False(t, retrievedMessages[messageIdHex], "duplicate message found: %s", messageIdHex)
			retrievedMessages[messageIdHex] = true
		}

		if resp.NextToken == "" {
			t.Logf("Pagination complete after %d pages", pageCount)
			break
		}

		nextToken = resp.NextToken
		require.Less(t, pageCount, 100, "too many pages - possible infinite loop")
	}

	require.Equal(t, numMessages, len(retrievedMessages), "should retrieve all messages")

	for expectedId := range expectedMessageIds {
		require.True(t, retrievedMessages[expectedId], "message %s was not retrieved", expectedId)
	}

	t.Logf("✅ Pagination test completed: %d messages retrieved across %d pages", len(retrievedMessages), pageCount)
}

// TestMultiShardPagination tests pagination with multiple shard configurations.
func TestMultiShardPagination(t *testing.T) {
	tests := []struct {
		name       string
		shardCount int
		pageSize   int
	}{
		{
			name:       "two_shard_pagination",
			shardCount: 2,
			pageSize:   5,
		},
		{
			name:       "three_shard_pagination",
			shardCount: 3,
			pageSize:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running multi-shard pagination test with %d shards and page size %d",
				tt.shardCount, tt.pageSize)
			runMultiShardPaginationTest(t, tt.shardCount, tt.pageSize)
		})
	}
}

func runMultiShardPaginationTest(t *testing.T, shardCount, pageSize int) {
	const totalMessages = 20

	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")

	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}

	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(
		t,
		WithCommitteeConfig(config),
		WithStorageType("dynamodb"),
		WithPaginationConfig(pageSize),
		WithShardCount(shardCount),
	)
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	t.Logf("Creating %d messages with %d shards...", totalMessages, shardCount)

	expectedMessageIds := make(map[string]bool)
	shardCounts := make(map[string]int)

	for i := 0; i < totalMessages; i++ {
		message := NewProtocolMessage(t)
		message.Nonce = protocol.Nonce(i + 1)

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID for message %d", i)
		expectedMessageIds[common.Bytes2Hex(messageId[:])] = true

		shard := ddbconstant.CalculateShardFromMessageID(messageId[:], shardCount)
		shardCounts[shard]++

		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(context.Background(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(context.Background(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)
	}

	t.Logf("All %d messages submitted", totalMessages)
	t.Logf("Shard distribution:")
	for shard, count := range shardCounts {
		t.Logf("  %s: %d messages", shard, count)
	}

	time.Sleep(2 * time.Second)

	t.Logf("Paginating through messages across %d shards...", shardCount)
	retrievedMessages := make(map[string]bool)
	var nextToken string
	pageCount := 0

	for {
		pageCount++
		req := &pb.GetMessagesSinceRequest{
			Since: 0,
		}
		if nextToken != "" {
			req.NextToken = nextToken
		}

		resp, err := ccvDataClient.GetMessagesSince(context.Background(), req)
		require.NoError(t, err, "GetMessagesSince failed on page %d", pageCount)
		require.NotNil(t, resp)

		t.Logf("Page %d: retrieved %d reports", pageCount, len(resp.Results))

		for _, report := range resp.Results {
			msg := &protocol.Message{
				Version:              uint8(report.Message.Version),
				SourceChainSelector:  protocol.ChainSelector(report.Message.SourceChainSelector),
				DestChainSelector:    protocol.ChainSelector(report.Message.DestChainSelector),
				Nonce:                protocol.Nonce(report.Message.Nonce),
				OnRampAddressLength:  uint8(report.Message.OnRampAddressLength),
				OnRampAddress:        report.Message.OnRampAddress,
				OffRampAddressLength: uint8(report.Message.OffRampAddressLength),
				OffRampAddress:       report.Message.OffRampAddress,
				Finality:             uint16(report.Message.Finality),
				SenderLength:         uint8(report.Message.SenderLength),
				Sender:               report.Message.Sender,
				ReceiverLength:       uint8(report.Message.ReceiverLength),
				Receiver:             report.Message.Receiver,
				DestBlobLength:       uint16(report.Message.DestBlobLength),
				DestBlob:             report.Message.DestBlob,
				TokenTransferLength:  uint16(report.Message.TokenTransferLength),
				TokenTransfer:        report.Message.TokenTransfer,
				DataLength:           uint16(report.Message.DataLength),
				Data:                 report.Message.Data,
			}

			messageId, err := msg.MessageID()
			require.NoError(t, err)
			messageIdHex := common.Bytes2Hex(messageId[:])

			require.False(t, retrievedMessages[messageIdHex], "duplicate message: %s", messageIdHex)
			retrievedMessages[messageIdHex] = true
		}

		if resp.NextToken == "" {
			t.Logf("Pagination complete after %d pages", pageCount)
			break
		}

		nextToken = resp.NextToken
		require.Less(t, pageCount, 100, "too many pages - possible infinite loop")
	}

	require.Equal(t, totalMessages, len(retrievedMessages), "should retrieve all messages")

	for expectedId := range expectedMessageIds {
		require.True(t, retrievedMessages[expectedId], "message %s was not retrieved", expectedId)
	}

	t.Logf("✅ Multi-shard pagination test completed: %d messages retrieved across %d shards and %d pages",
		len(retrievedMessages), shardCount, pageCount)
}

// TestParticipantDeduplication verifies that only one verification per participant
// is included in the aggregated report, keeping the most recent one.
func TestParticipantDeduplication(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")

	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}

	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message := NewProtocolMessage(t)
	messageId, err := message.MessageID()
	require.NoError(t, err, "failed to compute message ID")

	oldTimestamp := time.Now().Add(-1 * time.Hour).UnixMicro()
	ccvNodeData1Old := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
		WithSignatureFrom(t, signer1),
		WithCustomTimestamp(oldTimestamp))

	resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1Old,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed for signer1 (old)")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

	newTimestamp := time.Now().Add(-30 * time.Minute).UnixMicro()
	ccvNodeData1New := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
		WithSignatureFrom(t, signer1),
		WithCustomTimestamp(newTimestamp))

	resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1New,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed for signer1 (new)")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

	ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
		WithSignatureFrom(t, signer2))

	resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed for signer2")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	time.Sleep(100 * time.Millisecond)

	aggResp1 := assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
		WithExactNumberOfSignatures(2),
		WithValidSignatureFrom(signer2),
		WithValidSignatureFrom(signer1),
	)

	// Wait a second to ensure the aggregation timestamp is different (we use write time as aggregation time)
	time.Sleep(1 * time.Second)

	newerTimestamp := time.Now().UnixMicro()
	ccvNodeData1Newer := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
		WithSignatureFrom(t, signer1),
		WithCustomTimestamp(newerTimestamp))

	resp4, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1Newer,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed for signer1 (new)")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp4.Status, "expected WriteStatus_SUCCESS")

	aggResp2 := assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
		WithExactNumberOfSignatures(2),
		WithValidSignatureFrom(signer2),
		WithValidSignatureFrom(signer1),
	)

	require.Greater(t, aggResp2.Timestamp, aggResp1.Timestamp, "We should have a newer aggregation timestamp")
}

// TestWriteTimeOrdering verifies that GetMessagesSince returns reports ordered by WrittenAt.
func TestWriteTimeOrdering(t *testing.T) {
	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")

	config := map[string]*model.Committee{
		"default": {
			SourceVerifierAddresses: map[string]string{
				"1": common.Bytes2Hex(sourceVerifierAddress),
			},
			QuorumConfigs: map[string]*model.QuorumConfig{
				"2": {
					Threshold: 2,
					Signers: []model.Signer{
						signer1.Signer,
						signer2.Signer,
					},
					CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
				},
			},
		},
	}

	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType("dynamodb"))
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	message1 := NewProtocolMessage(t, WithNonce(100))
	messageId1, err := message1.MessageID()
	require.NoError(t, err, "failed to compute message ID 1")

	oldTime := time.Now().Add(-24 * time.Hour).UnixMicro()

	message2 := NewProtocolMessage(t, WithNonce(200))
	messageId2, err := message2.MessageID()
	require.NoError(t, err, "failed to compute message ID 2")

	recentTime := time.Now().UnixMicro()

	t.Log("Submitting message 2 with recent timestamps - will aggregate first")
	ccvNodeData2_1 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress,
		WithSignatureFrom(t, signer1),
		WithCustomTimestamp(recentTime))

	resp, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2_1,
	})
	require.NoError(t, err)
	require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

	ccvNodeData2_2 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress,
		WithSignatureFrom(t, signer2),
		WithCustomTimestamp(recentTime))

	resp, err = aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData2_2,
	})
	require.NoError(t, err)
	require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

	time.Sleep(500 * time.Millisecond)

	_, err = ccvDataClient.GetCCVDataForMessage(t.Context(), &pb.GetCCVDataForMessageRequest{
		MessageId: messageId2[:],
	})
	require.NoError(t, err, "Message 2 should be aggregated")

	t.Log("Submitting message 1 with old timestamps - will aggregate second")
	ccvNodeData1_1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress,
		WithSignatureFrom(t, signer1),
		WithCustomTimestamp(oldTime))

	resp, err = aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1_1,
	})
	require.NoError(t, err)
	require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

	ccvNodeData1_2 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress,
		WithSignatureFrom(t, signer2),
		WithCustomTimestamp(oldTime))

	resp, err = aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData1_2,
	})
	require.NoError(t, err)
	require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

	time.Sleep(500 * time.Millisecond)

	_, err = ccvDataClient.GetCCVDataForMessage(t.Context(), &pb.GetCCVDataForMessageRequest{
		MessageId: messageId1[:],
	})
	require.NoError(t, err, "Message 1 should be aggregated")

	resp2, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
		Since: 0,
	})
	require.NoError(t, err, "GetMessagesSince should succeed")
	require.Len(t, resp2.Results, 2, "Should return 2 messages")

	t.Logf("First result timestamp: %d", resp2.Results[0].Timestamp)
	t.Logf("Second result timestamp: %d", resp2.Results[1].Timestamp)

	result1MessageID := resp2.Results[0].Message.Nonce
	result2MessageID := resp2.Results[1].Message.Nonce

	require.Equal(t, uint64(200), result1MessageID, "First result should be message2 (nonce 200)")
	require.Equal(t, uint64(100), result2MessageID, "Second result should be message1 (nonce 100)")

	require.LessOrEqual(t, resp2.Results[0].Timestamp, resp2.Results[1].Timestamp,
		"First message (written first) should have earlier or equal WrittenAt than second message (written second)")

	t.Log("SUCCESS: GetMessagesSince returns items ordered by write time, not verification time")
}
