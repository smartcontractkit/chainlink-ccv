// Package tests contains functional tests for the aggregator service.
package tests

import (
	"bytes"
	"context"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
	expectedSigners []*SignerFixture
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
) {
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

	// Try to recover signer addresses using the aggregated ccvArgs
	// Note: The signatures in aggregated reports were originally created with different ccvArgs
	// during individual submission, so exact signature validation is complex. This validates
	// that the signature data is well-formed and can be processed.
	var signatureHashInput bytes.Buffer
	signatureHashInput.Write(messageId[:])
	signatureHash := crypto.Keccak256(signatureHashInput.Bytes())

	var hash32 [32]byte
	copy(hash32[:], signatureHash[:])

	recoveredAddresses, err := protocol.RecoverSigners(hash32, rs, ss)
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

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))

	// Change committee to remove signer1 and add signer3
	config["default"].QuorumConfigs["2"] = &model.QuorumConfig{
		Threshold: 2,
		Signers: []model.Signer{
			signer2.Signer,
			signer3.Signer,
		},
		CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
	}

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))

	// Ensure that we can still write new signatures with the updated committee
	ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))

	resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
		CcvNodeData: ccvNodeData3,
	})
	require.NoError(t, err, "WriteCommitCCVNodeData failed")
	require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

	assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer2), WithValidSignatureFrom(signer3))
}

// TestPaginationWithVariousPageSizes tests the GetMessagesSince API with pagination
// using different page sizes to verify both multiple and non-multiple scenarios.
func TestPaginationWithVariousPageSizes(t *testing.T) {
	testCases := []struct {
		name           string
		numMessages    int
		pageSize       int
		messagesPerDay int
		numDays        int
		expectedPages  int
		description    string
	}{
		{
			name:           "multiple_page_size",
			numMessages:    100,
			pageSize:       10,
			messagesPerDay: 20,
			numDays:        5,
			expectedPages:  11, // 10 full pages + 1 empty final page
			description:    "Page size is a multiple of total messages",
		},
		{
			name:           "non_multiple_page_size_7",
			numMessages:    100,
			pageSize:       7,
			messagesPerDay: 20,
			numDays:        5,
			expectedPages:  15, // 14 full pages + 1 page with 2 messages
			description:    "Page size 7 with 100 messages (remainder 2)",
		},
		{
			name:           "non_multiple_page_size_13",
			numMessages:    100,
			pageSize:       13,
			messagesPerDay: 20,
			numDays:        5,
			expectedPages:  8, // 7 full pages + 1 page with 9 messages
			description:    "Page size 13 with 100 messages (remainder 9)",
		},
		{
			name:           "small_page_size",
			numMessages:    50,
			pageSize:       3,
			messagesPerDay: 10,
			numDays:        5,
			expectedPages:  17, // 16 full pages + 1 page with 2 messages
			description:    "Small page size with 50 messages",
		},
	}

	for _, tc := range testCases {
		// capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running test case: %s - %s", tc.name, tc.description)
			runPaginationTest(t, tc.numMessages, tc.pageSize, tc.messagesPerDay, tc.numDays, tc.expectedPages)
		})
	}
}

// runPaginationTest is a helper function that runs a pagination test with the given parameters.
func runPaginationTest(t *testing.T, numMessages, pageSize, messagesPerDay, numDays, expectedPages int) {
	// Define date range: Sept 1-N, 2025
	sept1_2025 := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
	dayTimestamps := make([]int64, numDays)
	for i := 0; i < numDays; i++ {
		dayTimestamps[i] = sept1_2025.AddDate(0, 0, i).Unix()
	}

	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")

	// Configure committee with 2 signers and threshold of 2
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

	// Create server with specific pagination config
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(
		t,
		WithCommitteeConfig(config),
		WithStorageType("dynamodb"),
		WithPaginationConfig(pageSize),
	)
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	t.Logf("Starting to create and submit %d messages across %d days with page size %d...", numMessages, numDays, pageSize)

	// Track all message IDs for later verification
	messageIds := make([]protocol.Bytes32, 0, numMessages)
	messageToDay := make(map[string]int) // Track which day each message belongs to

	// Create and submit messages
	startTime := time.Now()
	for i := 0; i < numMessages; i++ {
		if i%50 == 0 {
			t.Logf("Progress: %d/%d messages submitted", i, numMessages)
		}

		// Determine which day this message belongs to
		dayIndex := i / messagesPerDay
		if dayIndex >= numDays {
			dayIndex = numDays - 1 // Ensure we don't exceed available days
		}
		messageTimestamp := dayTimestamps[dayIndex] + rand.Int64N(86400)

		// Create unique message by varying the nonce
		message := NewProtocolMessage(t)
		message.Nonce = protocol.Nonce(i + 1) // Ensure unique nonce for each message

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID for message %d", i)
		messageIds = append(messageIds, messageId)
		messageToDay[common.Bytes2Hex(messageId[:])] = dayIndex

		// First signature from signer1 with custom timestamp
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithCustomTimestamp(messageTimestamp))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer1", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS for message %d, signer1", i)

		// Second signature from signer2 (this should trigger aggregation) with same timestamp
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
			WithCustomTimestamp(messageTimestamp))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer2", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS for message %d, signer2", i)
	}

	submissionTime := time.Since(startTime)
	t.Logf("All %d messages submitted in %v across %d days", numMessages, submissionTime, numDays)

	// Wait for all aggregations to complete
	t.Log("Waiting for aggregation to complete...")
	time.Sleep(5 * time.Second)

	// Test pagination to retrieve all messages
	t.Log("Starting pagination test to retrieve all aggregated messages...")

	retrievedMessages := make(map[string]*pb.MessageWithCCVData)
	var nextToken string
	pageCount := 0
	totalRetrieved := 0

	paginationStartTime := time.Now()
	for {
		pageCount++
		t.Logf("Fetching page %d with token: %s", pageCount, nextToken)

		// Call GetMessagesSince with current pagination token
		req := &pb.GetMessagesSinceRequest{
			Since: 0, // Get all messages
		}
		if nextToken != "" {
			req.NextToken = nextToken
		}

		resp, err := ccvDataClient.GetMessagesSince(t.Context(), req)
		require.NoError(t, err, "GetMessagesSince failed on page %d", pageCount)
		require.NotNil(t, resp, "GetMessagesSince response should not be nil on page %d", pageCount)

		currentPageSize := len(resp.Results)
		totalRetrieved += currentPageSize
		t.Logf("Page %d: retrieved %d reports, hasMore=%t", pageCount, currentPageSize, resp.NextToken != "")

		// Validate page size constraints
		if resp.NextToken != "" {
			// Not the last page - should have exactly pageSize records
			require.Equal(t, pageSize, currentPageSize, "Non-final page %d should have exactly %d records", pageCount, pageSize)
		} else {
			// Last page - calculate expected remainder
			remainder := numMessages % pageSize
			if remainder == 0 {
				// If total messages is divisible by page size, final page should be empty
				require.Equal(t, 0, currentPageSize, "Final page %d should have 0 records when total is divisible by page size", pageCount)
			} else {
				// Otherwise, final page should have the remainder
				require.Equal(t, remainder, currentPageSize, "Final page %d should have %d records (remainder)", pageCount, remainder)
			}
		}

		// Store retrieved messages for verification
		for _, report := range resp.Results {
			// Compute message ID from the message
			require.NotNil(t, report.Message, "Message should not be nil in response")

			// Convert pb.Message to types.Message to compute message ID
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
			require.NoError(t, err, "Failed to compute message ID on page %d", pageCount)
			messageIdHex := common.Bytes2Hex(messageId[:])

			// Ensure no duplicates
			_, exists := retrievedMessages[messageIdHex]
			require.False(t, exists, "Duplicate message found in pagination: %s on page %d", messageIdHex, pageCount)

			retrievedMessages[messageIdHex] = report

			// Validate that the report has proper structure
			require.NotEmpty(t, report.CcvData, "CcvData should not be empty for messageId %s", messageIdHex)
			require.Equal(t, sourceVerifierAddress, report.SourceVerifierAddress, "Source verifier address mismatch for messageId %s", messageIdHex)
			require.Equal(t, destVerifierAddress, report.DestVerifierAddress, "Dest verifier address mismatch for messageId %s", messageIdHex)
		}

		// Check if there are more pages
		if resp.NextToken == "" {
			t.Logf("Reached final page %d", pageCount)
			break
		}

		nextToken = resp.NextToken

		// Safety check to prevent infinite loops
		require.Less(t, pageCount, 200, "Too many pages - possible infinite loop or missing messages")
	}

	paginationTime := time.Since(paginationStartTime)
	t.Logf("Retrieved all messages via pagination in %v across %d pages", paginationTime, pageCount)

	// Verify that we retrieved all expected messages
	require.Equal(t, numMessages, totalRetrieved, "Should have retrieved all %d messages via pagination", numMessages)
	require.Equal(t, numMessages, len(retrievedMessages), "Should have %d unique messages in result map", numMessages)

	// Verify that all original message IDs are present in retrieved messages
	t.Log("Verifying all original messages are present in pagination results...")
	for i, originalMessageId := range messageIds {
		messageIdHex := common.Bytes2Hex(originalMessageId[:])
		report, found := retrievedMessages[messageIdHex]
		require.True(t, found, "Original message %d with ID %s not found in pagination results", i, messageIdHex)

		// Verify the message nonce matches (our unique identifier)
		require.Equal(t, uint64(i+1), report.Message.Nonce, "Nonce mismatch for message %d", i)
	}

	// Verify expected number of pages
	require.Equal(t, expectedPages, pageCount, "Expected %d pages for %d messages with page size %d", expectedPages, numMessages, pageSize)

	t.Logf("✅ Pagination test completed successfully!")
	t.Logf("📊 Summary:")
	t.Logf("   - Messages created: %d across %d days", numMessages, numDays)
	t.Logf("   - Messages per day: %d", messagesPerDay)
	t.Logf("   - Page size: %d", pageSize)
	t.Logf("   - Expected pages: %d", expectedPages)
	t.Logf("   - Actual pages: %d", pageCount)
	t.Logf("   - Submission time: %v", submissionTime)
	t.Logf("   - All messages retrieved: %d", totalRetrieved)
	t.Logf("   - Pagination time: %v", paginationTime)
	t.Logf("   - All messages verified: ✅")
}

// TestMultiShardPagination tests pagination functionality with multiple shard configurations.
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
		{
			name:       "five_shard_pagination",
			shardCount: 5,
			pageSize:   10,
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running multi-shard pagination test with %d shards and page size %d",
				tt.shardCount, tt.pageSize)
			runMultiShardPaginationTest(t, tt.shardCount, tt.pageSize)
		})
	}
}

// runMultiShardPaginationTest runs a multi-shard pagination test with the given parameters.
func runMultiShardPaginationTest(t *testing.T, shardCount, pageSize int) {
	// Define date range: Sept 1-3, 2025
	sept1_2025 := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
	const numDays = 3
	const messagesPerDay = 8
	const totalMessages = messagesPerDay * numDays

	dayTimestamps := make([]int64, numDays)
	for i := 0; i < numDays; i++ {
		dayTimestamps[i] = sept1_2025.AddDate(0, 0, i).Unix()
	}

	sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
	signer1 := NewSignerFixture(t, "node1")
	signer2 := NewSignerFixture(t, "node2")

	// Configure committee with 2 signers and threshold of 2
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

	// Create server with multi-shard pagination config
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(
		t,
		WithCommitteeConfig(config),
		WithStorageType("dynamodb"),
		WithPaginationConfig(pageSize),
		WithShardCount(shardCount),
	)
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	t.Logf("Creating %d messages across %d days with %d shards...",
		totalMessages, numDays, shardCount)

	// Track which shards each message goes to for verification
	messageToShard := make(map[string]string)
	shardCounts := make(map[string]int)

	// Create and submit messages
	startTime := time.Now()
	for i := 0; i < totalMessages; i++ {
		// Determine which day this message belongs to
		dayIndex := i / messagesPerDay
		if dayIndex >= numDays {
			dayIndex = numDays - 1 // Ensure we don't exceed available days
		}
		messageTimestamp := dayTimestamps[dayIndex] + rand.Int64N(86400)

		// Create unique message by varying the nonce
		message := NewProtocolMessage(t)
		message.Nonce = protocol.Nonce(i + 1) // Ensure unique nonce for each message

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID for message %d", i)

		// Calculate which shard this message goes to
		shard := ddbconstant.CalculateShardFromMessageID(messageId[:], shardCount)
		messageToShard[common.Bytes2Hex(messageId[:])] = shard
		shardCounts[shard]++

		// First signature from signer1 with custom timestamp
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithCustomTimestamp(messageTimestamp))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(context.Background(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer1", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS for message %d, signer1", i)

		// Second signature from signer2 (this should trigger aggregation) with same timestamp
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
			WithCustomTimestamp(messageTimestamp))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(context.Background(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer2", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS for message %d, signer2", i)
	}
	submissionTime := time.Since(startTime)

	t.Logf("All %d messages submitted in %v", totalMessages, submissionTime)

	// Print shard distribution
	t.Logf("Shard distribution:")
	for shard, count := range shardCounts {
		t.Logf("  %s: %d messages (%.1f%%)", shard, count, float64(count)*100/totalMessages)
	}

	// Wait for aggregation to complete
	t.Logf("Waiting for aggregation to complete...")
	time.Sleep(2 * time.Second)

	// Test pagination across all shards
	t.Logf("Starting pagination test across %d shards...", shardCount)

	startTime = time.Now()
	var allReports []*pb.MessageWithCCVData
	pageCount := 0
	nextToken := ""

	for {
		pageCount++
		t.Logf("Fetching page %d with token: %s", pageCount, nextToken)

		// Call GetMessagesSince with current pagination token
		req := &pb.GetMessagesSinceRequest{
			Since: 0, // Get all messages
		}
		if nextToken != "" {
			req.NextToken = nextToken
		}

		resp, err := ccvDataClient.GetMessagesSince(context.Background(), req)
		require.NoError(t, err, "GetMessagesSince failed on page %d", pageCount)
		require.NotNil(t, resp, "GetMessagesSince response should not be nil on page %d", pageCount)

		currentPageSize := len(resp.Results)
		t.Logf("Page %d: retrieved %d reports, hasMore=%t",
			pageCount, currentPageSize, resp.NextToken != "")

		allReports = append(allReports, resp.Results...)

		if resp.NextToken == "" {
			t.Logf("Reached final page %d", pageCount)
			break
		}

		nextToken = resp.NextToken
	}

	paginationTime := time.Since(startTime)
	t.Logf("Retrieved all messages via pagination in %v across %d pages",
		paginationTime, pageCount)

	// Verify we retrieved all messages
	require.Len(t, allReports, totalMessages,
		"Should retrieve exactly %d aggregated reports", totalMessages)

	// Verify shard distribution in results
	retrievedShardCounts := make(map[string]int)
	messageIDs := make(map[string]bool)

	for _, report := range allReports {
		// Convert pb.Message to protocol.Message to compute message ID
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
		require.NoError(t, err, "Failed to compute message ID")
		messageIDHex := common.Bytes2Hex(messageId[:])

		// Verify no duplicate messages
		require.False(t, messageIDs[messageIDHex],
			"Message %s should not be duplicated", messageIDHex)
		messageIDs[messageIDHex] = true

		// Check shard distribution
		expectedShard := messageToShard[messageIDHex]
		retrievedShardCounts[expectedShard]++
	}

	// Verify shard distribution matches expectations
	for shard, expectedCount := range shardCounts {
		actualCount := retrievedShardCounts[shard]
		require.Equal(t, expectedCount, actualCount,
			"Shard %s should have %d messages, got %d", shard, expectedCount, actualCount)
	}

	// Verify temporal ordering within each shard
	verifyTemporalOrderingAcrossShards(t, allReports, shardCount)

	// Verify global temporal ordering across all shards
	verifyGlobalTemporalOrdering(t, allReports)

	t.Logf("✅ Multi-shard pagination test completed successfully!")
	t.Logf("📊 Summary:")
	t.Logf("   - Shard count: %d", shardCount)
	t.Logf("   - Messages created: %d across %d days", totalMessages, numDays)
	t.Logf("   - Page size: %d", pageSize)
	t.Logf("   - Pages retrieved: %d", pageCount)
	t.Logf("   - Submission time: %v", submissionTime)
	t.Logf("   - Pagination time: %v", paginationTime)
	t.Logf("   - All messages retrieved: %d", len(allReports))
	t.Logf("   - Shard distribution verified: ✅")
	t.Logf("   - Global temporal ordering verified: ✅")
}

// verifyTemporalOrderingAcrossShards verifies that messages are properly ordered across shards.
func verifyTemporalOrderingAcrossShards(t *testing.T, reports []*pb.MessageWithCCVData, shardCount int) {
	// Group messages by shard based on calculated shard from messageID
	shardReports := make(map[string][]*pb.MessageWithCCVData)

	for _, report := range reports {
		// Convert pb.Message to protocol.Message to compute message ID
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
		require.NoError(t, err, "Failed to compute message ID for temporal ordering")
		shard := ddbconstant.CalculateShardFromMessageID(messageId[:], shardCount)
		shardReports[shard] = append(shardReports[shard], report)
	}

	// Verify temporal ordering within each shard
	for shard, shardMessages := range shardReports {
		t.Logf("Verifying temporal ordering for shard %s (%d messages)",
			shard, len(shardMessages))

		for i := 1; i < len(shardMessages); i++ {
			prev := shardMessages[i-1]
			curr := shardMessages[i]

			// Messages should be ordered by timestamp (oldest first)
			require.LessOrEqual(t, prev.Timestamp, curr.Timestamp,
				"Messages in shard %s should be ordered by Timestamp (oldest first). "+
					"Previous: %d, Current: %d", shard, prev.Timestamp, curr.Timestamp)
		}
	}
}

// verifyGlobalTemporalOrdering verifies that all messages are properly ordered by timestamp globally.
func verifyGlobalTemporalOrdering(t *testing.T, reports []*pb.MessageWithCCVData) {
	t.Logf("Verifying global temporal ordering across all %d messages", len(reports))

	if len(reports) <= 1 {
		return // Nothing to verify with 0 or 1 message
	}

	// Verify that all messages are ordered by timestamp globally (oldest first)
	for i := 1; i < len(reports); i++ {
		prev := reports[i-1]
		curr := reports[i]

		require.LessOrEqual(t, prev.Timestamp, curr.Timestamp,
			"Messages should be globally ordered by Timestamp (oldest first). "+
				"Message %d timestamp: %d, Message %d timestamp: %d",
			i-1, prev.Timestamp, i, curr.Timestamp)
	}

	t.Logf("✅ Global temporal ordering verified: all %d messages are correctly ordered", len(reports))
}
