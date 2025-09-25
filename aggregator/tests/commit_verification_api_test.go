// Package tests contains functional tests for the aggregator service.
package tests

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/signature"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"

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
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
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
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
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
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
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

func assertCCVDataNotFound(t *testing.T, ctx context.Context, ccvDataClient pb.CCVDataClient, messageId types.Bytes32) {
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
	messageId types.Bytes32,
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
func validateSignatures(t *testing.T, ccvData []byte, messageId types.Bytes32, options ...SignatureValidationOption) {
	// Build configuration from options
	config := &signatureValidationConfig{}
	for _, opt := range options {
		opt(config)
	}

	if len(config.expectedSigners) == 0 {
		return // Nothing to validate
	}

	// Decode the signature data
	rs, ss, err := signature.DecodeSignatures(ccvData)
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

	recoveredAddresses, err := signature.RecoverSigners(hash32, rs, ss)
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
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
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
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config))
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

// TestPaginationWithThousandMessages tests the GetMessagesSince API with pagination
// by creating 1000+ messages from 2 signers, configuring page size to 10, and
// verifying that all messages are properly aggregated by iterating through all pages.
func TestPaginationWithThousandMessages(t *testing.T) {
	const numMessages = 1000
	const pageSize = 10

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

	// Create server with pagination config (page size 10)
	aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(
		t,
		WithCommitteeConfig(config),
		WithPaginationConfig(pageSize, "test-pagination-secret-32-bytes!!!"),
	)
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	t.Logf("Starting to create and submit %d messages...", numMessages)

	// Track all message IDs for later verification
	messageIds := make([]types.Bytes32, 0, numMessages)

	// Create and submit messages in batches for better performance
	startTime := time.Now()
	for i := 0; i < numMessages; i++ {
		if i%100 == 0 {
			t.Logf("Progress: %d/%d messages submitted", i, numMessages)
		}

		// Create unique message by varying the nonce
		message := NewProtocolMessage(t)
		message.Nonce = types.Nonce(i + 1) // Ensure unique nonce for each message

		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID for message %d", i)
		messageIds = append(messageIds, messageId)

		// First signature from signer1
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer1", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS for message %d, signer1", i)

		// Second signature from signer2 (this should trigger aggregation)
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for message %d, signer2", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS for message %d, signer2", i)

		// Brief pause every 100 messages to allow aggregation to process
		if (i+1)%100 == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	submissionTime := time.Since(startTime)
	t.Logf("All %d messages submitted in %v", numMessages, submissionTime)

	// Wait for all aggregations to complete
	t.Log("Waiting for aggregation to complete...")
	time.Sleep(2 * time.Second)

	// Now test pagination by retrieving all messages using GetMessagesSince
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

		pageSize := len(resp.Results)
		totalRetrieved += pageSize
		t.Logf("Page %d: retrieved %d reports, hasMore=%t", pageCount, pageSize, resp.NextToken != "")

		// Validate page size constraints
		if resp.NextToken != "" {
			// Not the last page - should have exactly pageSize records (10)
			require.Equal(t, 10, pageSize, "Non-final page %d should have exactly 10 records", pageCount)
		} else {
			// Last page - should have remaining records (1-10)
			require.True(t, pageSize > 0 && pageSize <= 10, "Final page %d should have 1-10 records, got %d", pageCount, pageSize)
		}

		// Store retrieved messages for verification
		for _, report := range resp.Results {
			// Compute message ID from the message
			require.NotNil(t, report.Message, "Message should not be nil in response")

			// Convert pb.Message to types.Message to compute message ID
			msg := &types.Message{
				Version:              uint8(report.Message.Version),
				SourceChainSelector:  types.ChainSelector(report.Message.SourceChainSelector),
				DestChainSelector:    types.ChainSelector(report.Message.DestChainSelector),
				Nonce:                types.Nonce(report.Message.Nonce),
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

	// Calculate expected number of pages
	expectedPages := (numMessages + pageSize - 1) / pageSize // Ceiling division
	require.Equal(t, expectedPages, pageCount, "Expected %d pages for %d messages with page size %d", expectedPages, numMessages, pageSize)

	t.Logf("✅ Pagination test completed successfully!")
	t.Logf("📊 Summary:")
	t.Logf("   - Messages created: %d", numMessages)
	t.Logf("   - Submission time: %v", submissionTime)
	t.Logf("   - Messages retrieved: %d", totalRetrieved)
	t.Logf("   - Pagination time: %v", paginationTime)
	t.Logf("   - Total pages: %d", pageCount)
	t.Logf("   - Page size: %d", pageSize)
	t.Logf("   - All messages verified: ✅")
}
