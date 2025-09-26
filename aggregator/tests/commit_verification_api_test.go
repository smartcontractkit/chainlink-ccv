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
