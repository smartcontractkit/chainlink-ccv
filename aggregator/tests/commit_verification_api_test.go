// Package tests contains functional tests for the aggregator service.
package tests

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
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
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
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

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func TestAggregationHappyPathMultipleCommittees(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
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

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func TestIdempotency(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
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

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
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

func assertCCVDataNotFound(t *testing.T, ctx context.Context, ccvDataClient pb.VerifierResultAPIClient, messageId protocol.Bytes32) {
	// Wait a moment for the aggregation to process
	time.Sleep(50 * time.Millisecond)
	respCcvData, err := ccvDataClient.GetVerifierResultForMessage(ctx, &pb.GetVerifierResultForMessageRequest{
		MessageId: messageId[:],
	})
	require.Error(t, err, "GetVerifierResultForMessage failed")
	require.Equal(t, codes.NotFound, status.Code(err), "expected NotFound error code")
	require.Nil(t, respCcvData, "expected nil response")
}

func assertCCVDataFound(
	t *testing.T,
	ctx context.Context,
	ccvDataClient pb.VerifierResultAPIClient,
	messageId protocol.Bytes32,
	message *pb.Message,
	sourceVerifierAddress []byte,
	destVerifierAddress []byte,
	options ...SignatureValidationOption,
) *pb.VerifierResult {
	var respCcvData *pb.VerifierResult
	require.EventuallyWithTf(t, func(collect *assert.CollectT) {
		response, err := ccvDataClient.GetVerifierResultForMessage(ctx, &pb.GetVerifierResultForMessageRequest{
			MessageId: messageId[:],
		})
		respCcvData = response
		require.NoError(collect, err, "GetVerifierResultForMessage failed")
		require.NotNil(collect, respCcvData, "expected non-nil response")
		require.Equal(collect, message.DataLength, respCcvData.GetMessage().GetDataLength())
		require.Equal(collect, message.Data, respCcvData.GetMessage().GetData())
		require.Equal(collect, message.DestBlobLength, respCcvData.GetMessage().GetDestBlobLength())
		require.Equal(collect, message.DestBlob, respCcvData.GetMessage().GetDestBlob())
		require.Equal(collect, message.Finality, respCcvData.GetMessage().GetFinality())
		require.Equal(collect, message.OffRampAddressLength, respCcvData.GetMessage().GetOffRampAddressLength())
		require.Equal(collect, message.OffRampAddress, respCcvData.GetMessage().GetOffRampAddress())
		require.Equal(collect, message.OnRampAddressLength, respCcvData.GetMessage().GetOnRampAddressLength())
		require.Equal(collect, message.OnRampAddress, respCcvData.GetMessage().GetOnRampAddress())
		require.Equal(collect, message.ReceiverLength, respCcvData.GetMessage().GetReceiverLength())
		require.Equal(collect, message.Receiver, respCcvData.GetMessage().GetReceiver())
		require.Equal(collect, message.SenderLength, respCcvData.GetMessage().GetSenderLength())
		require.Equal(collect, message.Sender, respCcvData.GetMessage().GetSender())
		require.Equal(collect, message.Nonce, respCcvData.GetMessage().GetNonce())
		require.Equal(collect, message.SourceChainSelector, respCcvData.GetMessage().GetSourceChainSelector())
		require.Equal(collect, message.DestChainSelector, respCcvData.GetMessage().GetDestChainSelector())
		require.Equal(collect, message.TokenTransferLength, respCcvData.GetMessage().GetTokenTransferLength())
		require.True(collect, bytes.Equal(message.TokenTransfer, respCcvData.GetMessage().GetTokenTransfer()))
		require.Equal(collect, message.Version, respCcvData.GetMessage().GetVersion())

		require.Equal(collect, respCcvData.DestVerifierAddress, destVerifierAddress)
		require.Equal(collect, respCcvData.SourceVerifierAddress, sourceVerifierAddress)

		// Validate signatures if options are provided
		require.NotNil(collect, respCcvData.CcvData)
		if len(options) > 0 {
			validateSignatures(collect, respCcvData.CcvData, messageId, options...)
		}
	}, 5*time.Second, 100*time.Millisecond, "CCV data not found within timeout")

	return respCcvData
}

// validateSignatures decodes the CCV data and validates signatures from expected signers.
func validateSignatures(t *assert.CollectT, ccvData []byte, messageId protocol.Bytes32, options ...SignatureValidationOption) {
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

// assertReceiptBlobsFromMajority validates that the aggregated report contains the expected receipt blobs from majority consensus.
func assertReceiptBlobsFromMajority(
	t *testing.T,
	ctx context.Context,
	ccvDataClient pb.VerifierResultAPIClient,
	messageId protocol.Bytes32,
	expectedReceiptBlobs []*pb.ReceiptBlob,
) {
	require.EventuallyWithTf(t, func(collect *assert.CollectT) {
		getResp, err := ccvDataClient.GetMessagesSince(ctx, &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(collect, err, "GetMessagesSince should succeed")
		require.Len(collect, getResp.Results, 1, "Should return exactly 1 aggregated report")

		report := getResp.Results[0]
		require.NotNil(collect, report, "Report should not be nil")

		// Check that the message ID matches
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

		reportMessageId, err := msg.MessageID()
		require.NoError(collect, err, "Failed to compute message ID from report")
		require.Equal(collect, messageId, reportMessageId, "Message ID mismatch")

		// Validate the receipt blobs from majority
		actualReceiptBlobs := report.GetReceiptBlobsFromMajority()
		require.NotNil(collect, actualReceiptBlobs, "ReceiptBlobsFromMajority should not be nil")
		require.Len(collect, actualReceiptBlobs, len(expectedReceiptBlobs), "Receipt blob count mismatch")

		// Debug logging for receipt blob comparison
		if len(actualReceiptBlobs) > 0 && len(expectedReceiptBlobs) > 0 {
			t.Logf("DEBUG: Expected DestGasLimit: %d, Actual DestGasLimit: %d",
				expectedReceiptBlobs[0].DestGasLimit, actualReceiptBlobs[0].DestGasLimit)
			t.Logf("DEBUG: Expected Blob: %s, Actual Blob: %s",
				expectedReceiptBlobs[0].Blob, actualReceiptBlobs[0].Blob)
		}

		// Validate each expected receipt blob
		for i, expectedBlob := range expectedReceiptBlobs {
			require.Less(collect, i, len(actualReceiptBlobs), "Actual receipt blobs list is too short")
			actualBlob := actualReceiptBlobs[i]

			require.Equal(collect, expectedBlob.Issuer, actualBlob.Issuer, "Receipt blob issuer mismatch at index %d", i)
			require.Equal(collect, expectedBlob.DestGasLimit, actualBlob.DestGasLimit, "Receipt blob DestGasLimit mismatch at index %d", i)
			require.Equal(collect, expectedBlob.DestBytesOverhead, actualBlob.DestBytesOverhead, "Receipt blob DestBytesOverhead mismatch at index %d", i)
			require.Equal(collect, expectedBlob.Blob, actualBlob.Blob, "Receipt blob Blob data mismatch at index %d", i)
			require.Equal(collect, expectedBlob.ExtraArgs, actualBlob.ExtraArgs, "Receipt blob ExtraArgs mismatch at index %d", i)
		}
	}, 5*time.Second, 100*time.Millisecond, "Aggregated report with expected receipt blobs not found")
}

// Test where a valid signer sign but is later removed from the committee and another valider signs but aggregation should not complete. Only when we sign with a third valid signer it succeeds.
func TestChangingCommitteeBeforeAggregation(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
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

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func TestChangingCommitteeAfterAggregation(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
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

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestPaginationWithVariousPageSizes tests the GetMessagesSince API with pagination.
func TestPaginationWithVariousPageSizes(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres", "dynamodb"}

	testFunc := func(t *testing.T, storageType string) {
		expectedPages := 3
		if storageType == "dynamodb" {
			// DynamoDB has different pagination behavior due to its internal limits
			expectedPages = 4
		}
		testCases := []struct {
			name          string
			numMessages   int
			pageSize      int
			description   string
			expectedPages int
		}{
			{
				name:          "basic_pagination",
				numMessages:   15,
				pageSize:      5,
				description:   "Basic pagination with small dataset",
				expectedPages: expectedPages,
			},
			{
				name:          "single_page",
				numMessages:   8,
				pageSize:      10,
				description:   "All messages fit in single page",
				expectedPages: 1,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Logf("Running test case: %s - %s", tc.name, tc.description)
				runPaginationTest(t, tc.numMessages, tc.pageSize, storageType, tc.expectedPages)
			})
		}
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func runPaginationTest(t *testing.T, numMessages, pageSize int, storageType string, expectedPages int) {
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
		WithStorageType(storageType),
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
			SinceSequence: 0,
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

	require.Equal(t, expectedPages, pageCount, "number of pages does not match expected")

	t.Logf("✅ Pagination test completed: %d messages retrieved across %d pages", len(retrievedMessages), pageCount)
}

// TestMultiShardPagination tests pagination with multiple shard configurations.
func TestMultiShardPagination(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"dynamodb"}

	testFunc := func(t *testing.T, storageType string) {
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
				runMultiShardPaginationTest(t, tt.shardCount, tt.pageSize, storageType)
			})
		}
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func runMultiShardPaginationTest(t *testing.T, shardCount, pageSize int, storageType string) {
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
		WithStorageType(storageType),
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
			SinceSequence: 0,
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
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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

		// Create server with enabled EnableAggregationAfterQuorum feature
		configOption := func(c *model.AggregatorConfig, clientConfig *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
			c.Aggregation.EnableAggregationAfterQuorum = true // Explicitly enable the feature
			return c, clientConfig
		}

		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType), configOption)
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

		// The assertion above should eventually return the new report, but let's add an explicit check
		// with retry logic to ensure we're not getting a cached/stale result
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := ccvDataClient.GetVerifierResultForMessage(t.Context(), &pb.GetVerifierResultForMessageRequest{
				MessageId: messageId[:],
			})
			require.NoError(collect, err)
			require.Greater(collect, resp.Timestamp, aggResp1.Timestamp, "We should have a newer aggregation timestamp")
		}, 5*time.Second, 100*time.Millisecond, "New aggregated report not found within timeout")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestSequenceOrdering verifies that GetMessagesSince returns reports ordered by WrittenAt.
func TestSequenceOrdering(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"dynamodb", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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

		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
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

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId2, ccvNodeData2_2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		_, err = ccvDataClient.GetVerifierResultForMessage(t.Context(), &pb.GetVerifierResultForMessageRequest{
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

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId1, ccvNodeData1_2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		resp2, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err, "GetMessagesSince should succeed")
		require.Len(t, resp2.Results, 2, "Should return 2 messages")

		t.Logf("First result timestamp: %d", resp2.Results[0].Timestamp)
		t.Logf("Second result timestamp: %d", resp2.Results[1].Timestamp)

		result1MessageID := resp2.Results[0].Message.Nonce
		result2MessageID := resp2.Results[1].Message.Nonce

		require.Equal(t, uint64(200), result1MessageID, "First result should be message2 (nonce 200)")
		require.Equal(t, uint64(100), result2MessageID, "Second result should be message1 (nonce 100)")

		require.LessOrEqual(t, resp2.Results[0].Sequence, resp2.Results[1].Sequence,
			"First message (written first) should have earlier or equal Sequence than second message (written second)")

		t.Log("SUCCESS: GetMessagesSince returns items ordered by write time, not verification time")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestReceiptBlobMajorityConsensus tests that when there are conflicting receipt blobs,
// the consensus algorithm selects the majority winner.
func TestReceiptBlobMajorityConsensus(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"memory", "postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
						Threshold: 3, // Require all 3 signers for quorum
						Signers: []model.Signer{
							signer1.Signer,
							signer2.Signer,
							signer3.Signer,
						},
						CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
					},
				},
			},
		}

		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(config), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		// Create different receipt blobs - signer1 has a different blob than signer2 and signer3
		minorityReceiptBlob := []*pb.ReceiptBlob{
			{
				Issuer:            sourceVerifierAddress,
				DestGasLimit:      100000,
				DestBytesOverhead: 1000,
				Blob:              []byte("minority-blob-data"),
				ExtraArgs:         []byte("minority-args"),
			},
		}

		majorityReceiptBlob := []*pb.ReceiptBlob{
			{
				Issuer:            sourceVerifierAddress,
				DestGasLimit:      200000,
				DestBytesOverhead: 2000,
				Blob:              []byte("majority-blob-data"),
				ExtraArgs:         []byte("majority-args"),
			},
		}

		// Signer1 provides the minority receipt blob
		t.Log("Step 1: Signer1 provides minority receipt blob")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithReceiptBlobs(minorityReceiptBlob))

		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer1")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		// Signer2 provides the majority receipt blob
		t.Log("Step 2: Signer2 provides majority receipt blob")
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
			WithReceiptBlobs(majorityReceiptBlob))

		resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		// Signer3 also provides the majority receipt blob
		t.Log("Step 3: Signer3 provides majority receipt blob (should trigger aggregation)")
		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer3),
			WithReceiptBlobs(majorityReceiptBlob))

		resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData3,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer3")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status)

		// Now we should have the aggregated result with the majority receipt blob
		t.Log("Step 4: Verify majority receipt blob was selected")
		_ = assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3.GetMessage(),
			sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1),
			WithValidSignatureFrom(signer2),
			WithValidSignatureFrom(signer3),
			WithExactNumberOfSignatures(3))

		// Verify that the majority receipt blob was selected in the consensus
		t.Log("Step 5: Verify majority consensus selected the correct receipt blobs")
		assertReceiptBlobsFromMajority(t, t.Context(), ccvDataClient, messageId, majorityReceiptBlob)

		t.Log("✅ Majority consensus test passed: consensus algorithm successfully processed conflicting receipt blobs")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestGetMessagesSinceDeduplication verifies that GetMessagesSince deduplicates messages
// and shows correct behavior when the same signer submits multiple verifications.
// With the stop-aggregation-after-quorum feature enabled (default), reaggregation is prevented
// when an existing report already meets quorum, even with newer timestamps.
func TestGetMessagesSinceDeduplication(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres", "dynamodb"}

	testFunc := func(t *testing.T, storageType string) {
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
			WithStorageType(storageType),
		)
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		// Create a message that both signers will verify
		message := NewProtocolMessage(t)
		require.NoError(t, err, "failed to compute message ID")

		// Step 1: Signer1 sends their verification
		t.Log("Step 1: Signer1 sends verification")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1), WithCustomTimestamp(time.Now().Add(-1*time.Minute).UnixMicro()))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer1")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		// GetMessagesSince should return nothing (no quorum yet)
		getResp1, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err, "GetMessagesSince should succeed")
		require.Len(t, getResp1.Results, 0, "Should return 0 reports (no quorum yet)")
		t.Log("✓ GetMessagesSince returns 0 reports after signer1 verification")

		// Step 2: Signer2 sends their verification
		t.Log("Step 2: Signer2 sends verification")
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2), WithCustomTimestamp(time.Now().Add(-1*time.Minute).UnixMicro()))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should return 1 report (quorum reached)")
		}, 5*time.Second, 500*time.Millisecond, "GetMessagesSince should eventually return 1 report after quorum is reached")

		// Step 3: Signer2 sends their verification again (duplicate)
		t.Log("Step 3: Signer2 sends same verification again")
		resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2, // Same data as before
		})
		require.NoError(t, err, "WriteCommitCCVNodeData should handle duplicate")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should still return 1 report (duplicate deduplicated)")
		}, 5*time.Second, 500*time.Millisecond, "GetMessagesSince still returns 1 report after duplicate verification")

		// Wait a second to ensure the aggregation timestamp is different (we use write time as aggregation time)
		time.Sleep(1 * time.Second)

		// Step 4: Create a second message with a more recent timestamp
		t.Log("Step 4: Signer2 sends new verification for the same message (more recent timestamp)")

		newerTimestamp := time.Now().UnixMicro()
		ccvNodeData2New := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2), WithCustomTimestamp(newerTimestamp))
		resp4, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2New,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer2 (newer timestamp)")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp4.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should return 1 report (reaggregation skipped due to existing quorum)")
		}, 5*time.Second, 500*time.Millisecond, "GetMessagesSince should still return 1 report (reaggregation prevented by stop-aggregation-after-quorum feature)")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestPostQuorumAggregationWhenAggregationAfterQuorumEnabled verifies that when EnableAggregationAfterQuorum is enabled
// the system allows post-quorum aggregations and both GetMessagesSince and GetVerifierResultForMessage
// return the expected results with multiple aggregated reports.
func TestPostQuorumAggregationWhenAggregationAfterQuorumEnabled(t *testing.T) {
	storageTypes := []string{"postgres", "dynamodb"}

	testFunc := func(t *testing.T, storageType string) {
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

		// Create server with enabled EnableAggregationAfterQuorum feature
		configOption := func(c *model.AggregatorConfig, clientConfig *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
			c.Aggregation.EnableAggregationAfterQuorum = true // Explicitly enable the feature
			return c, clientConfig
		}

		aggregatorClient, ccvDataClient, cleanup, err := CreateServerAndClient(
			t,
			WithCommitteeConfig(config),
			WithStorageType(storageType),
			configOption,
		)
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		// Create a message that both signers will verify
		message := NewProtocolMessage(t)
		messageID, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		// Step 1: Signer1 sends their verification
		t.Log("Step 1: Signer1 sends verification")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1), WithCustomTimestamp(time.Now().Add(-2*time.Minute).UnixMicro()))
		resp1, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData1,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer1")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		// GetMessagesSince should return nothing (no quorum yet)
		getResp1, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err, "GetMessagesSince should succeed")
		require.Len(t, getResp1.Results, 0, "Should return 0 reports (no quorum yet)")
		t.Log("✓ GetMessagesSince returns 0 reports after signer1 verification")

		// GetVerifierResultForMessage should return nothing (no quorum yet)
		_, err = ccvDataClient.GetVerifierResultForMessage(t.Context(), &pb.GetVerifierResultForMessageRequest{
			MessageId: messageID[:],
		})
		require.Error(t, err, "GetVerifierResultForMessage should fail before quorum")
		require.Contains(t, err.Error(), "no data found", "Error should indicate no data found before quorum")
		t.Log("✓ GetVerifierResultForMessage returns not found before quorum")

		// Step 2: Signer2 sends their verification (quorum reached)
		t.Log("Step 2: Signer2 sends verification")
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2), WithCustomTimestamp(time.Now().Add(-1*time.Minute).UnixMicro()))
		resp2, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)

		// Wait for first aggregation to complete
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should return 1 report (first quorum reached)")
		}, 5*time.Second, 500*time.Millisecond, "GetMessagesSince should eventually return 1 report after first quorum is reached")

		// Check GetVerifierResultForMessage after first aggregation
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getVerifierResp, err := ccvDataClient.GetVerifierResultForMessage(t.Context(), &pb.GetVerifierResultForMessageRequest{
				MessageId: messageID[:],
			})
			require.NoError(collect, err, "GetVerifierResultForMessage should succeed")
			require.NotNil(collect, getVerifierResp, "Should return a result after first quorum")
		}, 5*time.Second, 500*time.Millisecond, "GetVerifierResultForMessage should eventually return a result after first quorum")

		// Wait a second to ensure the aggregation timestamp is different (we use write time as aggregation time)
		time.Sleep(1 * time.Second)

		// Step 3: Signer2 sends new verification with more recent timestamp (should trigger reaggregation since feature is disabled)
		t.Log("Step 3: Signer2 sends new verification for the same message (more recent timestamp)")
		newerTimestamp := time.Now().UnixMicro()
		ccvNodeData2New := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2), WithCustomTimestamp(newerTimestamp))
		resp3, err := aggregatorClient.WriteCommitCCVNodeData(t.Context(), &pb.WriteCommitCCVNodeDataRequest{
			CcvNodeData: ccvNodeData2New,
		})
		require.NoError(t, err, "WriteCommitCCVNodeData failed for signer2 (newer timestamp)")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status)

		// GetMessagesSince should eventually return 2 reports (feature disabled allows reaggregation)
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := ccvDataClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 2, "Should return 2 reports (feature disabled allows reaggregation)")

			// Verify both reports are for the same message but with different timestamps
			result1 := getResp.Results[0]
			result2 := getResp.Results[1]

			assert.Equal(collect, uint64(message.Nonce), result1.Message.Nonce, "First report should be for our message")
			assert.Equal(collect, uint64(message.Nonce), result2.Message.Nonce, "Second report should be for our message")

			// The newer report should have a more recent timestamp
			assert.Greater(collect, result2.Timestamp, result1.Timestamp, "Second report should have newer timestamp")
		}, 10*time.Second, 500*time.Millisecond, "GetMessagesSince should eventually return 2 reports when feature is disabled")

		// GetVerifierResultForMessage should return the most recent aggregated report
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getVerifierResp, err := ccvDataClient.GetVerifierResultForMessage(t.Context(), &pb.GetVerifierResultForMessageRequest{
				MessageId: messageID[:],
			})
			require.NoError(collect, err, "GetVerifierResultForMessage should succeed")
			require.NotNil(collect, getVerifierResp, "Should return a result")

			// Should return the most recent aggregated report
			assert.Equal(collect, uint64(message.Nonce), getVerifierResp.Message.Nonce, "Should return result for our message")

			// The result should have the recent timestamp (indicating it's the newer aggregation)
			// We can't check exact timestamp due to timing variations, but we can verify it's reasonably recent
			now := time.Now().Unix()
			assert.InDelta(collect, now, getVerifierResp.Timestamp, 10, "Result timestamp should be recent")
		}, 10*time.Second, 500*time.Millisecond, "GetVerifierResultForMessage should return the most recent aggregated report")

		t.Log("✓ Both GetMessagesSince and GetVerifierResultForMessage behave correctly with feature disabled")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}
