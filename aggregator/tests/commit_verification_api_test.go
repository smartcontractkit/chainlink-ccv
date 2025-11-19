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
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func TestAggregationHappyPath(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		// ctxWithMetadata := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("committee", "default"))
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		require.NoError(t, err, "failed to compute message ID")
		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
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

func TestAggregationHappyPath_NoQuorumWhenBlobDataIsDifferent(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithBlobData([]byte{1, 2, 3, 4}), WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithBlobData([]byte{2, 3, 4, 5}), WithSignatureFrom(t, signer2))

		require.NoError(t, err, "failed to compute message ID")
		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		require.Equal(t, ccvNodeData1.MessageId, ccvNodeData2.MessageId, "MessageID should be equal since blob data is not part of the messageID hash")

		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithBlobData([]byte{1, 2, 3, 4}), WithSignatureFrom(t, signer2))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

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

func TestIdempotency(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		ccvNodeData := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")
		readResp1, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &pb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   common.HexToAddress(signer1.Signer.Address).Bytes(),
		})
		require.NoError(t, err, "ReadCommitteeVerifierNodeResult failed")

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")
		readResp2, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &pb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   common.HexToAddress(signer1.Signer.Address).Bytes(),
		})
		require.NoError(t, err, "ReadCommitteeVerifierNodeResult failed")

		require.NotEqual(t, ccvNodeData2.Timestamp, ccvNodeData.Timestamp)
		require.True(t, bytes.Equal(readResp1.CcvNodeData.CcvData, readResp2.CcvNodeData.CcvData), "CCV data should be identical for idempotent writes")
		require.Equal(t, readResp1.CcvNodeData.Timestamp, readResp2.CcvNodeData.Timestamp, "Timestamps should be identical for idempotent writes")
		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func TestKeyRotation(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer1Address1 := common.HexToAddress(signer1.Signer.Address)
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err)

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err)

		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))

		signer1Rotated := NewSignerFixture(t, "node1")
		signer1Address2 := common.HexToAddress(signer1Rotated.Signer.Address)
		require.NotEqual(t, signer1Address1, signer1Address2)

		committee.QuorumConfigs["2"]["1"].Signers[0] = signer1Rotated.Signer

		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1Rotated))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status)

		time.Sleep(100 * time.Millisecond)
		getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err)
		require.Len(t, getResp.Results, 2, "Should have 2 aggregation records after key rotation")

		ccvNodeData4 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1Rotated))
		resp4, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData4))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp4.Status)

		time.Sleep(100 * time.Millisecond)
		getResp2, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err)
		require.Len(t, getResp2.Results, 2, "Should still have 2 aggregation records")

		readResp1, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &pb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   signer1Address1.Bytes(),
		})
		require.NoError(t, err)
		require.NotNil(t, readResp1.CcvNodeData)
		require.True(t, bytes.Equal(ccvNodeData1.CcvData, readResp1.CcvNodeData.CcvData))

		readResp2, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &pb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   signer1Address2.Bytes(),
		})
		require.NoError(t, err)
		require.NotNil(t, readResp2.CcvNodeData)
		require.True(t, bytes.Equal(ccvNodeData3.CcvData, readResp2.CcvNodeData.CcvData))
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
	respCcvData, err := ccvDataClient.GetVerifierResultsForMessage(ctx, &pb.GetVerifierResultsForMessageRequest{
		MessageIds: [][]byte{messageId[:]},
	})
	if err != nil {
		require.Error(t, err, "GetVerifierResultsForMessage failed")
		require.Equal(t, codes.NotFound, status.Code(err), "expected NotFound error code")
		require.Nil(t, respCcvData, "expected nil response")
	} else {
		require.NotNil(t, respCcvData, "response should not be nil")
		require.Len(t, respCcvData.Results, 1, "expected 1:1 correspondence with input message IDs")
		// Check if result is empty (protobuf may instantiate empty struct instead of nil)
		if respCcvData.Results[0] != nil {
			require.Nil(t, respCcvData.Results[0].Message, "expected empty result for not-found message")
		}
		require.Len(t, respCcvData.Errors, 1, "expected one error")
		require.Equal(t, int32(codes.NotFound), respCcvData.Errors[0].Code, "expected NotFound error code")
	}
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
		response, err := ccvDataClient.GetVerifierResultsForMessage(ctx, &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{messageId[:]},
		})
		require.NoError(collect, err, "GetVerifierResultsForMessage failed")
		require.NotNil(collect, response, "expected non-nil response")
		require.Len(collect, response.Results, 1, "expected one result")
		require.Len(collect, response.Errors, 1, "expected one error status")
		require.Equal(collect, int32(codes.OK), response.Errors[0].Code, "expected OK status")
		respCcvData = response.Results[0]
		require.NotNil(collect, respCcvData, "expected non-nil result")
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
	// We need to exclude the verifier version to get the simple signature data (i.e. length + sigs)
	rs, ss, err := protocol.DecodeSignatures(ccvData[committee.VerifierVersionLength:])
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
	hash, err := committee.NewSignableHash(messageId, ccvData)
	require.NoError(t, err, "failed to create signed hash")
	recoveredAddresses, err := protocol.RecoverSigners(hash, rs, ss)
	require.NoError(t, err, "failed to recover signer addresses")

	// Create a map of expected signer addresses for easier lookup
	expectedAddresses := make(map[common.Address]bool)
	for _, expectedSigner := range config.expectedSigners {
		require.NotEmpty(t, expectedSigner.Signer.Address, "expected signer should have an address")
		addr := common.HexToAddress(expectedSigner.Signer.Address)
		expectedAddresses[addr] = true
	}

	require.Equal(t, len(rs), len(recoveredAddresses), "should recover one address per signature")
	for _, addr := range recoveredAddresses {
		require.NotEqual(t, common.Address{}, addr, "recovered address should not be zero")
	}

	for expectedAddr := range expectedAddresses {
		found := false
		for _, recoveredAddr := range recoveredAddresses {
			if recoveredAddr == expectedAddr {
				found = true
				break
			}
		}
		require.True(t, found, "expected signer %s not found in recovered addresses", expectedAddr.Hex())
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
	messageDiscoveryClient pb.MessageDiscoveryClient,
	messageId protocol.Bytes32,
	expectedReceiptBlobs []*pb.ReceiptBlob,
) {
	require.EventuallyWithTf(t, func(collect *assert.CollectT) {
		getResp, err := messageDiscoveryClient.GetMessagesSince(ctx, &pb.GetMessagesSinceRequest{
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
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		signer3 := NewSignerFixture(t, "node3")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		// Change committee to remove signer1 and add signer3
		committee.QuorumConfigs["2"]["1"] = &model.QuorumConfig{
			Threshold: 2,
			Signers: []model.Signer{
				signer2.Signer,
				signer3.Signer,
			},
			CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
		}

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))

		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
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
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		signer3 := NewSignerFixture(t, "node3")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		// Change committee to remove signer1 and add signer3
		committee.QuorumConfigs["2"]["1"] = &model.QuorumConfig{
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

		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
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
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
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
				expectedPages: 4, // 3 full batch + 1 empty batch
			},
			{
				name:          "single_page",
				numMessages:   8,
				pageSize:      10,
				description:   "All messages fit in single page",
				expectedPages: 2, // 1 partial + 1 empty
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

	committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)

	aggregatorClient, _, messageDiscoveryClient, cleanup, err := CreateServerAndClient(
		t,
		WithCommitteeConfig(committee),
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
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message %d, signer1", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message %d, signer2", i)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)
	}

	t.Logf("All %d messages submitted", numMessages)

	time.Sleep(2 * time.Second)

	t.Log("Iterating through all messages...")
	retrievedMessages := make(map[string]bool)
	var sinceSequence int64 = 0
	pageCount := 0

	for {
		pageCount++
		req := &pb.GetMessagesSinceRequest{
			SinceSequence: sinceSequence,
		}

		resp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), req)
		require.NoError(t, err, "GetMessagesSince failed on page %d", pageCount)
		require.NotNil(t, resp, "response should not be nil")

		t.Logf("Page %d: retrieved %d reports", pageCount, len(resp.Results))

		if len(resp.Results) == 0 {
			t.Logf("Iteration complete after %d pages", pageCount)
			break
		}

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

		lastResult := resp.Results[len(resp.Results)-1]
		sinceSequence = lastResult.Sequence + 1
		require.Less(t, pageCount, 100, "too many pages - possible infinite loop")
	}

	require.Equal(t, numMessages, len(retrievedMessages), "should retrieve all messages")

	for expectedId := range expectedMessageIds {
		require.True(t, retrievedMessages[expectedId], "message %s was not retrieved", expectedId)
	}

	require.Equal(t, expectedPages, pageCount, "number of pages does not match expected")

	t.Logf("✅ Iteration test completed: %d messages retrieved across %d pages", len(retrievedMessages), pageCount)
}

// TestParticipantDeduplication verifies that only one verification per participant
// is included in the aggregated report, keeping the most recent one.
func TestParticipantDeduplication(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)

		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		oldTimestamp := time.Now().Add(-1 * time.Hour).UnixMilli()
		ccvNodeData1Old := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithCustomTimestamp(oldTimestamp))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1Old))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1 (old)")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		newTimestamp := time.Now().Add(-30 * time.Minute).UnixMilli()
		ccvNodeData1New := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithCustomTimestamp(newTimestamp))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1New))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1 (new)")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))

		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

		aggResp1 := assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
			WithExactNumberOfSignatures(2),
			WithValidSignatureFrom(signer2),
			WithValidSignatureFrom(signer1),
		)

		t.Logf("✅ Participant deduplication verified: aggregation timestamp=%d", aggResp1.Timestamp)
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
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message1 := NewProtocolMessage(t, WithNonce(100))
		messageId1, err := message1.MessageID()
		require.NoError(t, err, "failed to compute message ID 1")

		oldTime := time.Now().Add(-24 * time.Hour).UnixMilli()

		message2 := NewProtocolMessage(t, WithNonce(200))
		messageId2, err := message2.MessageID()
		require.NoError(t, err, "failed to compute message ID 2")

		recentTime := time.Now().UnixMilli()

		t.Log("Submitting message 2 with recent timestamps - will aggregate first")
		ccvNodeData2_1 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithCustomTimestamp(recentTime))

		resp, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_1))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		ccvNodeData2_2 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
			WithCustomTimestamp(recentTime))

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_2))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId2, ccvNodeData2_2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{messageId2[:]},
		})
		require.NoError(t, err, "Message 2 should be aggregated")
		require.Len(t, batchResp.Results, 1, "should have one result")
		require.Equal(t, int32(codes.OK), batchResp.Errors[0].Code, "should have OK status")

		t.Log("Submitting message 1 with old timestamps - will aggregate second")
		ccvNodeData1_1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithCustomTimestamp(oldTime))

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_1))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		ccvNodeData1_2 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
			WithCustomTimestamp(oldTime))

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_2))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId1, ccvNodeData1_2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		resp2, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
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

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer, signer3.Signer)

		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		majorityBlobData := []byte{0x01, 0x02, 0x03, 0x04}
		minorityBlobData := []byte{0x05, 0x06, 0x07, 0x08}

		// Create different receipt blobs - signer1 has a different blob than signer2 and signer3
		minorityReceiptBlob := []*pb.ReceiptBlob{
			{
				Issuer:            sourceVerifierAddress,
				DestGasLimit:      100000,
				DestBytesOverhead: 1000,
				Blob:              minorityBlobData,
				ExtraArgs:         []byte("minority-args"),
			},
		}

		majorityReceiptBlob := []*pb.ReceiptBlob{
			{
				Issuer:            sourceVerifierAddress,
				DestGasLimit:      200000,
				DestBytesOverhead: 2000,
				Blob:              majorityBlobData,
				ExtraArgs:         []byte("majority-args"),
			},
		}

		// Signer1 provides the minority receipt blob
		t.Log("Step 1: Signer1 provides minority receipt blob")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
			WithReceiptBlobs(minorityReceiptBlob))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		// Signer2 provides the majority receipt blob
		t.Log("Step 2: Signer2 provides majority receipt blob")
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
			WithReceiptBlobs(majorityReceiptBlob))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		// Signer3 also provides the majority receipt blob
		t.Log("Step 3: Signer3 provides majority receipt blob (should trigger aggregation)")
		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer3),
			WithReceiptBlobs(majorityReceiptBlob))

		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer3")
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
		assertReceiptBlobsFromMajority(t, t.Context(), messageDiscoveryClient, messageId, majorityReceiptBlob)

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
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)

		aggregatorClient, _, messageDiscoveryClient, cleanup, err := CreateServerAndClient(
			t,
			WithCommitteeConfig(committee),
			WithStorageType(storageType),
		)
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		// Create a message that both signers will verify
		message := NewProtocolMessage(t)
		require.NoError(t, err, "failed to compute message ID")

		// Step 1: Signer1 sends their verification
		t.Log("Step 1: Signer1 sends verification")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1), WithCustomTimestamp(time.Now().Add(-1*time.Minute).UnixMilli()))
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1.Status)

		// GetMessagesSince should return nothing (no quorum yet)
		getResp1, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err, "GetMessagesSince should succeed")
		require.Len(t, getResp1.Results, 0, "Should return 0 reports (no quorum yet)")
		t.Log("✓ GetMessagesSince returns 0 reports after signer1 verification")

		// Step 2: Signer2 sends their verification
		t.Log("Step 2: Signer2 sends verification")
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2), WithCustomTimestamp(time.Now().Add(-1*time.Minute).UnixMilli()))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should return 1 report (quorum reached)")
		}, 5*time.Second, 500*time.Millisecond, "GetMessagesSince should eventually return 1 report after quorum is reached")

		// Step 3: Signer2 sends their verification again (duplicate)
		t.Log("Step 3: Signer2 sends same verification again")
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult should handle duplicate")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp3.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should still return 1 report (duplicate deduplicated)")
		}, 5*time.Second, 500*time.Millisecond, "GetMessagesSince still returns 1 report after duplicate verification")

		// Wait a second to ensure the aggregation timestamp is different (we use write time as aggregation time)
		time.Sleep(1 * time.Second)

		// Step 4: Create a second message with a more recent timestamp
		t.Log("Step 4: Signer2 sends new verification for the same message (more recent timestamp)")

		newerTimestamp := time.Now().UnixMilli()
		ccvNodeData2New := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2), WithCustomTimestamp(newerTimestamp))
		resp4, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2New))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2 (newer timestamp)")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp4.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &pb.GetMessagesSinceRequest{
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

// TestBatchGetVerifierResult_HappyPath tests basic batch API functionality with multiple messages.
func TestBatchGetVerifierResult_HappyPath(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"} // DynamoDB not implemented for batch operations

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		signer3 := NewSignerFixture(t, "node3")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer, signer3.Signer)
		// Set threshold to 2 so we can have quorum with just 2 signatures
		committee.QuorumConfigs["2"]["1"].Threshold = 2
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create two different messages
		message1 := NewProtocolMessage(t)
		message1.Nonce = protocol.Nonce(1001)
		messageId1, err := message1.MessageID()
		require.NoError(t, err, "failed to compute message ID 1")

		message2 := NewProtocolMessage(t)
		message2.Nonce = protocol.Nonce(2002)
		messageId2, err := message2.MessageID()
		require.NoError(t, err, "failed to compute message ID 2")

		// Ensure messages have different IDs
		require.NotEqual(t, messageId1, messageId2, "message IDs should be different")

		// Create first aggregated report (message1 with signer1 and signer2)
		ccvNodeData1_1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp1_1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message1/signer1")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1_1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData1_2 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp1_2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message1/signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp1_2.Status, "expected WriteStatus_SUCCESS")

		// Create second aggregated report (message2 with signer2 and signer3)
		ccvNodeData2_2 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp2_2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message2/signer2")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2_2.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2_3 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress, WithSignatureFrom(t, signer3))
		resp2_3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message2/signer3")
		require.Equal(t, pb.WriteStatus_SUCCESS, resp2_3.Status, "expected WriteStatus_SUCCESS")

		// Wait for aggregation to complete
		time.Sleep(100 * time.Millisecond)

		// Test batch retrieval with both message IDs
		batchReq := &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				messageId1[:],
				messageId2[:],
			},
		}

		batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReq)
		require.NoError(t, err, "GetVerifierResultsForMessage failed")
		require.NotNil(t, batchResp, "batch response should not be nil")

		// Verify we got results for both messages with 1:1 correspondence
		require.Len(t, batchResp.Results, 2, "should have 2 results")
		require.Len(t, batchResp.Errors, 2, "should have 2 errors (1:1 correspondence)")

		// All errors should be success (Code: 0)
		for i, errStatus := range batchResp.Errors {
			require.NotNil(t, errStatus, "error status at index %d should not be nil", i)
			require.Equal(t, int32(0), errStatus.Code, "error at index %d should be success (Code: 0)", i)
		}

		// Verify both messages are present
		resultsByNonce := make(map[uint64]*pb.VerifierResult)
		for _, result := range batchResp.Results {
			resultsByNonce[result.GetMessage().GetNonce()] = result
		}

		result1, found := resultsByNonce[1001]
		require.True(t, found, "message1 should be found in batch results")
		require.Equal(t, sourceVerifierAddress, result1.SourceVerifierAddress, "source verifier address should match")
		require.Equal(t, destVerifierAddress, result1.DestVerifierAddress, "dest verifier address should match")
		require.NotNil(t, result1.CcvData, "CCV data should not be nil")

		result2, found := resultsByNonce[2002]
		require.True(t, found, "message2 should be found in batch results")
		require.Equal(t, sourceVerifierAddress, result2.SourceVerifierAddress, "source verifier address should match")
		require.Equal(t, destVerifierAddress, result2.DestVerifierAddress, "dest verifier address should match")
		require.NotNil(t, result2.CcvData, "CCV data should not be nil")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestBatchGetVerifierResult_DuplicateMessageIDs tests batch API with duplicate message IDs in request.
func TestBatchGetVerifierResult_DuplicateMessageIDs(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create and aggregate a message
		message := NewProtocolMessage(t)
		message.Nonce = protocol.Nonce(1001)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")

		time.Sleep(100 * time.Millisecond)

		// Test batch request with duplicate message IDs
		batchReqWithDuplicates := &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				messageId[:],
				messageId[:], // duplicate
				messageId[:], // another duplicate
			},
		}

		batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReqWithDuplicates)
		require.NoError(t, err, "GetVerifierResultsForMessage with duplicates should not error")
		require.NotNil(t, batchResp, "batch response with duplicates should not be nil")

		// Should have 3 results (1:1 correspondence with requests) and 3 errors (all successful)
		require.Len(t, batchResp.Results, 3, "should have 3 results (1:1 correspondence)")
		require.Len(t, batchResp.Errors, 3, "should have 3 errors (1:1 correspondence)")

		// All errors should be success (Code: 0)
		for i, errStatus := range batchResp.Errors {
			require.NotNil(t, errStatus, "error status at index %d should not be nil", i)
			require.Equal(t, int32(0), errStatus.Code, "error at index %d should be success (Code: 0)", i)
		}

		// Verify all results are correct and identical (since they're duplicates)
		for i, result := range batchResp.Results {
			require.Equal(t, uint64(1001), result.GetMessage().GetNonce(), "nonce should match for result %d", i)
			require.Equal(t, sourceVerifierAddress, result.SourceVerifierAddress, "source verifier address should match for result %d", i)
			require.Equal(t, destVerifierAddress, result.DestVerifierAddress, "dest verifier address should match for result %d", i)
		}
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestBatchGetVerifierResult_MissingMessages tests batch API with mix of existing and non-existing messages.
func TestBatchGetVerifierResult_MissingMessages(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create and aggregate one message
		existingMessage := NewProtocolMessage(t)
		existingMessage.Nonce = protocol.Nonce(1001)
		existingMessageId, err := existingMessage.MessageID()
		require.NoError(t, err, "failed to compute existing message ID")

		ccvNodeData1 := NewMessageWithCCVNodeData(t, existingMessage, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")

		ccvNodeData2 := NewMessageWithCCVNodeData(t, existingMessage, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")

		time.Sleep(100 * time.Millisecond)

		// Create a non-existent message ID
		nonExistentMessage := NewProtocolMessage(t)
		nonExistentMessage.Nonce = protocol.Nonce(9999)
		nonExistentMsgId, err := nonExistentMessage.MessageID()
		require.NoError(t, err, "failed to compute non-existent message ID")

		// Test batch request with mix of existing and non-existing messages
		batchReqWithMissing := &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				existingMessageId[:], // exists
				nonExistentMsgId[:],  // doesn't exist
			},
		}

		batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReqWithMissing)
		require.NoError(t, err, "GetVerifierResultsForMessage with missing should not error")
		require.NotNil(t, batchResp, "batch response with missing should not be nil")

		// Should have 2 results and 2 errors (1:1 correspondence with requests)
		require.Len(t, batchResp.Results, 2, "should have 2 results (1:1 with message IDs)")
		require.Len(t, batchResp.Errors, 2, "should have 2 errors (1:1 with requests)")

		// First request (existing) should have Status with Code 0
		require.NotNil(t, batchResp.Errors[0], "existing message should have Status with Code 0")
		require.Equal(t, int32(codes.OK), batchResp.Errors[0].Code, "existing message should have Code 0")

		// Second request (missing) should have NotFound error
		require.NotNil(t, batchResp.Errors[1], "missing message should have error")
		require.Equal(t, int32(codes.NotFound), batchResp.Errors[1].Code, "missing message should have NotFound error")

		// Verify the first result is correct (existing message)
		require.NotNil(t, batchResp.Results[0], "first result should not be nil")
		require.NotNil(t, batchResp.Results[0].Message, "first result should have message")
		result := batchResp.Results[0]
		require.Equal(t, uint64(1001), result.GetMessage().GetNonce(), "nonce should match")
		require.Equal(t, sourceVerifierAddress, result.SourceVerifierAddress, "source verifier address should match")

		// Second result should be empty (not found) - protobuf may instantiate empty struct
		if batchResp.Results[1] != nil {
			require.Nil(t, batchResp.Results[1].Message, "second result should be empty for not-found message")
		}
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestBatchGetVerifierResult_EmptyRequest tests batch API with empty request.
func TestBatchGetVerifierResult_EmptyRequest(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		_, ccvDataClient, _, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		// Test empty batch request (should fail)
		emptyBatchReq := &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{},
		}

		_, err = ccvDataClient.GetVerifierResultsForMessage(t.Context(), emptyBatchReq)
		require.Error(t, err, "empty batch request should fail")
		require.Equal(t, codes.InvalidArgument, status.Code(err), "error should be InvalidArgument")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

func TestBatchWriteCommitteeVerifierNodeResult_MixedSuccessFailure(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)

		aggregatorClient, _, _, cleanup, err := CreateServerAndClient(t,
			WithCommitteeConfig(committee),
			WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err)

		message := NewProtocolMessage(t)
		validCcvNodeData := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		validRequest := NewWriteCommitteeVerifierNodeResultRequest(validCcvNodeData)

		invalidMessage := NewProtocolMessage(t)
		invalidCcvNodeData1 := NewMessageWithCCVNodeData(t, invalidMessage, sourceVerifierAddress)
		invalidCcvNodeData1.CcvData = nil
		invalidRequest1 := &pb.WriteCommitteeVerifierNodeResultRequest{
			CcvNodeData: invalidCcvNodeData1,
		}

		invalidCcvNodeData2 := &pb.CommitteeVerifierNodeResult{
			MessageId: make([]byte, 32),
			CcvData:   []byte{},
		}
		invalidRequest2 := &pb.WriteCommitteeVerifierNodeResultRequest{
			CcvNodeData: invalidCcvNodeData2,
		}

		batchReq := &pb.BatchWriteCommitteeVerifierNodeResultRequest{
			Requests: []*pb.WriteCommitteeVerifierNodeResultRequest{
				validRequest,
				invalidRequest1,
				invalidRequest2,
			},
		}

		resp, err := aggregatorClient.BatchWriteCommitteeVerifierNodeResult(context.Background(), batchReq)
		require.NoError(t, err, "gRPC call should succeed")

		require.Len(t, resp.Responses, 3)
		require.Len(t, resp.Errors, 3)

		require.NotNil(t, resp.Responses[0])
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Responses[0].Status)
		require.NotNil(t, resp.Errors[0], "successful request should have ok error")
		require.Equal(t, codes.OK, codes.Code(resp.Errors[0].Code))

		for i := 1; i <= 2; i++ {
			require.NotNil(t, resp.Responses[i], "failed request should have response")
			require.Equal(t, pb.WriteStatus_FAILED, resp.Responses[i].Status)

			require.NotNil(t, resp.Errors[i], "failed request should have error")
			require.NotEqual(t, codes.OK, codes.Code(resp.Errors[i].Code))
		}

		t.Logf("✅ Batch mixed success/failure test completed: 1 success, 2 failures")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			testFunc(t, storageType)
		})
	}
}

func TestBatchGetVerifierResult_MixedSuccessFailure(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)

		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(
			t,
			WithCommitteeConfig(committee),
			WithStorageType(storageType),
		)
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create and aggregate one message to have one successful result
		message1 := NewProtocolMessage(t)
		messageId1, err := message1.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		ccvNodeData1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		ccvNodeData2 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")

		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")

		time.Sleep(500 * time.Millisecond)

		// Create a non-existent message ID
		nonExistentMessageId := make([]byte, 32)
		for i := range nonExistentMessageId {
			nonExistentMessageId[i] = 0xFF
		}

		// Test batch request with mix of existing and non-existing messages
		batchReq := &pb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				messageId1[:],        // Should succeed
				nonExistentMessageId, // Should fail with NotFound
				make([]byte, 32),     // Should fail with NotFound
			},
		}

		batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReq)
		require.NoError(t, err, "GetVerifierResultsForMessage should not error")
		require.NotNil(t, batchResp, "batch response should not be nil")

		// Verify 1:1 correspondence between requests and errors
		require.Len(t, batchResp.Errors, 3, "should have 3 errors (1:1 with requests)")

		// First request should succeed (Status with Code 0)
		require.NotNil(t, batchResp.Errors[0], "successful request should have Status with Code 0")
		require.Equal(t, int32(codes.OK), batchResp.Errors[0].Code, "successful request should have Code 0")

		// Second and third requests should fail with NotFound
		for i := 1; i <= 2; i++ {
			require.NotNil(t, batchResp.Errors[i], "failed request should have error")
			require.Equal(t, int32(codes.NotFound), batchResp.Errors[i].Code, "failed request should have NotFound error")
		}

		// Should have exactly 3 results (1:1 correspondence with message IDs)
		require.Len(t, batchResp.Results, 3, "should have 3 results (1:1 with message IDs)")

		// Verify the first result is correct (successful)
		require.NotNil(t, batchResp.Results[0], "first result should not be nil")
		require.NotNil(t, batchResp.Results[0].Message, "first result should have message")
		result := batchResp.Results[0]
		require.Equal(t, uint64(message1.Nonce), result.GetMessage().GetNonce(), "nonce should match")
		require.Equal(t, sourceVerifierAddress, result.SourceVerifierAddress, "source verifier address should match")

		// Second and third results should be empty (not found) - protobuf may instantiate empty structs
		if batchResp.Results[1] != nil {
			require.Nil(t, batchResp.Results[1].Message, "second result should be empty for not-found message")
		}
		if batchResp.Results[2] != nil {
			require.Nil(t, batchResp.Results[2].Message, "third result should be empty for not-found message")
		}

		t.Logf("✅ Batch mixed success/failure test completed: 1 success, 2 failures with 1:1 error correspondence")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestReadCommitteeVerifierNodeResult_ReturnsLatestAggregationKey verifies that when a signer
// writes a verification and then the blob data changes, ReadCommitteeVerifierNodeResult returns
// only the latest record (highest seq_num) for that signer.
func TestReadCommitteeVerifierNodeResult_ReturnsLatestAggregationKey(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer)

		aggregatorClient, _, _, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)

		// Step 1: Send verification from signer with old blob data
		oldBlobData := []byte{0x01, 0x02, 0x03, 0x04}
		ccvNodeData_old := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithBlobData(oldBlobData),
			WithSignatureFrom(t, signer1))

		resp, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData_old))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		// Step 2: Change blob data and send new verification from same signer
		newBlobData := []byte{0x05, 0x06, 0x07, 0x08}
		ccvNodeData_new := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithBlobData(newBlobData),
			WithSignatureFrom(t, signer1))

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData_new))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		// Step 3: Verify ReadCommitteeVerifierNodeResult returns only the latest one (with new blob data)
		messageId, err := message.MessageID()
		require.NoError(t, err)

		readResp, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &pb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   common.HexToAddress(signer1.Signer.Address).Bytes(),
		})
		require.NoError(t, err, "ReadCommitteeVerifierNodeResult should succeed")
		require.NotNil(t, readResp.CcvNodeData, "should return node data")

		// Verify the returned data has the NEW blob data (not the old one)
		require.Equal(t, newBlobData, readResp.CcvNodeData.BlobData, "should return latest record with new blob data")
		require.NotEqual(t, oldBlobData, readResp.CcvNodeData.BlobData, "should not return old blob data")

		t.Log("✅ ReadCommitteeVerifierNodeResult returns only latest record after blob data change")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestKeyRotation_StopAggregationAfterQuorumThenRotate tests the scenario where:
// 1. Committee has 3 signers with threshold 2
// 2. First 2 signers verify → aggregation happens
// 3. Third signer verifies → no re-aggregation (stop-aggregation-after-quorum)
// 4. Committee rotation removes first signer
// 5. Third signer verifies again → re-aggregation happens with new committee.
func TestKeyRotation_StopAggregationAfterQuorumThenRotate(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		signer3 := NewSignerFixture(t, "node3")

		// Start with all 3 signers in committee, threshold = 2
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer, signer3.Signer)
		committee.QuorumConfigs["2"]["1"].Threshold = 2

		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee), WithStorageType(storageType))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		messageId, err := message.MessageID()
		require.NoError(t, err, "failed to compute message ID")

		// Phase 1: Signer1 and Signer2 verify → aggregation happens (quorum reached)
		t.Log("Phase 1: Signer1 and Signer2 verify")
		ccvNodeData1 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		resp, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		ccvNodeData2 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))
		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		// Verify aggregation with signer1 + signer2
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(),
			sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2),
			WithExactNumberOfSignatures(2))

		// Phase 2: Signer3 verifies → no re-aggregation (stop-aggregation-after-quorum)
		t.Log("Phase 2: Signer3 verifies (should not trigger re-aggregation)")
		ccvNodeData3 := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer3))
		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		// Sleep briefly to allow any potential re-aggregation to occur
		time.Sleep(200 * time.Millisecond)

		// Verify still only 2 signatures (no re-aggregation happened)
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(),
			sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2),
			WithExactNumberOfSignatures(2))

		// Phase 3: Committee rotation - remove signer1, keep signer2 and signer3
		t.Log("Phase 3: Rotate committee - remove signer1, keep signer2 and signer3")
		committee.QuorumConfigs["2"]["1"] = &model.QuorumConfig{
			Threshold: 2,
			Signers: []model.Signer{
				signer2.Signer,
				signer3.Signer,
			},
			CommitteeVerifierAddress: common.BytesToAddress(destVerifierAddress).Hex(),
		}

		// Phase 4: Signer3 verifies again → re-aggregation happens with new committee
		t.Log("Phase 4: Signer3 verifies again (should trigger re-aggregation)")
		ccvNodeData3New := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer3))
		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3New))
		require.NoError(t, err)
		require.Equal(t, pb.WriteStatus_SUCCESS, resp.Status)

		// Verify re-aggregation with new committee (signer2 + signer3)
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3New.GetMessage(),
			sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer2), WithValidSignatureFrom(signer3),
			WithExactNumberOfSignatures(2))

		t.Log("✅ Key rotation after quorum: stop-aggregation-after-quorum works, then re-aggregation after rotation")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}
