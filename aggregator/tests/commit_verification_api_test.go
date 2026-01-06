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

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func TestAggregationHappyPath(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		// ctxWithMetadata := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("committee", "default"))
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithCcvVersion([]byte{1, 2, 3, 4}), WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithCcvVersion([]byte{2, 3, 4, 5}), WithSignatureFrom(t, signer2))

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithCcvVersion([]byte{1, 2, 3, 4}), WithSignatureFrom(t, signer2))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

		// Example of signature validation: Verify that the aggregated CCV data contains
		// valid signatures from both signer1 and signer2
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))
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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		ccvNodeData, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err)

		message := NewProtocolMessage(t)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status)

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2))

		signer1Rotated := NewSignerFixture(t, "node1")
		signer1Address2 := common.HexToAddress(signer1Rotated.Signer.Address)
		require.NotEqual(t, signer1Address1, signer1Address2)

		committee.QuorumConfigs["1"].Signers[0] = signer1Rotated.Signer

		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1Rotated))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp3.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err)
			require.Len(collect, getResp.Results, 2, "Should have 2 aggregation records after key rotation")
		}, 5*time.Second, 100*time.Millisecond, "should have 2 aggregation records after key rotation")

		ccvNodeData4, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1Rotated))
		resp4, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData4))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp4.Status)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp2, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err)
			require.Len(collect, getResp2.Results, 2, "Should still have 2 aggregation records")
		}, 5*time.Second, 100*time.Millisecond, "should still have 2 aggregation records")

		readResp1, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &committeepb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   signer1Address1.Bytes(),
		})
		require.NoError(t, err)
		require.NotNil(t, readResp1.CommitteeVerifierNodeResult)
		require.True(t, bytes.Equal(ccvNodeData1.Signature, readResp1.CommitteeVerifierNodeResult.Signature))

		readResp2, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &committeepb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   signer1Address2.Bytes(),
		})
		require.NoError(t, err)
		require.NotNil(t, readResp2.CommitteeVerifierNodeResult)
		require.True(t, bytes.Equal(ccvNodeData3.Signature, readResp2.CommitteeVerifierNodeResult.Signature))
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

func assertCCVDataNotFound(t *testing.T, ctx context.Context, ccvDataClient verifierpb.VerifierClient, messageId protocol.Bytes32) {
	require.EventuallyWithTf(t, func(collect *assert.CollectT) {
		respCcvData, err := ccvDataClient.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{messageId[:]},
		})
		if err != nil {
			require.Error(collect, err, "GetVerifierResultsForMessage failed")
			require.Equal(collect, codes.NotFound, status.Code(err), "expected NotFound error code")
			require.Nil(collect, respCcvData, "expected nil response")
		} else {
			require.NotNil(collect, respCcvData, "response should not be nil")
			require.Len(collect, respCcvData.Results, 1, "expected 1:1 correspondence with input message IDs")
			// Check if result is empty (protobuf may instantiate empty struct instead of nil)
			if respCcvData.Results[0] != nil {
				require.Nil(collect, respCcvData.Results[0].Message, "expected empty result for not-found message")
			}
			require.Len(collect, respCcvData.Errors, 1, "expected one error")
			require.Equal(collect, int32(codes.NotFound), respCcvData.Errors[0].Code, "expected NotFound error code")
		}
	}, 500*time.Millisecond, 50*time.Millisecond, "CCV data should not be found")
}

func assertCCVDataFound(t *testing.T, ctx context.Context, ccvDataClient verifierpb.VerifierClient, messageId protocol.Bytes32, message *verifierpb.Message, sourceVerifierAddress, destVerifierAddress []byte, options ...SignatureValidationOption) *verifierpb.VerifierResult {
	var respCcvData *verifierpb.VerifierResult
	require.EventuallyWithTf(t, func(collect *assert.CollectT) {
		response, err := ccvDataClient.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{
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
		require.Equal(collect, message.SequenceNumber, respCcvData.GetMessage().GetSequenceNumber())
		require.Equal(collect, message.SourceChainSelector, respCcvData.GetMessage().GetSourceChainSelector())
		require.Equal(collect, message.DestChainSelector, respCcvData.GetMessage().GetDestChainSelector())
		require.Equal(collect, message.TokenTransferLength, respCcvData.GetMessage().GetTokenTransferLength())
		require.True(collect, bytes.Equal(message.TokenTransfer, respCcvData.GetMessage().GetTokenTransfer()))
		require.Equal(collect, message.Version, respCcvData.GetMessage().GetVersion())
		require.Equal(collect, destVerifierAddress, respCcvData.GetMetadata().GetVerifierDestAddress())
		require.Equal(collect, sourceVerifierAddress, respCcvData.GetMetadata().GetVerifierSourceAddress())
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
	recoveredAddresses, err := protocol.RecoverECDSASigners(hash, rs, ss)
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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		// Change committee to remove signer1 and add signer3
		UpdateCommitteeQuorum(committee, sourceVerifierAddress, signer2.Signer, signer3.Signer)

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))

		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataNotFound(t, t.Context(), ccvDataClient, messageId)

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))

		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		// Change committee to remove signer1 and add signer3
		UpdateCommitteeQuorum(committee, sourceVerifierAddress, signer2.Signer, signer3.Signer)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(1))

		// Ensure that we can still write new signatures with the updated committee
		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))

		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp3.Status, "expected WriteStatus_SUCCESS")

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
		WithPaginationConfig(pageSize),
	)
	t.Cleanup(cleanup)
	require.NoError(t, err, "failed to create server and client")

	t.Logf("Creating and submitting %d messages with page size %d...", numMessages, pageSize)

	expectedMessageIds := make(map[string]bool)

	for i := 0; i < numMessages; i++ {
		message := NewProtocolMessage(t)
		message.SequenceNumber = protocol.SequenceNumber(i + 1)

		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		expectedMessageIds[common.Bytes2Hex(messageId[:])] = true
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message %d, signer1", i)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status)

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message %d, signer2", i)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status)
	}

	t.Logf("All %d messages submitted", numMessages)

	time.Sleep(2 * time.Second)

	t.Log("Iterating through all messages...")
	retrievedMessages := make(map[string]bool)
	var sinceSequence int64 = 0
	pageCount := 0

	for {
		pageCount++
		req := &msgdiscoverypb.GetMessagesSinceRequest{
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
			var ccvAndExecutorHash protocol.Bytes32
			copy(ccvAndExecutorHash[:], report.VerifierResult.Message.CcvAndExecutorHash)

			msg := &protocol.Message{
				Version:              uint8(report.VerifierResult.Message.Version),
				SourceChainSelector:  protocol.ChainSelector(report.VerifierResult.Message.SourceChainSelector),
				DestChainSelector:    protocol.ChainSelector(report.VerifierResult.Message.DestChainSelector),
				SequenceNumber:       protocol.SequenceNumber(report.VerifierResult.Message.SequenceNumber),
				OnRampAddressLength:  uint8(report.VerifierResult.Message.OnRampAddressLength),
				OnRampAddress:        report.VerifierResult.Message.OnRampAddress,
				OffRampAddressLength: uint8(report.VerifierResult.Message.OffRampAddressLength),
				OffRampAddress:       report.VerifierResult.Message.OffRampAddress,
				CcvAndExecutorHash:   ccvAndExecutorHash,
				Finality:             uint16(report.VerifierResult.Message.Finality),
				SenderLength:         uint8(report.VerifierResult.Message.SenderLength),
				Sender:               report.VerifierResult.Message.Sender,
				ReceiverLength:       uint8(report.VerifierResult.Message.ReceiverLength),
				Receiver:             report.VerifierResult.Message.Receiver,
				DestBlobLength:       uint16(report.VerifierResult.Message.DestBlobLength),
				DestBlob:             report.VerifierResult.Message.DestBlob,
				TokenTransferLength:  uint16(report.VerifierResult.Message.TokenTransferLength),
				DataLength:           uint16(report.VerifierResult.Message.DataLength),
				Data:                 report.VerifierResult.Message.Data,
			}

			// Decode TokenTransfer if present
			if report.VerifierResult.Message.TokenTransferLength > 0 && len(report.VerifierResult.Message.TokenTransfer) > 0 {
				tt, err := protocol.DecodeTokenTransfer(report.VerifierResult.Message.TokenTransfer)
				require.NoError(t, err, "failed to decode token transfer")
				msg.TokenTransfer = tt
			} else {
				msg.TokenTransfer = nil
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

// TestSequenceOrdering verifies that GetMessagesSince returns reports ordered by WrittenAt.
func TestSequenceOrdering(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message1 := NewProtocolMessage(t, WithSequenceNumber(100))
		message2 := NewProtocolMessage(t, WithSequenceNumber(200))

		t.Log("Submitting message 2 with recent timestamps - will aggregate first")
		ccvNodeData2_1, messageId2 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
		)

		resp, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_1))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		ccvNodeData2_2, _ := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
		)

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_2))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId2, ccvNodeData2_2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{messageId2[:]},
		})
		require.NoError(t, err, "Message 2 should be aggregated")
		require.Len(t, batchResp.Results, 1, "should have one result")
		require.Equal(t, int32(codes.OK), batchResp.Errors[0].Code, "should have OK status")

		t.Log("Submitting message 1 with old timestamps - will aggregate second")
		ccvNodeData1_1, messageId1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress,
			WithSignatureFrom(t, signer1),
		)

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_1))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		ccvNodeData1_2, _ := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress,
			WithSignatureFrom(t, signer2),
		)

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_2))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId1, ccvNodeData1_2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		resp2, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
			SinceSequence: 0,
		})
		require.NoError(t, err, "GetMessagesSince should succeed")
		require.Len(t, resp2.Results, 2, "Should return 2 messages")

		t.Logf("First result timestamp: %d", resp2.Results[0].VerifierResult.Metadata.Timestamp)
		t.Logf("Second result timestamp: %d", resp2.Results[1].VerifierResult.Metadata.Timestamp)

		result1MessageID := resp2.Results[0].VerifierResult.Message.SequenceNumber
		result2MessageID := resp2.Results[1].VerifierResult.Message.SequenceNumber

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

// TestStopAggregationAfterQuorum verifies that when a committee has 3 signers with threshold 2,
// aggregation completes after 2 signers verify (reaching quorum), and a third signer's verification
// does not trigger re-aggregation due to the stop-aggregation-after-quorum feature.
func TestStopAggregationAfterQuorum(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		signer3 := NewSignerFixture(t, "node3")

		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer, signer3.Signer)
		// Override threshold to 2 (out of 3 signers)
		committee.QuorumConfigs["1"].Threshold = 2

		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(
			t,
			WithCommitteeConfig(committee),
		)
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		// Create a message that all three signers will verify
		message := NewProtocolMessage(t)

		// Phase 1: Signer1 sends verification (1/2 threshold - no quorum yet)
		t.Log("Phase 1: Signer1 sends verification")
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status)

		// Verify no aggregation yet (no quorum)
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 0, "Should return 0 reports (no quorum yet with 1/2 signatures)")
		}, 2*time.Second, 100*time.Millisecond, "No aggregation should occur with only 1 signature")
		t.Log("✓ Phase 1 complete: No aggregation with 1/2 signatures")

		// Phase 2: Signer2 sends verification (2/2 threshold - quorum reached!)
		t.Log("Phase 2: Signer2 sends verification")
		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status)

		// Verify aggregation happens (quorum reached)
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should return 1 report (quorum reached with 2/2 signatures)")
		}, 5*time.Second, 100*time.Millisecond, "Aggregation should complete after reaching quorum")

		// Verify the aggregated report contains signatures from signer1 and signer2
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1),
			WithValidSignatureFrom(signer2),
			WithExactNumberOfSignatures(2))
		t.Log("✓ Phase 2 complete: Aggregation succeeded with 2/2 signatures")

		// Phase 3: Signer3 sends verification (3/2 threshold - but quorum already met)
		t.Log("Phase 3: Signer3 sends verification (stop-aggregation-after-quorum should prevent re-aggregation)")
		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer3))
		resp3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer3")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp3.Status)

		// Verify NO re-aggregation occurs (stop-aggregation-after-quorum feature)
		// Wait a bit to ensure any potential aggregation would have triggered
		time.Sleep(1 * time.Second)

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			getResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, getResp.Results, 1, "Should still return only 1 report (no re-aggregation)")
		}, 2*time.Second, 100*time.Millisecond, "No re-aggregation should occur (stop-aggregation-after-quorum)")

		// Verify the report still only contains signatures from signer1 and signer2
		// (signer3's signature should NOT have been aggregated)
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1),
			WithValidSignatureFrom(signer2),
			WithExactNumberOfSignatures(2))
		t.Log("✓ Phase 3 complete: No re-aggregation occurred (stop-aggregation-after-quorum working correctly)")

		// Final verification via batch API
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress,
			WithValidSignatureFrom(signer1),
			WithValidSignatureFrom(signer2),
			WithExactNumberOfSignatures(2))
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
		committee.QuorumConfigs["1"].Threshold = 2
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create two different messages
		message1 := NewProtocolMessage(t)
		message1.SequenceNumber = protocol.SequenceNumber(1001)

		message2 := NewProtocolMessage(t)
		message2.SequenceNumber = protocol.SequenceNumber(2002)

		// Create first aggregated report (message1 with signer1 and signer2)
		ccvNodeData1_1, messageId1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		resp1_1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message1/signer1")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1_1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData1_2, _ := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		resp1_2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1_2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message1/signer2")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1_2.Status, "expected WriteStatus_SUCCESS")

		// Create second aggregated report (message2 with signer2 and signer3)
		ccvNodeData2_2, messageId2 := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		// Ensure messages have different IDs
		require.NotEqual(t, messageId1, messageId2, "message IDs should be different")

		resp2_2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message2/signer2")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2_2.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2_3, _ := NewMessageWithCCVNodeData(t, message2, sourceVerifierAddress, WithSignatureFrom(t, signer3))
		resp2_3, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2_3))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for message2/signer3")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2_3.Status, "expected WriteStatus_SUCCESS")

		// Test batch retrieval with both message IDs - wait for aggregation to complete
		batchReq := &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				messageId1[:],
				messageId2[:],
			},
		}

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReq)
			require.NoError(collect, err, "GetVerifierResultsForMessage failed")
			require.NotNil(collect, batchResp, "batch response should not be nil")

			// Verify we got results for both messages with 1:1 correspondence
			require.Len(collect, batchResp.Results, 2, "should have 2 results")
			require.Len(collect, batchResp.Errors, 2, "should have 2 errors (1:1 correspondence)")

			// All errors should be success (Code: 0)
			for i, errStatus := range batchResp.Errors {
				require.NotNil(collect, errStatus, "error status at index %d should not be nil", i)
				require.Equal(collect, int32(0), errStatus.Code, "error at index %d should be success (Code: 0)", i)
			}

			// Verify both messages are present
			resultsByNonce := make(map[uint64]*verifierpb.VerifierResult)
			for _, result := range batchResp.Results {
				resultsByNonce[result.GetMessage().GetSequenceNumber()] = result
			}

			result1, found := resultsByNonce[1001]
			require.True(collect, found, "message1 should be found in batch results")
			require.Equal(collect, destVerifierAddress, result1.Metadata.VerifierDestAddress, "dest verifier address should match")
			require.NotNil(collect, result1.CcvData, "CCV data should not be nil")

			result2, found := resultsByNonce[2002]
			require.True(collect, found, "message2 should be found in batch results")
			require.Equal(collect, destVerifierAddress, result2.Metadata.VerifierDestAddress, "dest verifier address should match")
			require.NotNil(collect, result2.CcvData, "CCV data should not be nil")
		}, 5*time.Second, 100*time.Millisecond, "batch retrieval with both messages should succeed")
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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create and aggregate a message
		message := NewProtocolMessage(t)
		message.SequenceNumber = protocol.SequenceNumber(1001)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")

		// Test batch request with duplicate message IDs - wait for aggregation to complete
		batchReqWithDuplicates := &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				messageId[:],
				messageId[:], // duplicate
				messageId[:], // another duplicate
			},
		}

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReqWithDuplicates)
			require.NoError(collect, err, "GetVerifierResultsForMessage with duplicates should not error")
			require.NotNil(collect, batchResp, "batch response with duplicates should not be nil")

			// Should have 3 results (1:1 correspondence with requests) and 3 errors (all successful)
			require.Len(collect, batchResp.Results, 3, "should have 3 results (1:1 correspondence)")
			require.Len(collect, batchResp.Errors, 3, "should have 3 errors (1:1 correspondence)")

			// All errors should be success (Code: 0)
			for i, errStatus := range batchResp.Errors {
				require.NotNil(collect, errStatus, "error status at index %d should not be nil", i)
				require.Equal(collect, int32(0), errStatus.Code, "error at index %d should be success (Code: 0)", i)
			}

			// Verify all results are correct and identical (since they're duplicates)
			for i, result := range batchResp.Results {
				require.Equal(collect, uint64(1001), result.GetMessage().GetSequenceNumber(), "nonce should match for result %d", i)
				require.Equal(collect, destVerifierAddress, result.Metadata.VerifierDestAddress, "dest verifier address should match for result %d", i)
			}
		}, 5*time.Second, 100*time.Millisecond, "batch retrieval with duplicate message IDs should succeed")
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
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create and aggregate one message
		existingMessage := NewProtocolMessage(t)
		existingMessage.SequenceNumber = protocol.SequenceNumber(1001)
		ccvNodeData1, existingMessageId := NewMessageWithCCVNodeData(t, existingMessage, sourceVerifierAddress, WithSignatureFrom(t, signer1))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer1")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, existingMessage, sourceVerifierAddress, WithSignatureFrom(t, signer2))
		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed for signer2")

		// Create a non-existent message ID
		nonExistentMessage := NewProtocolMessage(t)
		nonExistentMessage.SequenceNumber = protocol.SequenceNumber(9999)
		nonExistentMsgId, err := nonExistentMessage.MessageID()
		require.NoError(t, err, "failed to compute non-existent message ID")

		// Test batch request with mix of existing and non-existing messages - wait for aggregation to complete
		batchReqWithMissing := &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				existingMessageId[:], // exists
				nonExistentMsgId[:],  // doesn't exist
			},
		}

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReqWithMissing)
			require.NoError(collect, err, "GetVerifierResultsForMessage with missing should not error")
			require.NotNil(collect, batchResp, "batch response with missing should not be nil")

			// Should have 2 results and 2 errors (1:1 correspondence with requests)
			require.Len(collect, batchResp.Results, 2, "should have 2 results (1:1 with message IDs)")
			require.Len(collect, batchResp.Errors, 2, "should have 2 errors (1:1 with requests)")

			// First request (existing) should have Status with Code 0
			require.NotNil(collect, batchResp.Errors[0], "existing message should have Status with Code 0")
			require.Equal(collect, int32(codes.OK), batchResp.Errors[0].Code, "existing message should have Code 0")

			// Second request (missing) should have NotFound error
			require.NotNil(collect, batchResp.Errors[1], "missing message should have error")
			require.Equal(collect, int32(codes.NotFound), batchResp.Errors[1].Code, "missing message should have NotFound error")

			// Verify the first result is correct (existing message)
			require.NotNil(collect, batchResp.Results[0], "first result should not be nil")
			require.NotNil(collect, batchResp.Results[0].Message, "first result should have message")
			result := batchResp.Results[0]
			require.Equal(collect, uint64(1001), result.GetMessage().GetSequenceNumber(), "nonce should match")

			// Second result should be empty (not found) - protobuf may instantiate empty struct
			if batchResp.Results[1] != nil {
				require.Nil(collect, batchResp.Results[1].Message, "second result should be empty for not-found message")
			}
		}, 5*time.Second, 100*time.Millisecond, "batch retrieval with missing messages should return partial results")
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
		_, ccvDataClient, _, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		// Test empty batch request (should fail)
		emptyBatchReq := &verifierpb.GetVerifierResultsForMessageRequest{
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
			WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err)

		message := NewProtocolMessage(t)
		validCcvNodeData, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		validRequest := NewWriteCommitteeVerifierNodeResultRequest(validCcvNodeData)

		invalidMessage := NewProtocolMessage(t)
		invalidCcvNodeData1, _ := NewMessageWithCCVNodeData(t, invalidMessage, sourceVerifierAddress)
		invalidCcvNodeData1.Signature = nil
		invalidRequest1 := &committeepb.WriteCommitteeVerifierNodeResultRequest{
			CommitteeVerifierNodeResult: invalidCcvNodeData1,
		}

		invalidCcvNodeData2 := &committeepb.CommitteeVerifierNodeResult{
			Signature: []byte{},
		}
		invalidRequest2 := &committeepb.WriteCommitteeVerifierNodeResultRequest{
			CommitteeVerifierNodeResult: invalidCcvNodeData2,
		}

		batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
			Requests: []*committeepb.WriteCommitteeVerifierNodeResultRequest{
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
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Responses[0].Status)
		require.NotNil(t, resp.Errors[0], "successful request should have ok error")
		require.Equal(t, codes.OK, codes.Code(resp.Errors[0].Code))

		for i := 1; i <= 2; i++ {
			require.NotNil(t, resp.Responses[i], "failed request should have response")
			require.Equal(t, committeepb.WriteStatus_FAILED, resp.Responses[i].Status)

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
		)
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		// Create and aggregate one message to have one successful result
		message1 := NewProtocolMessage(t)
		ccvNodeData1, messageId1 := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer1))

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message1, sourceVerifierAddress, WithSignatureFrom(t, signer2))

		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")

		_, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")

		// Create a non-existent message ID
		nonExistentMessageId := make([]byte, 32)
		for i := range nonExistentMessageId {
			nonExistentMessageId[i] = 0xFF
		}

		// Test batch request with mix of existing and non-existing messages - wait for aggregation to complete
		batchReq := &verifierpb.GetVerifierResultsForMessageRequest{
			MessageIds: [][]byte{
				messageId1[:],        // Should succeed
				nonExistentMessageId, // Should fail with NotFound
				make([]byte, 32),     // Should fail with NotFound
			},
		}

		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), batchReq)
			require.NoError(collect, err, "GetVerifierResultsForMessage should not error")
			require.NotNil(collect, batchResp, "batch response should not be nil")

			// Verify 1:1 correspondence between requests and errors
			require.Len(collect, batchResp.Errors, 3, "should have 3 errors (1:1 with requests)")

			// First request should succeed (Status with Code 0)
			require.NotNil(collect, batchResp.Errors[0], "successful request should have Status with Code 0")
			require.Equal(collect, int32(codes.OK), batchResp.Errors[0].Code, "successful request should have Code 0")

			// Second and third requests should fail with NotFound
			for i := 1; i <= 2; i++ {
				require.NotNil(collect, batchResp.Errors[i], "failed request should have error")
				require.Equal(collect, int32(codes.NotFound), batchResp.Errors[i].Code, "failed request should have NotFound error")
			}

			// Should have exactly 3 results (1:1 correspondence with message IDs)
			require.Len(collect, batchResp.Results, 3, "should have 3 results (1:1 with message IDs)")

			// Verify the first result is correct (successful)
			require.NotNil(collect, batchResp.Results[0], "first result should not be nil")
			require.NotNil(collect, batchResp.Results[0].Message, "first result should have message")
			result := batchResp.Results[0]
			require.Equal(collect, uint64(message1.SequenceNumber), result.GetMessage().GetSequenceNumber(), "nonce should match")

			// Second and third results should be empty (not found) - protobuf may instantiate empty structs
			if batchResp.Results[1] != nil {
				require.Nil(collect, batchResp.Results[1].Message, "second result should be empty for not-found message")
			}
			if batchResp.Results[2] != nil {
				require.Nil(collect, batchResp.Results[2].Message, "third result should be empty for not-found message")
			}
		}, 5*time.Second, 100*time.Millisecond, "batch mixed success/failure test should complete with 1:1 error correspondence")
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

		aggregatorClient, _, _, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)

		// Step 1: Send verification from signer with old blob data
		oldBlobData := []byte{0x01, 0x02, 0x03, 0x04}
		ccvNodeData_old, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithCcvVersion(oldBlobData),
			WithSignatureFrom(t, signer1))

		resp, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData_old))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		// Step 2: Change blob data and send new verification from same signer
		newBlobData := []byte{0x05, 0x06, 0x07, 0x08}
		ccvNodeData_new, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithCcvVersion(newBlobData),
			WithSignatureFrom(t, signer1))

		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData_new))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		// Step 3: Verify ReadCommitteeVerifierNodeResult returns only the latest one (with new blob data)

		readResp, err := aggregatorClient.ReadCommitteeVerifierNodeResult(t.Context(), &committeepb.ReadCommitteeVerifierNodeResultRequest{
			MessageId: messageId[:],
			Address:   common.HexToAddress(signer1.Signer.Address).Bytes(),
		})
		require.NoError(t, err, "ReadCommitteeVerifierNodeResult should succeed")
		require.NotNil(t, readResp.CommitteeVerifierNodeResult, "should return node data")

		// Verify the returned data has the NEW blob data (not the old one)
		require.Equal(t, newBlobData, readResp.CommitteeVerifierNodeResult.CcvVersion, "should return latest record with new blob data")
		require.NotEqual(t, oldBlobData, readResp.CommitteeVerifierNodeResult.CcvVersion, "should not return old blob data")

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
		committee.QuorumConfigs["1"].Threshold = 2

		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")
		_ = messageDiscoveryClient // may be used later

		message := NewProtocolMessage(t)
		// Phase 1: Signer1 and Signer2 verify → aggregation happens (quorum reached)
		t.Log("Phase 1: Signer1 and Signer2 verify")
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))
		resp, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))
		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		// Verify aggregation with signer1 + signer2
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		// Phase 2: Signer3 verifies → no re-aggregation (stop-aggregation-after-quorum)
		t.Log("Phase 2: Signer3 verifies (should not trigger re-aggregation)")
		ccvNodeData3, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer3))
		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		// Sleep briefly to allow any potential re-aggregation to occur
		time.Sleep(200 * time.Millisecond)

		// Verify still only 2 signatures (no re-aggregation happened)
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData2.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer1), WithValidSignatureFrom(signer2), WithExactNumberOfSignatures(2))

		// Phase 3: Committee rotation - remove signer1, keep signer2 and signer3
		t.Log("Phase 3: Rotate committee - remove signer1, keep signer2 and signer3")
		UpdateCommitteeQuorum(committee, sourceVerifierAddress, signer2.Signer, signer3.Signer)

		// Phase 4: Signer3 verifies again → re-aggregation happens with new committee
		t.Log("Phase 4: Signer3 verifies again (should trigger re-aggregation)")
		ccvNodeData3New, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer3))
		resp, err = aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData3New))
		require.NoError(t, err)
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)

		// Verify re-aggregation with new committee (signer2 + signer3)
		assertCCVDataFound(t, t.Context(), ccvDataClient, messageId, ccvNodeData3New.GetMessage(), sourceVerifierAddress, destVerifierAddress, WithValidSignatureFrom(signer2), WithValidSignatureFrom(signer3), WithExactNumberOfSignatures(2))

		t.Log("✅ Key rotation after quorum: stop-aggregation-after-quorum works, then re-aggregation after rotation")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestGetVerifierResultsForMessage_ReturnsNotFoundWhenSourceVerifierNotInCCVAddresses verifies that
// GetVerifierResultsForMessage returns NotFound when the source verifier address is not in the ccvAddresses.
func TestGetVerifierResultsForMessage_ReturnsNotFoundWhenSourceVerifierNotInCCVAddresses(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, _, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)

		// Create a different address that is NOT the source verifier
		differentAddress := make([]byte, 20)
		for i := range differentAddress {
			differentAddress[i] = 0xAB
		}

		// Create ccvNodeData with ccvAddresses that do NOT include the source verifier
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithCcvAddresses(t, [][]byte{differentAddress}),
			WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithCcvAddresses(t, [][]byte{differentAddress}),
			WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		// GetVerifierResultsForMessage should return NotFound because source verifier is not in ccvAddresses
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), &verifierpb.GetVerifierResultsForMessageRequest{
				MessageIds: [][]byte{messageId[:]},
			})
			require.NoError(collect, err, "GetVerifierResultsForMessage should not return error")
			require.NotNil(collect, batchResp, "response should not be nil")
			require.Len(collect, batchResp.Results, 1, "should have 1 result slot")
			require.Len(collect, batchResp.Errors, 1, "should have 1 error slot")

			// Verify it returns NotFound
			require.Equal(collect, int32(codes.NotFound), batchResp.Errors[0].Code, "should return NotFound when source verifier not in ccvAddresses")
		}, 5*time.Second, 100*time.Millisecond, "should return NotFound when source verifier not in ccvAddresses")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestGetMessagesSince_ReturnsNilMetadataWhenSourceVerifierNotInCCVAddresses verifies that
// GetMessagesSince returns nil VerifierSourceAddress and VerifierDestAddress when source verifier
// is not in the ccvAddresses.
func TestGetMessagesSince_ReturnsNilMetadataWhenSourceVerifierNotInCCVAddresses(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, _, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)

		// Create a different address that is NOT the source verifier
		differentAddress := make([]byte, 20)
		for i := range differentAddress {
			differentAddress[i] = 0xCD
		}

		// Create ccvNodeData with ccvAddresses that do NOT include the source verifier
		ccvNodeData1, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithCcvAddresses(t, [][]byte{differentAddress}),
			WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithCcvAddresses(t, [][]byte{differentAddress}),
			WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		// GetMessagesSince should return the message but with nil metadata addresses
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			resp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, resp.Results, 1, "should have 1 result")

			result := resp.Results[0]
			require.NotNil(collect, result.VerifierResult, "VerifierResults should not be nil")
			require.NotNil(collect, result.VerifierResult.Metadata, "Metadata should not be nil")

			// Verify metadata addresses are nil because source verifier is not in ccvAddresses
			require.Nil(collect, result.VerifierResult.Metadata.VerifierSourceAddress, "VerifierSourceAddress should be nil when source verifier not in ccvAddresses")
			require.Nil(collect, result.VerifierResult.Metadata.VerifierDestAddress, "VerifierDestAddress should be nil when source verifier not in ccvAddresses")

			// Verify the rest of the data is still present
			require.NotNil(collect, result.VerifierResult.Message, "Message should still be present")
			require.NotNil(collect, result.VerifierResult.CcvData, "CcvData should still be present")
		}, 5*time.Second, 100*time.Millisecond, "should return nil metadata addresses when source verifier not in ccvAddresses")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}

// TestSourceVerifierInCCVAddresses_MetadataPopulated verifies that when source verifier IS in
// ccvAddresses, the metadata addresses are properly populated in both APIs.
func TestSourceVerifierInCCVAddresses_MetadataPopulated(t *testing.T) {
	t.Parallel()
	storageTypes := []string{"postgres"}

	testFunc := func(t *testing.T, storageType string) {
		sourceVerifierAddress, destVerifierAddress := GenerateVerifierAddresses(t)
		signer1 := NewSignerFixture(t, "node1")
		signer2 := NewSignerFixture(t, "node2")
		committee := NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer1.Signer, signer2.Signer)
		aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, err := CreateServerAndClient(t, WithCommitteeConfig(committee))
		t.Cleanup(cleanup)
		require.NoError(t, err, "failed to create server and client")

		message := NewProtocolMessage(t)

		// Create ccvNodeData with ccvAddresses that INCLUDE the source verifier (default behavior)
		ccvNodeData1, messageId := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer1))

		resp1, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData1))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp1.Status, "expected WriteStatus_SUCCESS")

		ccvNodeData2, _ := NewMessageWithCCVNodeData(t, message, sourceVerifierAddress,
			WithSignatureFrom(t, signer2))

		resp2, err := aggregatorClient.WriteCommitteeVerifierNodeResult(t.Context(), NewWriteCommitteeVerifierNodeResultRequest(ccvNodeData2))
		require.NoError(t, err, "WriteCommitteeVerifierNodeResult failed")
		require.Equal(t, committeepb.WriteStatus_SUCCESS, resp2.Status, "expected WriteStatus_SUCCESS")

		// Test GetVerifierResultsForMessage - should return OK with populated metadata
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			batchResp, err := ccvDataClient.GetVerifierResultsForMessage(t.Context(), &verifierpb.GetVerifierResultsForMessageRequest{
				MessageIds: [][]byte{messageId[:]},
			})
			require.NoError(collect, err, "GetVerifierResultsForMessage should succeed")
			require.NotNil(collect, batchResp, "response should not be nil")
			require.Len(collect, batchResp.Results, 1, "should have 1 result")
			require.Len(collect, batchResp.Errors, 1, "should have 1 error slot")
			require.Equal(collect, int32(codes.OK), batchResp.Errors[0].Code, "should return OK")

			result := batchResp.Results[0]
			require.NotNil(collect, result.Metadata, "Metadata should not be nil")
			require.Equal(collect, sourceVerifierAddress, result.Metadata.VerifierSourceAddress, "VerifierSourceAddress should be populated")
			require.Equal(collect, destVerifierAddress, result.Metadata.VerifierDestAddress, "VerifierDestAddress should be populated")
		}, 5*time.Second, 100*time.Millisecond, "GetVerifierResultsForMessage should return OK with populated metadata")

		// Test GetMessagesSince - should also have populated metadata
		require.EventuallyWithTf(t, func(collect *assert.CollectT) {
			msgResp, err := messageDiscoveryClient.GetMessagesSince(t.Context(), &msgdiscoverypb.GetMessagesSinceRequest{
				SinceSequence: 0,
			})
			require.NoError(collect, err, "GetMessagesSince should succeed")
			require.Len(collect, msgResp.Results, 1, "should have 1 result")

			msgResult := msgResp.Results[0]
			require.NotNil(collect, msgResult.VerifierResult.Metadata, "Metadata should not be nil")
			require.Equal(collect, sourceVerifierAddress, msgResult.VerifierResult.Metadata.VerifierSourceAddress, "VerifierSourceAddress should be populated")
			require.Equal(collect, destVerifierAddress, msgResult.VerifierResult.Metadata.VerifierDestAddress, "VerifierDestAddress should be populated")
		}, 5*time.Second, 100*time.Millisecond, "GetMessagesSince should return populated metadata")
	}

	for _, storageType := range storageTypes {
		t.Run(storageType, func(t *testing.T) {
			t.Parallel()
			testFunc(t, storageType)
		})
	}
}
