package model

import (
	"encoding/json"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func TestMessageMappingRoundTrip_PreservesMessageID(t *testing.T) {
	message := createComprehensiveMessage(t)

	originalID, err := message.MessageID()
	require.NoError(t, err)

	protoMessage, err := common.MapProtocolMessageToProtoMessage(message)
	require.NoError(t, err)
	require.NotNil(t, protoMessage)

	convertedMessage, err := common.MapProtoMessageToProtocolMessage(protoMessage)
	require.NoError(t, err)
	require.NotNil(t, convertedMessage)

	convertedID, err := convertedMessage.MessageID()
	require.NoError(t, err)

	assert.Equal(t, originalID, convertedID, "MessageID should remain identical after round-trip conversion")
	assertMessagesEqual(t, message, convertedMessage)
}

func createComprehensiveMessage(t *testing.T) *protocol.Message {
	t.Helper()

	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRamp, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRamp, err := protocol.RandomAddress()
	require.NoError(t, err)

	tokenTransfer := &protocol.TokenTransfer{
		Version:                  protocol.MessageVersion,
		Amount:                   big.NewInt(1000000),
		SourceTokenAddressLength: 20,
		SourceTokenAddress:       make([]byte, 20),
		DestTokenAddressLength:   20,
		DestTokenAddress:         make([]byte, 20),
		TokenReceiverLength:      20,
		TokenReceiver:            make([]byte, 20),
		ExtraDataLength:          10,
		ExtraData:                []byte("extra_data"),
	}

	for i := range tokenTransfer.SourceTokenAddress {
		tokenTransfer.SourceTokenAddress[i] = byte(i + 1)
	}
	for i := range tokenTransfer.DestTokenAddress {
		tokenTransfer.DestTokenAddress[i] = byte(i + 50)
	}
	for i := range tokenTransfer.TokenReceiver {
		tokenTransfer.TokenReceiver[i] = byte(i + 100)
	}

	destBlob := make([]byte, 50)
	for i := range destBlob {
		destBlob[i] = byte(i + 200)
	}

	messageData := make([]byte, 100)
	for i := range messageData {
		messageData[i] = byte(i + 150)
	}

	message, err := protocol.NewMessage(
		protocol.ChainSelector(1337),
		protocol.ChainSelector(2337),
		protocol.SequenceNumber(12345),
		onRamp,
		offRamp,
		25,
		300_000,
		300_000,            // ccipReceiveGasLimit
		protocol.Bytes32{}, // ccvAndExecutorHash
		sender,
		receiver,
		destBlob,
		messageData,
		tokenTransfer,
	)
	require.NoError(t, err)
	return message
}

func assertMessagesEqual(t *testing.T, expected, actual *protocol.Message) {
	t.Helper()

	assert.Equal(t, expected.Version, actual.Version)
	assert.Equal(t, expected.SourceChainSelector, actual.SourceChainSelector)
	assert.Equal(t, expected.DestChainSelector, actual.DestChainSelector)
	assert.Equal(t, expected.SequenceNumber, actual.SequenceNumber)
	assert.Equal(t, expected.OnRampAddressLength, actual.OnRampAddressLength)
	assert.Equal(t, expected.OnRampAddress, actual.OnRampAddress)
	assert.Equal(t, expected.OffRampAddressLength, actual.OffRampAddressLength)
	assert.Equal(t, expected.OffRampAddress, actual.OffRampAddress)
	assert.Equal(t, expected.Finality, actual.Finality)
	assert.Equal(t, expected.SenderLength, actual.SenderLength)
	assert.Equal(t, expected.Sender, actual.Sender)
	assert.Equal(t, expected.ReceiverLength, actual.ReceiverLength)
	assert.Equal(t, expected.Receiver, actual.Receiver)
	assert.Equal(t, expected.DestBlobLength, actual.DestBlobLength)
	assert.Equal(t, expected.DestBlob, actual.DestBlob)
	assert.Equal(t, expected.TokenTransferLength, actual.TokenTransferLength)
	assert.Equal(t, expected.TokenTransfer, actual.TokenTransfer)
	assert.Equal(t, expected.DataLength, actual.DataLength)
	assert.Equal(t, expected.Data, actual.Data)

	expectedJSON, err := json.Marshal(expected)
	require.NoError(t, err, "Failed to marshal expected message to JSON")

	actualJSON, err := json.Marshal(actual)
	require.NoError(t, err, "Failed to marshal actual message to JSON")

	assert.JSONEq(t, string(expectedJSON), string(actualJSON), "JSON representations should be identical")
}

func TestIsSourceVerifierInCCVAddresses(t *testing.T) {
	addr1 := protocol.UnknownAddress([]byte{0x01, 0x02, 0x03})
	addr2 := protocol.UnknownAddress([]byte{0x04, 0x05, 0x06})
	addr3 := protocol.UnknownAddress([]byte{0x07, 0x08, 0x09})

	tests := []struct {
		name         string
		sourceAddr   protocol.UnknownAddress
		ccvAddresses []protocol.UnknownAddress
		expected     bool
	}{
		{
			name:         "address found in list",
			sourceAddr:   addr1,
			ccvAddresses: []protocol.UnknownAddress{addr1, addr2},
			expected:     true,
		},
		{
			name:         "address not in list",
			sourceAddr:   addr3,
			ccvAddresses: []protocol.UnknownAddress{addr1, addr2},
			expected:     false,
		},
		{
			name:         "empty list returns false",
			sourceAddr:   addr1,
			ccvAddresses: []protocol.UnknownAddress{},
			expected:     false,
		},
		{
			name:         "nil list returns false",
			sourceAddr:   addr1,
			ccvAddresses: nil,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSourceVerifierInCCVAddresses(tt.sourceAddr, tt.ccvAddresses)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCommitVerificationRecordFromProto(t *testing.T) {
	t.Run("converts proto with message successfully", func(t *testing.T) {
		msg := createComprehensiveMessage(t)
		protoMsg, err := common.MapProtocolMessageToProtoMessage(msg)
		require.NoError(t, err)

		proto := &committeepb.CommitteeVerifierNodeResult{
			Message:         protoMsg,
			CcvVersion:      []byte{0x01, 0x02, 0x03, 0x04},
			Signature:       []byte{0xaa, 0xbb, 0xcc},
			CcvAddresses:    [][]byte{{0x11, 0x22}, {0x33, 0x44}},
			ExecutorAddress: []byte{0x55, 0x66, 0x77},
		}

		record, err := CommitVerificationRecordFromProto(proto)
		require.NoError(t, err)
		require.NotNil(t, record)

		assert.Equal(t, proto.CcvVersion, record.CCVVersion)
		assert.Equal(t, proto.Signature, record.Signature)
		assert.Len(t, record.MessageCCVAddresses, 2)
		assert.Equal(t, protocol.UnknownAddress([]byte{0x55, 0x66, 0x77}), record.MessageExecutorAddress)
		assert.NotNil(t, record.Message)
		assert.NotEmpty(t, record.MessageID)
	})

	t.Run("converts proto without message", func(t *testing.T) {
		proto := &committeepb.CommitteeVerifierNodeResult{
			CcvVersion:      []byte{0x01, 0x02},
			Signature:       []byte{0xaa},
			CcvAddresses:    [][]byte{},
			ExecutorAddress: []byte{0x55},
		}

		record, err := CommitVerificationRecordFromProto(proto)
		require.NoError(t, err)
		require.NotNil(t, record)

		assert.Nil(t, record.Message)
		assert.Empty(t, record.MessageID)
	})
}

func TestCommitVerificationRecordToProto(t *testing.T) {
	t.Run("converts record with message successfully", func(t *testing.T) {
		msg := createComprehensiveMessage(t)

		record := &CommitVerificationRecord{
			Message:                msg,
			CCVVersion:             []byte{0x01, 0x02, 0x03, 0x04},
			Signature:              []byte{0xaa, 0xbb, 0xcc},
			MessageCCVAddresses:    []protocol.UnknownAddress{{0x11, 0x22}, {0x33, 0x44}},
			MessageExecutorAddress: protocol.UnknownAddress([]byte{0x55, 0x66, 0x77}),
		}

		proto, err := CommitVerificationRecordToProto(record)
		require.NoError(t, err)
		require.NotNil(t, proto)

		assert.Equal(t, record.CCVVersion, proto.CcvVersion)
		assert.Equal(t, record.Signature, proto.Signature)
		assert.Len(t, proto.CcvAddresses, 2)
		assert.Equal(t, []byte{0x55, 0x66, 0x77}, proto.ExecutorAddress)
		assert.NotNil(t, proto.Message)
	})

	t.Run("converts record without message", func(t *testing.T) {
		record := &CommitVerificationRecord{
			CCVVersion:             []byte{0x01},
			Signature:              []byte{0xaa},
			MessageCCVAddresses:    []protocol.UnknownAddress{},
			MessageExecutorAddress: protocol.UnknownAddress([]byte{0x55}),
		}

		proto, err := CommitVerificationRecordToProto(record)
		require.NoError(t, err)
		require.NotNil(t, proto)

		assert.Nil(t, proto.Message)
	})
}

func TestCommitVerificationRecord_ProtoRoundTrip(t *testing.T) {
	msg := createComprehensiveMessage(t)

	original := &CommitVerificationRecord{
		Message:                msg,
		CCVVersion:             []byte{0x01, 0x02, 0x03, 0x04},
		Signature:              []byte{0xaa, 0xbb, 0xcc, 0xdd},
		MessageCCVAddresses:    []protocol.UnknownAddress{{0x11, 0x22}, {0x33, 0x44}},
		MessageExecutorAddress: protocol.UnknownAddress([]byte{0x55, 0x66, 0x77, 0x88}),
	}

	proto, err := CommitVerificationRecordToProto(original)
	require.NoError(t, err)

	converted, err := CommitVerificationRecordFromProto(proto)
	require.NoError(t, err)

	assert.Equal(t, original.CCVVersion, converted.CCVVersion)
	assert.Equal(t, original.Signature, converted.Signature)
	assert.Equal(t, original.MessageExecutorAddress, converted.MessageExecutorAddress)
	assert.Len(t, converted.MessageCCVAddresses, len(original.MessageCCVAddresses))

	originalID, err := original.Message.MessageID()
	require.NoError(t, err)
	convertedID, err := converted.Message.MessageID()
	require.NoError(t, err)
	assert.Equal(t, originalID, convertedID)
}

func TestFilterSignaturesByQuorum(t *testing.T) {
	signerAddr1 := ethcommon.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signerAddr2 := ethcommon.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	signerAddr3 := ethcommon.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	addressSignatures := map[string]protocol.Data{
		normalizeHexAddress(signerAddr1.Hex()): {R: [32]byte{1}, S: [32]byte{2}, Signer: signerAddr1},
		normalizeHexAddress(signerAddr2.Hex()): {R: [32]byte{3}, S: [32]byte{4}, Signer: signerAddr2},
	}

	tests := []struct {
		name        string
		sigs        map[string]protocol.Data
		config      *QuorumConfig
		expectCount int
		expectErr   string
	}{
		{
			name: "returns_all_matching_signatures_at_threshold",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr1.Hex()}, {Address: signerAddr2.Hex()}},
				Threshold: 2,
			},
			expectCount: 2,
		},
		{
			name: "returns_matching_signatures_above_threshold",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr1.Hex()}, {Address: signerAddr2.Hex()}},
				Threshold: 1,
			},
			expectCount: 2,
		},
		{
			name: "handles_address_without_0x_prefix",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr1.Hex()[2:]}},
				Threshold: 1,
			},
			expectCount: 1,
		},
		{
			name: "case_insensitive_matching",
			sigs: map[string]protocol.Data{
				"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {R: [32]byte{1}, S: [32]byte{2}, Signer: signerAddr1},
			},
			config: &QuorumConfig{
				Signers:   []Signer{{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
				Threshold: 1,
			},
			expectCount: 1,
		},
		{
			name: "skips_signers_not_in_map_still_meets_threshold",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr1.Hex()}, {Address: signerAddr3.Hex()}},
				Threshold: 1,
			},
			expectCount: 1,
		},
		{
			name: "deduplicates_config_signers_with_same_address",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr1.Hex()}, {Address: signerAddr1.Hex()}},
				Threshold: 1,
			},
			expectCount: 1,
		},
		{
			name: "errors_when_valid_signatures_below_threshold",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr1.Hex()}},
				Threshold: 2,
			},
			expectErr: "below quorum threshold",
		},
		{
			name: "errors_when_no_signatures_match",
			sigs: addressSignatures,
			config: &QuorumConfig{
				Signers:   []Signer{{Address: signerAddr3.Hex()}},
				Threshold: 1,
			},
			expectErr: "below quorum threshold",
		},
		{
			name:      "errors_when_config_is_nil",
			sigs:      addressSignatures,
			config:    nil,
			expectErr: "quorum config is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := filterSignaturesByQuorum(tt.sigs, tt.config)
			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectErr)
			} else {
				require.NoError(t, err)
				assert.Len(t, result, tt.expectCount)
			}
		})
	}
}
