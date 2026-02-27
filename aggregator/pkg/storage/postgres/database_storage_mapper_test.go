package postgres

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestRecordToInsertParams(t *testing.T) {
	messageID := common.Hex2Bytes("deadbeef")
	signerAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	record := &model.CommitVerificationRecord{
		MessageID: messageID,
		Message: &protocol.Message{
			Version:              1,
			SourceChainSelector:  protocol.ChainSelector(1),
			DestChainSelector:    protocol.ChainSelector(2),
			SequenceNumber:       protocol.SequenceNumber(123),
			OnRampAddressLength:  20,
			OnRampAddress:        protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
			OffRampAddressLength: 20,
			OffRampAddress:       protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
			Finality:             10,
			SenderLength:         20,
			Sender:               protocol.UnknownAddress(common.HexToAddress("0x3333333333333333333333333333333333333333").Bytes()),
			ReceiverLength:       20,
			Receiver:             protocol.UnknownAddress(common.HexToAddress("0x4444444444444444444444444444444444444444").Bytes()),
			DestBlobLength:       10,
			DestBlob:             protocol.ByteSlice([]byte("destblob__")),
			TokenTransferLength:  0,
			TokenTransfer:        nil,
			DataLength:           8,
			Data:                 protocol.ByteSlice([]byte("testdata")),
			ExecutionGasLimit:    100000,
		},
		CCVVersion: []byte("ccv_version"),
		Signature:  []byte("signature_data"),
		SignerIdentifier: &model.SignerIdentifier{
			Identifier: protocol.ByteSlice(signerAddr.Bytes()),
		},
	}
	record.SetTimestampFromMillis(time.Now().UnixMilli())

	params, err := recordToInsertParams(record, "aggregation_key_1")
	require.NoError(t, err)
	require.NotNil(t, params)

	require.Equal(t, protocol.ByteSlice(messageID).String(), params["message_id"])
	require.Equal(t, protocol.ByteSlice(signerAddr.Bytes()).String(), params["signer_identifier"])
	require.Equal(t, "aggregation_key_1", params["aggregation_key"])

	messageDataJSON, ok := params["message_data"].([]byte)
	require.True(t, ok)

	// Verify the message is properly serialized with hex-encoded addresses (matching indexer)
	var msgData protocol.Message
	err = json.Unmarshal(messageDataJSON, &msgData)
	require.NoError(t, err)
	require.Equal(t, uint8(1), msgData.Version)
	require.Equal(t, protocol.ChainSelector(1), msgData.SourceChainSelector)
	require.Equal(t, protocol.ChainSelector(2), msgData.DestChainSelector)
	require.Equal(t, protocol.SequenceNumber(123), msgData.SequenceNumber)

	// Verify addresses are stored as hex strings with 0x prefix (not base64)
	var rawMsg map[string]any
	err = json.Unmarshal(messageDataJSON, &rawMsg)
	require.NoError(t, err)
	// Check that addresses are hex strings (starting with "0x")
	onRampAddr, ok := rawMsg["on_ramp_address"].(string)
	require.True(t, ok, "on_ramp_address should be a string")
	require.True(t, len(onRampAddr) > 2 && onRampAddr[:2] == "0x", "on_ramp_address should start with 0x")
	senderAddr, ok := rawMsg["sender"].(string)
	require.True(t, ok, "sender should be a string")
	require.True(t, len(senderAddr) > 2 && senderAddr[:2] == "0x", "sender should start with 0x")
}

func TestRowToCommitVerificationRecord(t *testing.T) {
	messageIDHex := "deadbeef"
	signerIdentifier := "0x1234567890123456789012345678901234567890"

	row := &commitVerificationRecordRow{
		ID:               1,
		MessageID:        messageIDHex,
		SignerIdentifier: signerIdentifier,
		CreatedAt:        time.Now().UTC(),
		AggregationKey:   "aggregation_key_1",
		CCVVersion:       []byte("ccv_version"),
		Signature:        []byte("signature_data"),
	}

	// Create test message matching protocol.Message structure
	testMessage := &protocol.Message{
		Version:              1,
		SourceChainSelector:  protocol.ChainSelector(1),
		DestChainSelector:    protocol.ChainSelector(2),
		OnRampAddress:        protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
		OffRampAddress:       protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
		Sender:               protocol.UnknownAddress(common.HexToAddress("0x3333333333333333333333333333333333333333").Bytes()),
		SenderLength:         20,
		Data:                 []byte("testdata"),
		DataLength:           8,
		TokenTransfer:        nil,
		TokenTransferLength:  0,
		DestBlob:             []byte("destblob__"),
		DestBlobLength:       10,
		Receiver:             protocol.UnknownAddress(common.HexToAddress("0x4444444444444444444444444444444444444444").Bytes()),
		ReceiverLength:       20,
		SequenceNumber:       protocol.SequenceNumber(123),
		Finality:             10,
		ExecutionGasLimit:    100000,
		CcipReceiveGasLimit:  50000,
		OnRampAddressLength:  20,
		OffRampAddressLength: 20,
	}
	// Use protocol.Message marshaling (which uses custom JSON for addresses)
	msgDataJSON, err := json.Marshal(testMessage)
	require.NoError(t, err)
	row.MessageData = msgDataJSON

	record, err := rowToCommitVerificationRecord(row)
	require.NoError(t, err)
	require.NotNil(t, record)

	expectedMsgID, _ := protocol.NewByteSliceFromHex(messageIDHex)
	require.Equal(t, []byte(expectedMsgID), record.MessageID)
	expectedSignerID, _ := protocol.NewByteSliceFromHex(signerIdentifier)
	require.Equal(t, expectedSignerID, record.SignerIdentifier.Identifier)

	require.NotNil(t, record.Message)
	require.Equal(t, uint8(1), record.Message.Version)
	require.Equal(t, protocol.ChainSelector(1), record.Message.SourceChainSelector)
	require.Equal(t, protocol.ChainSelector(2), record.Message.DestChainSelector)
	require.Equal(t, protocol.SequenceNumber(123), record.Message.SequenceNumber)

	require.Equal(t, []byte("ccv_version"), record.CCVVersion)
	require.Equal(t, []byte("signature_data"), record.Signature)
}

func mustParseUint64(t *testing.T, s string) uint64 {
	t.Helper()
	var result uint64
	_, _ = fmt.Sscanf(s, "%d", &result)
	return result
}

func TestMustParseUint64(t *testing.T) {
	require.Equal(t, uint64(123), mustParseUint64(t, "123"))
	require.Equal(t, uint64(0), mustParseUint64(t, "0"))
	require.Equal(t, uint64(18446744073709551615), mustParseUint64(t, "18446744073709551615"))
}
