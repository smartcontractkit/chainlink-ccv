package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestRecordToInsertParams(t *testing.T) {
	messageID := common.Hex2Bytes("deadbeef")
	signerAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sourceVerifier := common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")

	var sigR, sigS [32]byte
	copy(sigR[:], []byte("signature_r_data_here_______"))
	copy(sigS[:], []byte("signature_s_data_here_______"))

	record := &model.CommitVerificationRecord{
		MessageID:             messageID,
		SourceVerifierAddress: sourceVerifier.Bytes(),
		Message: &protocol.Message{
			Version:              1,
			SourceChainSelector:  protocol.ChainSelector(1),
			DestChainSelector:    protocol.ChainSelector(2),
			Nonce:                protocol.Nonce(123),
			OnRampAddressLength:  20,
			OnRampAddress:        common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes(),
			OffRampAddressLength: 20,
			OffRampAddress:       common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes(),
			Finality:             10,
			SenderLength:         20,
			Sender:               common.HexToAddress("0x3333333333333333333333333333333333333333").Bytes(),
			ReceiverLength:       20,
			Receiver:             common.HexToAddress("0x4444444444444444444444444444444444444444").Bytes(),
			DestBlobLength:       10,
			DestBlob:             []byte("destblob__"),
			TokenTransferLength:  0,
			TokenTransfer:        []byte{},
			DataLength:           8,
			Data:                 []byte("testdata"),
			GasLimit:             100000,
		},
		BlobData:  []byte("blob_data"),
		CcvData:   []byte("ccv_data"),
		Timestamp: time.Now().UTC(),
		ReceiptBlobs: []*model.ReceiptBlob{
			{
				Issuer:            sourceVerifier.Bytes(),
				DestGasLimit:      50000,
				DestBytesOverhead: 100,
				Blob:              []byte("receipt_blob"),
				ExtraArgs:         []byte("extra_args"),
			},
		},
		IdentifierSigner: &model.IdentifierSigner{
			Signer: model.Signer{
				ParticipantID: "participant1",
			},
			Address:     signerAddr.Bytes(),
			SignatureR:  sigR,
			SignatureS:  sigS,
			CommitteeID: "committee1",
		},
		CommitteeID:    "committee1",
		IdempotencyKey: uuid.New(),
	}

	params, err := recordToInsertParams(record, "aggregation_key_1")
	require.NoError(t, err)
	require.NotNil(t, params)

	require.Equal(t, common.Bytes2Hex(messageID), params["message_id"])
	require.Equal(t, "committee1", params["committee_id"])
	require.Equal(t, "participant1", params["participant_id"])
	require.Equal(t, signerAddr.Hex(), params["signer_address"])
	require.Equal(t, "1", params["source_chain_selector"])
	require.Equal(t, "2", params["dest_chain_selector"])
	require.Equal(t, "aggregation_key_1", params["aggregation_key"])

	messageDataJSON, ok := params["message_data"].([]byte)
	require.True(t, ok)
	var msgData struct {
		Version uint8  `json:"version"`
		Nonce   uint64 `json:"nonce"`
	}
	err = json.Unmarshal(messageDataJSON, &msgData)
	require.NoError(t, err)
	require.Equal(t, uint8(1), msgData.Version)
	require.Equal(t, uint64(123), msgData.Nonce)
}

func TestRowToCommitVerificationRecord(t *testing.T) {
	messageIDHex := "deadbeef"
	signerAddr := "0x1234567890123456789012345678901234567890"

	var sigR, sigS [32]byte
	copy(sigR[:], []byte("signature_r_data_here_______"))
	copy(sigS[:], []byte("signature_s_data_here_______"))

	row := &commitVerificationRecordRow{
		ID:                    1,
		MessageID:             messageIDHex,
		CommitteeID:           "committee1",
		ParticipantID:         "participant1",
		SignerAddress:         signerAddr,
		SourceChainSelector:   "1",
		DestChainSelector:     "2",
		OnrampAddress:         "0x1111111111111111111111111111111111111111",
		OfframpAddress:        "0x2222222222222222222222222222222222222222",
		SignatureR:            sigR[:],
		SignatureS:            sigS[:],
		VerificationTimestamp: time.Now().UTC(),
		IdempotencyKey:        uuid.New(),
		AggregationKey:        "aggregation_key_1",
		SourceVerifierAddress: common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
		BlobData:              []byte("blob_data"),
		CcvData:               []byte("ccv_data"),
	}

	msgData := messageDataJSON{
		Version:              1,
		Sender:               common.HexToAddress("0x3333333333333333333333333333333333333333").Bytes(),
		SenderLength:         20,
		Data:                 []byte("testdata"),
		DataLength:           8,
		TokenTransfer:        []byte{},
		TokenTransferLength:  0,
		DestBlob:             []byte("destblob__"),
		DestBlobLength:       10,
		Receiver:             common.HexToAddress("0x4444444444444444444444444444444444444444").Bytes(),
		ReceiverLength:       20,
		Nonce:                123,
		Finality:             10,
		GasLimit:             100000,
		OnRampAddressLength:  20,
		OffRampAddressLength: 20,
	}
	msgDataJSON, err := json.Marshal(msgData)
	require.NoError(t, err)
	row.MessageData = msgDataJSON

	// Manually add receipt blobs as JSON
	receiptBlobsJSON, err := json.Marshal([]*model.ReceiptBlob{
		{
			Issuer:            common.HexToAddress("0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd").Bytes(),
			DestGasLimit:      50000,
			DestBytesOverhead: 100,
			Blob:              []byte("receipt_blob"),
			ExtraArgs:         []byte("extra_args"),
		},
	})
	require.NoError(t, err)
	row.ReceiptBlobs = receiptBlobsJSON

	record, err := rowToCommitVerificationRecord(row)
	require.NoError(t, err)
	require.NotNil(t, record)

	require.Equal(t, common.Hex2Bytes(messageIDHex), record.MessageID)
	require.Equal(t, "committee1", record.CommitteeID)
	require.Equal(t, "participant1", record.IdentifierSigner.ParticipantID)
	require.Equal(t, common.HexToAddress(signerAddr).Bytes(), record.IdentifierSigner.Address)
	require.Equal(t, sigR, record.IdentifierSigner.SignatureR)
	require.Equal(t, sigS, record.IdentifierSigner.SignatureS)

	require.NotNil(t, record.Message)
	require.Equal(t, uint8(1), record.Message.Version)
	require.Equal(t, protocol.ChainSelector(1), record.Message.SourceChainSelector)
	require.Equal(t, protocol.ChainSelector(2), record.Message.DestChainSelector)
	require.Equal(t, protocol.Nonce(123), record.Message.Nonce)

	require.Len(t, record.ReceiptBlobs, 1)
	require.Equal(t, uint64(50000), record.ReceiptBlobs[0].DestGasLimit)
}

func TestMustParseUint64(t *testing.T) {
	require.Equal(t, uint64(123), mustParseUint64("123"))
	require.Equal(t, uint64(0), mustParseUint64("0"))
	require.Equal(t, uint64(18446744073709551615), mustParseUint64("18446744073709551615"))
}
