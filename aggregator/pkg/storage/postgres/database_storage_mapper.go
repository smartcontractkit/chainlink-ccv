package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type commitVerificationRecordRow struct {
	ID                    int64     `db:"id"`
	SeqNum                int64     `db:"seq_num"`
	MessageID             string    `db:"message_id"`
	ParticipantID         string    `db:"participant_id"`
	SignerAddress         string    `db:"signer_address"`
	SignatureR            []byte    `db:"signature_r"`
	SignatureS            []byte    `db:"signature_s"`
	VerificationTimestamp time.Time `db:"verification_timestamp"`
	IdempotencyKey        uuid.UUID `db:"idempotency_key"`
	AggregationKey        string    `db:"aggregation_key"`
	SourceVerifierAddress []byte    `db:"source_verifier_address"`
	BlobData              []byte    `db:"blob_data"`
	CcvData               []byte    `db:"ccv_data"`
	MessageData           []byte    `db:"message_data"`
	ReceiptBlobs          []byte    `db:"receipt_blobs"`
	CreatedAt             time.Time `db:"created_at"`
}

type messageDataJSON struct {
	Version              uint8  `json:"version"`
	SourceChainSelector  uint64 `json:"source_chain_selector"`
	DestChainSelector    uint64 `json:"dest_chain_selector"`
	OnRampAddress        []byte `json:"onramp_address"`
	OffRampAddress       []byte `json:"offramp_address"`
	Sender               []byte `json:"sender"`
	SenderLength         uint8  `json:"sender_length"`
	Data                 []byte `json:"data"`
	DataLength           uint16 `json:"data_length"`
	TokenTransfer        []byte `json:"token_transfer"`
	TokenTransferLength  uint16 `json:"token_transfer_length"`
	DestBlob             []byte `json:"dest_blob"`
	DestBlobLength       uint16 `json:"dest_blob_length"`
	Receiver             []byte `json:"receiver"`
	ReceiverLength       uint8  `json:"receiver_length"`
	Nonce                uint64 `json:"nonce"`
	Finality             uint16 `json:"finality"`
	GasLimit             uint32 `json:"gas_limit"`
	OnRampAddressLength  uint8  `json:"onramp_address_length"`
	OffRampAddressLength uint8  `json:"offramp_address_length"`
}

func rowToCommitVerificationRecord(row *commitVerificationRecordRow) (*model.CommitVerificationRecord, error) {
	messageID := common.Hex2Bytes(row.MessageID)
	signerAddrBytes := common.HexToAddress(row.SignerAddress).Bytes()

	var sigR, sigS [32]byte
	copy(sigR[:], row.SignatureR)
	copy(sigS[:], row.SignatureS)

	identifierSigner := &model.IdentifierSigner{
		ParticipantID: row.ParticipantID,
		Address:       signerAddrBytes,
		SignatureR:    sigR,
		SignatureS:    sigS,
	}

	var msgData messageDataJSON
	if err := json.Unmarshal(row.MessageData, &msgData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message_data: %w", err)
	}

	message := &protocol.Message{
		Version:              msgData.Version,
		SourceChainSelector:  protocol.ChainSelector(msgData.SourceChainSelector),
		DestChainSelector:    protocol.ChainSelector(msgData.DestChainSelector),
		Nonce:                protocol.Nonce(msgData.Nonce),
		OnRampAddressLength:  msgData.OnRampAddressLength,
		OnRampAddress:        msgData.OnRampAddress,
		OffRampAddressLength: msgData.OffRampAddressLength,
		OffRampAddress:       msgData.OffRampAddress,
		Finality:             msgData.Finality,
		SenderLength:         msgData.SenderLength,
		Sender:               msgData.Sender,
		ReceiverLength:       msgData.ReceiverLength,
		Receiver:             msgData.Receiver,
		DestBlobLength:       msgData.DestBlobLength,
		DestBlob:             msgData.DestBlob,
		TokenTransferLength:  msgData.TokenTransferLength,
		TokenTransfer:        msgData.TokenTransfer,
		DataLength:           msgData.DataLength,
		Data:                 msgData.Data,
		GasLimit:             msgData.GasLimit,
	}

	var receiptBlobs []*model.ReceiptBlob
	if len(row.ReceiptBlobs) > 0 {
		if err := json.Unmarshal(row.ReceiptBlobs, &receiptBlobs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal receipt blobs: %w", err)
		}
	}

	return &model.CommitVerificationRecord{
		MessageID:             messageID,
		SourceVerifierAddress: row.SourceVerifierAddress,
		Message:               message,
		BlobData:              row.BlobData,
		CcvData:               row.CcvData,
		Timestamp:             row.VerificationTimestamp,
		ReceiptBlobs:          receiptBlobs,
		IdentifierSigner:      identifierSigner,
		IdempotencyKey:        row.IdempotencyKey,
	}, nil
}

func recordToInsertParams(record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) (map[string]any, error) {
	if record == nil {
		return nil, fmt.Errorf("record cannot be nil")
	}
	if record.Message == nil {
		return nil, fmt.Errorf("record.Message cannot be nil")
	}
	if record.IdentifierSigner == nil {
		return nil, fmt.Errorf("record.IdentifierSigner cannot be nil")
	}

	messageIDHex := common.Bytes2Hex(record.MessageID)
	signerAddressHex := common.BytesToAddress(record.IdentifierSigner.Address).Hex()

	msgData := messageDataJSON{
		Version:              record.Message.Version,
		SourceChainSelector:  uint64(record.Message.SourceChainSelector),
		DestChainSelector:    uint64(record.Message.DestChainSelector),
		OnRampAddress:        record.Message.OnRampAddress,
		OffRampAddress:       record.Message.OffRampAddress,
		Sender:               record.Message.Sender,
		SenderLength:         record.Message.SenderLength,
		Data:                 record.Message.Data,
		DataLength:           record.Message.DataLength,
		TokenTransfer:        record.Message.TokenTransfer,
		TokenTransferLength:  record.Message.TokenTransferLength,
		DestBlob:             record.Message.DestBlob,
		DestBlobLength:       record.Message.DestBlobLength,
		Receiver:             record.Message.Receiver,
		ReceiverLength:       record.Message.ReceiverLength,
		Nonce:                uint64(record.Message.Nonce),
		Finality:             record.Message.Finality,
		GasLimit:             record.Message.GasLimit,
		OnRampAddressLength:  record.Message.OnRampAddressLength,
		OffRampAddressLength: record.Message.OffRampAddressLength,
	}

	messageDataJSON, err := json.Marshal(msgData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message_data: %w", err)
	}

	params := map[string]any{
		"message_id":              messageIDHex,
		"participant_id":          record.IdentifierSigner.ParticipantID,
		"signer_address":          signerAddressHex,
		"signature_r":             record.IdentifierSigner.SignatureR[:],
		"signature_s":             record.IdentifierSigner.SignatureS[:],
		"verification_timestamp":  record.Timestamp,
		"idempotency_key":         record.IdempotencyKey,
		"aggregation_key":         aggregationKey,
		"source_verifier_address": record.SourceVerifierAddress,
		"blob_data":               record.BlobData,
		"ccv_data":                record.CcvData,
		"message_data":            messageDataJSON,
	}

	if len(record.ReceiptBlobs) > 0 {
		receiptBlobsJSON, err := json.Marshal(record.ReceiptBlobs)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal receipt blobs: %w", err)
		}
		params["receipt_blobs"] = receiptBlobsJSON
	}

	return params, nil
}

const allVerificationRecordColumns = `message_id, participant_id, signer_address, 
	signature_r, signature_s, verification_timestamp, idempotency_key, aggregation_key,
	source_verifier_address, blob_data, ccv_data, message_data, receipt_blobs, id`

const allVerificationRecordColumnsQualified = `cvr.message_id, cvr.participant_id, cvr.signer_address, 
	cvr.signature_r, cvr.signature_s, cvr.verification_timestamp, cvr.idempotency_key, cvr.aggregation_key,
	cvr.source_verifier_address, cvr.blob_data, cvr.ccv_data, cvr.message_data, cvr.receipt_blobs, cvr.id`

func mustParseUint64(s string) uint64 {
	var result uint64
	_, _ = fmt.Sscanf(s, "%d", &result)
	return result
}
