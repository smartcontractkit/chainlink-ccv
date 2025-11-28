package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type commitVerificationRecordRow struct {
	ID                        int64          `db:"id"`
	SeqNum                    int64          `db:"seq_num"`
	MessageID                 string         `db:"message_id"`
	SignerAddress             string         `db:"signer_address"`
	SignatureR                []byte         `db:"signature_r"`
	SignatureS                []byte         `db:"signature_s"`
	AggregationKey            string         `db:"aggregation_key"`
	CCVVersion                []byte         `db:"ccv_version"`
	Signature                 []byte         `db:"signature"`
	MessageCCVAddresses       pq.StringArray `db:"message_ccv_addresses"`
	MessageExecutorAddress    string         `db:"message_executor_address"`
	MessageData               []byte         `db:"message_data"`
	SourceChainBlockTimestamp time.Time      `db:"source_chain_block_timestamp"`
	CreatedAt                 time.Time      `db:"created_at"`
}

func rowToCommitVerificationRecord(row *commitVerificationRecordRow) (*model.CommitVerificationRecord, error) {
	messageID := common.Hex2Bytes(row.MessageID)
	signerAddrBytes := common.HexToAddress(row.SignerAddress).Bytes()

	var sigR, sigS [32]byte
	copy(sigR[:], row.SignatureR)
	copy(sigS[:], row.SignatureS)

	identifierSigner := &model.IdentifierSigner{
		Address:    signerAddrBytes,
		SignatureR: sigR,
		SignatureS: sigS,
	}

	var message protocol.Message
	if err := json.Unmarshal(row.MessageData, &message); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message_data: %w", err)
	}

	// Convert MessageCCVAddresses from hex strings to UnknownAddress slice
	messageCCVAddresses := make([]protocol.UnknownAddress, 0, len(row.MessageCCVAddresses))
	for _, hexAddr := range row.MessageCCVAddresses {
		addrBytes, err := protocol.NewUnknownAddressFromHex(hexAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode message_ccv_address %s: %w", hexAddr, err)
		}
		messageCCVAddresses = append(messageCCVAddresses, addrBytes)
	}

	// Convert MessageExecutorAddress from hex string to UnknownAddress
	var messageExecutorAddress protocol.UnknownAddress
	if row.MessageExecutorAddress != "" {
		var err error
		messageExecutorAddress, err = protocol.NewUnknownAddressFromHex(row.MessageExecutorAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to decode message_executor_address %s: %w", row.MessageExecutorAddress, err)
		}
	}

	record := &model.CommitVerificationRecord{
		MessageID:                 messageID,
		Message:                   &message,
		CCVVersion:                row.CCVVersion,
		Signature:                 row.Signature,
		MessageCCVAddresses:       messageCCVAddresses,
		MessageExecutorAddress:    messageExecutorAddress,
		SourceChainBlockTimestamp: row.SourceChainBlockTimestamp,
		IdentifierSigner:          identifierSigner,
	}
	record.SetTimestampFromMillis(row.CreatedAt.UnixMilli())
	return record, nil
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

	messageDataJSON, err := json.Marshal(record.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message_data: %w", err)
	}

	// Convert MessageCCVAddresses to hex strings
	messageCCVAddressesHex := make([]string, 0, len(record.MessageCCVAddresses))
	for _, addr := range record.MessageCCVAddresses {
		messageCCVAddressesHex = append(messageCCVAddressesHex, addr.String())
	}

	// Convert MessageExecutorAddress to hex string
	messageExecutorAddressHex := record.MessageExecutorAddress.String()

	params := map[string]any{
		"message_id":                   messageIDHex,
		"signer_address":               signerAddressHex,
		"signature_r":                  record.IdentifierSigner.SignatureR[:],
		"signature_s":                  record.IdentifierSigner.SignatureS[:],
		"aggregation_key":              aggregationKey,
		"ccv_version":                  record.CCVVersion,
		"signature":                    record.Signature,
		"message_ccv_addresses":        pq.Array(messageCCVAddressesHex),
		"message_executor_address":     messageExecutorAddressHex,
		"message_data":                 messageDataJSON,
		"source_chain_block_timestamp": record.SourceChainBlockTimestamp,
	}

	return params, nil
}

const allVerificationRecordColumns = `message_id, signer_address, 
	signature_r, signature_s, aggregation_key,
	ccv_version, signature, message_ccv_addresses, message_executor_address, message_data, id, source_chain_block_timestamp, created_at`

const allVerificationRecordColumnsQualified = `cvr.message_id, cvr.signer_address, 
	cvr.signature_r, cvr.signature_s, cvr.aggregation_key,
	cvr.ccv_version, cvr.signature, cvr.message_ccv_addresses, cvr.message_executor_address, cvr.message_data, cvr.id, cvr.source_chain_block_timestamp, cvr.created_at`

func mustParseUint64(s string) uint64 {
	var result uint64
	_, _ = fmt.Sscanf(s, "%d", &result)
	return result
}
