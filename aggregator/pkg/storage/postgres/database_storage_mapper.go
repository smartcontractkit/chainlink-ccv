package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type commitVerificationRecordRow struct {
	ID                     int64          `db:"id"`
	SeqNum                 int64          `db:"seq_num"`
	MessageID              string         `db:"message_id"`
	SignerIdentifier       string         `db:"signer_identifier"`
	AggregationKey         string         `db:"aggregation_key"`
	CCVVersion             []byte         `db:"ccv_version"`
	Signature              []byte         `db:"signature"`
	MessageCCVAddresses    pq.StringArray `db:"message_ccv_addresses"`
	MessageExecutorAddress string         `db:"message_executor_address"`
	MessageData            []byte         `db:"message_data"`
	CreatedAt              time.Time      `db:"created_at"`
}

func rowToCommitVerificationRecord(row *commitVerificationRecordRow) (*model.CommitVerificationRecord, error) {
	messageID, err := protocol.NewByteSliceFromHex(row.MessageID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message_id: %w", err)
	}

	signerIdentifierBytes, err := protocol.NewByteSliceFromHex(row.SignerIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer_identifier: %w", err)
	}

	signerIdentifier := &model.SignerIdentifier{
		Identifier: signerIdentifierBytes,
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
		MessageID:              messageID,
		Message:                &message,
		CCVVersion:             row.CCVVersion,
		Signature:              row.Signature,
		MessageCCVAddresses:    messageCCVAddresses,
		MessageExecutorAddress: messageExecutorAddress,
		SignerIdentifier:       signerIdentifier,
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
	if record.SignerIdentifier == nil {
		return nil, fmt.Errorf("record.SignerIdentifier cannot be nil")
	}

	messageIDHex := protocol.ByteSlice(record.MessageID).String()
	signerIdentifierHex := record.SignerIdentifier.Identifier.String()

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
		"message_id":               messageIDHex,
		"signer_identifier":        signerIdentifierHex,
		"aggregation_key":          aggregationKey,
		"ccv_version":              record.CCVVersion,
		"signature":                record.Signature,
		"message_ccv_addresses":    pq.Array(messageCCVAddressesHex),
		"message_executor_address": messageExecutorAddressHex,
		"message_data":             messageDataJSON,
	}

	return params, nil
}

const allVerificationRecordColumns = `message_id, signer_identifier, aggregation_key,
	ccv_version, signature, message_ccv_addresses, message_executor_address, message_data, id, created_at`

const allVerificationRecordColumnsQualified = `cvr.message_id, cvr.signer_identifier, cvr.aggregation_key,
	cvr.ccv_version, cvr.signature, cvr.message_ccv_addresses, cvr.message_executor_address, cvr.message_data, cvr.id, cvr.created_at`
