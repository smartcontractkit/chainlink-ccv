package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

var _ CCVStorage = &PostgresCCVStorage{}

type PostgresCCVStorage struct {
	ds   sqlutil.DataSource
	lggr logger.Logger
}

func NewPostgres(ds sqlutil.DataSource, lggr logger.Logger) *PostgresCCVStorage {
	return &PostgresCCVStorage{
		ds:   ds,
		lggr: lggr,
	}
}

func (p *PostgresCCVStorage) Get(ctx context.Context, keys []protocol.Bytes32) (map[protocol.Bytes32]Entry, error) {
	result := make(map[protocol.Bytes32]Entry)

	if len(keys) == 0 {
		return result, nil
	}

	// Convert keys to byte slices for the query
	args := make([]any, len(keys))
	placeholders := make([]string, len(keys))
	for i, key := range keys {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = key[:]
	}

	stmt := fmt.Sprintf(`SELECT 
		message_id,
		message,
		ccv_version,
		ccv_addresses,
		executor_address,
		signature,
		verifier_source_address,
		verifier_dest_address,
		timestamp
		FROM verifier_node_results 
		WHERE message_id IN (%s)`,
		strings.Join(placeholders, ","))

	type row struct {
		MessageID             []byte          `db:"message_id"`
		Message               json.RawMessage `db:"message"`
		CCVVersion            []byte          `db:"ccv_version"`
		CCVAddresses          json.RawMessage `db:"ccv_addresses"`
		ExecutorAddress       []byte          `db:"executor_address"`
		Signature             []byte          `db:"signature"`
		VerifierSourceAddress []byte          `db:"verifier_source_address"`
		VerifierDestAddress   []byte          `db:"verifier_dest_address"`
		Timestamp             time.Time       `db:"timestamp"`
	}

	var rows []row
	err := p.ds.SelectContext(ctx, &rows, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query verifier node results: %w", err)
	}

	for _, r := range rows {
		var msgID protocol.Bytes32
		if len(r.MessageID) != 32 {
			return nil, fmt.Errorf("invalid message_id length: got %d, expected 32", len(r.MessageID))
		}
		copy(msgID[:], r.MessageID)

		var message protocol.Message
		if err := json.Unmarshal(r.Message, &message); err != nil {
			return nil, fmt.Errorf("failed to unmarshal message for messageID %s: %w", msgID.String(), err)
		}

		var ccvAddresses []protocol.UnknownAddress
		if err := json.Unmarshal(r.CCVAddresses, &ccvAddresses); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ccv_addresses for messageID %s: %w", msgID.String(), err)
		}

		entry := Entry{
			value: protocol.VerifierNodeResult{
				MessageID:       msgID,
				Message:         message,
				CCVVersion:      protocol.ByteSlice(r.CCVVersion),
				CCVAddresses:    ccvAddresses,
				ExecutorAddress: protocol.UnknownAddress(r.ExecutorAddress),
				Signature:       protocol.ByteSlice(r.Signature),
			},
			verifierSourceAddress: protocol.UnknownAddress(r.VerifierSourceAddress),
			verifierDestAddress:   protocol.UnknownAddress(r.VerifierDestAddress),
			timestamp:             r.Timestamp,
		}

		result[msgID] = entry
	}

	p.lggr.Debugw("Retrieved verifier node results", "requested", len(keys), "found", len(result))
	return result, nil
}

func (p *PostgresCCVStorage) Set(ctx context.Context, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	return sqlutil.TransactDataSource(ctx, p.ds, nil, func(tx sqlutil.DataSource) error {
		stmt := `INSERT INTO verifier_node_results (
			message_id,
			message,
			ccv_version,
			ccv_addresses,
			executor_address,
			signature,
			verifier_source_address,
			verifier_dest_address,
			timestamp
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (message_id) DO UPDATE SET
			message = EXCLUDED.message,
			ccv_version = EXCLUDED.ccv_version,
			ccv_addresses = EXCLUDED.ccv_addresses,
			executor_address = EXCLUDED.executor_address,
			signature = EXCLUDED.signature,
			verifier_source_address = EXCLUDED.verifier_source_address,
			verifier_dest_address = EXCLUDED.verifier_dest_address,
			timestamp = EXCLUDED.timestamp`

		for _, entry := range entries {
			msgID, err := entry.value.Message.MessageID()
			if err != nil {
				return fmt.Errorf("failed to compute message ID: %w", err)
			}

			messageJSON, err := json.Marshal(entry.value.Message)
			if err != nil {
				return fmt.Errorf("failed to marshal message: %w", err)
			}

			ccvAddressesJSON, err := json.Marshal(entry.value.CCVAddresses)
			if err != nil {
				return fmt.Errorf("failed to marshal ccv addresses: %w", err)
			}

			_, err = tx.ExecContext(ctx, stmt,
				msgID[:],
				messageJSON,
				[]byte(entry.value.CCVVersion),
				ccvAddressesJSON,
				[]byte(entry.value.ExecutorAddress),
				[]byte(entry.value.Signature),
				[]byte(entry.verifierSourceAddress),
				[]byte(entry.verifierDestAddress),
				entry.timestamp,
			)
			if err != nil {
				return fmt.Errorf("failed to insert verifier node result for message %s: %w", msgID.String(), err)
			}
		}

		p.lggr.Debugw("Inserted verifier node results", "count", len(entries))
		return nil
	})
}
