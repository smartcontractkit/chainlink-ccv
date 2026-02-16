package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

var _ common.IndexerStorage = (*PostgresStorage)(nil)

const (
	opInsertCCVData                 = "InsertCCVData"
	opBatchInsertCCVData            = "BatchInsertCCVData"
	opBatchInsertMessages           = "BatchInsertMessages"
	opInsertMessage                 = "InsertMessage"
	opQueryMessages                 = "QueryMessages"
	opUpdateMessageStatus           = "UpdateMessageStatus"
	opCreateDiscoveryState          = "CreateDiscoveryState"
	opUpdateDiscoverySequenceNumber = "UpdateDiscoverySequenceNumber"
)

type PostgresStorage struct {
	ds         sqlutil.DataSource
	lggr       logger.Logger
	monitoring common.IndexerMonitoring
	mu         sync.RWMutex
}

func NewPostgresStorage(ctx context.Context, lggr logger.Logger, monitoring common.IndexerMonitoring, uri, driverName string, config pg.DBConfig) (*PostgresStorage, error) {
	ds, err := config.New(ctx, uri, driverName)
	if err != nil {
		lggr.Errorw("Failed to create database", "error", err)
		return nil, err
	}

	return &PostgresStorage{
		ds:         ds,
		lggr:       lggr,
		monitoring: monitoring,
	}, nil
}

// GetCCVData performs a lookup by messageID in the database.
func (d *PostgresStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
	startQueryMetric := time.Now()
	var err error
	d.mu.RLock()
	defer d.mu.RUnlock()
	defer func() {
		d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric), opGetCCVData, err != nil)
	}()

	query := `
		SELECT 
			message_id,
			verifier_source_address,
			verifier_dest_address,
			attestation_timestamp,
	        ingestion_timestamp,
			source_chain_selector,
			dest_chain_selector,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address
		FROM indexer.verifier_results
		WHERE message_id = $1
	`

	rows, err := d.queryContext(ctx, query, messageID.String())
	if err != nil {
		d.lggr.Errorw("Failed to query CCV data", "error", err, "messageID", messageID.String())
		return nil, fmt.Errorf("failed to query CCV data: %w", err)
	}

	defer func() {
		if cerr := rows.Close(); cerr != nil {
			d.lggr.Warnw("Failed to close rows", "error", cerr)
		}
	}()

	var results []common.VerifierResultWithMetadata
	for rows.Next() {
		ccvData, err := d.scanCCVData(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CCV data: %w", err)
		}
		results = append(results, ccvData)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}

	if len(results) == 0 {
		return nil, ErrCCVDataNotFound
	}
	return results, nil
}

// QueryCCVData retrieves all CCVData that matches the filter set with pagination.
func (d *PostgresStorage) QueryCCVData(
	ctx context.Context,
	start, end int64,
	sourceChainSelectors, destChainSelectors []protocol.ChainSelector,
	limit, offset uint64,
) (map[string][]common.VerifierResultWithMetadata, error) {
	startQueryMetric := time.Now()
	var err error
	d.mu.RLock()
	defer d.mu.RUnlock()
	defer func() {
		d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric), opQueryCCVData, err != nil)
	}()

	// Build dynamic query with filters
	query := `
		SELECT 
			message_id,
			verifier_source_address,
			verifier_dest_address,
			attestation_timestamp,
	        ingestion_timestamp,
			source_chain_selector,
			dest_chain_selector,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address
		FROM indexer.verifier_results
		WHERE ingestion_timestamp >= $1 AND ingestion_timestamp <= $2
	`

	args := []any{time.UnixMilli(start), time.UnixMilli(end)}
	argCounter := 3

	// Add source chain selector filter if provided
	if len(sourceChainSelectors) > 0 {
		query += fmt.Sprintf(" AND source_chain_selector = ANY($%d)", argCounter)
		args = append(args, convertChainSelectorsToUint64Array(sourceChainSelectors))
		argCounter++
	}

	// Add dest chain selector filter if provided
	if len(destChainSelectors) > 0 {
		query += fmt.Sprintf(" AND dest_chain_selector = ANY($%d)", argCounter)
		args = append(args, convertChainSelectorsToUint64Array(destChainSelectors))
		argCounter++
	}

	// Add ordering and pagination
	query += fmt.Sprintf(" ORDER BY ingestion_timestamp ASC LIMIT $%d OFFSET $%d", argCounter, argCounter+1)
	args = append(args, limit, offset)

	rows, err := d.queryContext(ctx, query, args...)
	if err != nil {
		d.lggr.Errorw("Failed to query CCV data", "error", err)
		return nil, fmt.Errorf("failed to query CCV data: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			d.lggr.Errorw("Failed to close rows", "error", cerr)
		}
	}()

	// Group results by messageID
	results := make(map[string][]common.VerifierResultWithMetadata)
	for rows.Next() {
		ccvData, err := d.scanCCVData(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CCV data: %w", err)
		}
		messageID := ccvData.VerifierResult.MessageID.String()
		results[messageID] = append(results[messageID], ccvData)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}
	return results, nil
}

// InsertCCVData inserts a new CCVData entry into the database.
func (d *PostgresStorage) InsertCCVData(ctx context.Context, ccvData common.VerifierResultWithMetadata) error {
	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Serialize message to JSON
	messageJSON, err := json.Marshal(ccvData.VerifierResult.Message)
	if err != nil {
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opInsertCCVData)
		return fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	// Convert CCV addresses to hex string array
	ccvAddressesHex := make([]string, len(ccvData.VerifierResult.MessageCCVAddresses))
	for i, addr := range ccvData.VerifierResult.MessageCCVAddresses {
		ccvAddressesHex[i] = addr.String()
	}

	query := `
		INSERT INTO indexer.verifier_results (
			message_id,
			verifier_source_address,
			verifier_dest_address,
			attestation_timestamp,
	        ingestion_timestamp,
			source_chain_selector,
			dest_chain_selector,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (message_id, verifier_source_address, verifier_dest_address) DO NOTHING
	`

	result, err := d.execContext(ctx, query,
		ccvData.VerifierResult.MessageID.String(),
		ccvData.VerifierResult.VerifierSourceAddress.String(),
		ccvData.VerifierResult.VerifierDestAddress.String(),
		ccvData.Metadata.AttestationTimestamp,
		ccvData.Metadata.IngestionTimestamp,
		uint64(ccvData.VerifierResult.Message.SourceChainSelector),
		uint64(ccvData.VerifierResult.Message.DestChainSelector),
		ccvData.VerifierResult.CCVData,
		messageJSON,
		pq.Array(ccvAddressesHex),
		ccvData.VerifierResult.MessageExecutorAddress.String(),
	)
	if err != nil {
		d.lggr.Errorw("Failed to insert CCV data", "error", err, "messageID", ccvData.VerifierResult.MessageID.String())
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opBatchInsertCCVData)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to insert CCV data: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Errorw("Failed to get rows affected", "error", err)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were affected, it means the data already exists (ON CONFLICT DO NOTHING)
	if rowsAffected == 0 {
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return ErrDuplicateCCVData
	}

	// Check if this is a new unique message
	if err := d.trackUniqueMessage(ctx, ccvData.VerifierResult.MessageID); err != nil {
		d.lggr.Warnw("Failed to track unique message", "error", err, "messageID", ccvData.VerifierResult.MessageID.String())
		// Don't fail the insert if we can't track the unique message
	}

	// Increment the verification records counter
	d.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)
	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))

	return nil
}

// BatchInsertCCVData inserts multiple CCVData entries into the database efficiently using a batch insert.
func (d *PostgresStorage) BatchInsertCCVData(ctx context.Context, ccvDataList []common.VerifierResultWithMetadata) error {
	if len(ccvDataList) == 0 {
		return nil
	}

	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Build batch insert query with multiple value sets
	var query strings.Builder
	query.WriteString(`
		INSERT INTO indexer.verifier_results (
			message_id,
			verifier_source_address,
			verifier_dest_address,
			attestation_timestamp,
            ingestion_timestamp,
			source_chain_selector,
			dest_chain_selector,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address
		) VALUES
	`)

	args := make([]any, 0, len(ccvDataList)*11)
	valueClauses := make([]string, 0, len(ccvDataList))

	for i, ccvData := range ccvDataList {
		// Serialize message to JSON
		messageJSON, err := json.Marshal(ccvData.VerifierResult.Message)
		if err != nil {
			d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opBatchInsertCCVData)
			return fmt.Errorf("failed to marshal message to JSON at index %d: %w", i, err)
		}

		// Convert CCV addresses to hex string array
		ccvAddressesHex := make([]string, len(ccvData.VerifierResult.MessageCCVAddresses))
		for j, addr := range ccvData.VerifierResult.MessageCCVAddresses {
			ccvAddressesHex[j] = addr.String()
		}

		// Calculate parameter positions for this row
		baseIdx := i * 11
		valueClause := fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			baseIdx+1, baseIdx+2, baseIdx+3, baseIdx+4, baseIdx+5, baseIdx+6,
			baseIdx+7, baseIdx+8, baseIdx+9, baseIdx+10, baseIdx+11)
		valueClauses = append(valueClauses, valueClause)

		// Add arguments for this row
		args = append(args,
			ccvData.VerifierResult.MessageID.String(),
			ccvData.VerifierResult.VerifierSourceAddress.String(),
			ccvData.VerifierResult.VerifierDestAddress.String(),
			ccvData.Metadata.AttestationTimestamp,
			ccvData.Metadata.IngestionTimestamp,
			uint64(ccvData.VerifierResult.Message.SourceChainSelector),
			uint64(ccvData.VerifierResult.Message.DestChainSelector),
			ccvData.VerifierResult.CCVData,
			messageJSON,
			pq.Array(ccvAddressesHex),
			ccvData.VerifierResult.MessageExecutorAddress.String(),
		)
	}

	// Complete the query with all value clauses and conflict resolution
	for i, vc := range valueClauses {
		if i > 0 {
			query.WriteString(", ")
		}
		query.WriteString(vc)
	}
	query.WriteString(" ON CONFLICT (message_id, verifier_source_address, verifier_dest_address) DO NOTHING")

	// Execute the batch insert
	result, err := d.execContext(ctx, query.String(), args...)
	if err != nil {
		d.lggr.Errorw("Failed to batch insert CCV data", "error", err, "count", len(ccvDataList))
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opBatchInsertCCVData)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to batch insert CCV data: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Errorw("Failed to get rows affected", "error", err)
	} else {
		d.lggr.Debugw("Batch insert completed", "requested", len(ccvDataList), "inserted", rowsAffected)
	}

	// Track unique messages and update metrics
	uniqueMessages := make(map[string]bool)
	for _, ccvData := range ccvDataList {
		uniqueMessages[ccvData.VerifierResult.MessageID.String()] = true
	}

	// Check which message IDs are new
	for messageID := range uniqueMessages {
		msgBytes32, err := protocol.NewBytes32FromString(messageID)
		if err != nil {
			continue
		}
		if err := d.trackUniqueMessage(ctx, msgBytes32); err != nil {
			d.lggr.Warnw("Failed to track unique message", "error", err, "messageID", messageID)
		}
	}

	// Increment the verification records counter by the number of rows actually inserted
	for range rowsAffected {
		d.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// BatchInsertMessages implements common.IndexerStorage.
func (d *PostgresStorage) BatchInsertMessages(ctx context.Context, messages []common.MessageWithMetadata) error {
	if len(messages) == 0 {
		return nil
	}

	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Build batch insert query with multiple value sets
	var query strings.Builder
	query.WriteString(`
		INSERT INTO indexer.messages (
			message_id,
			message,
			status,
			lastErr,
			source_chain_selector,
			dest_chain_selector,
			ingestion_timestamp
		) VALUES
	`)

	args := make([]any, 0, len(messages)*7)
	valueClauses := make([]string, 0, len(messages))

	for i, msg := range messages {
		// Serialize message to JSON
		messageJSON, err := json.Marshal(msg.Message)
		if err != nil {
			d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opBatchInsertMessages)
			return fmt.Errorf("failed to marshal message to JSON at index %d: %w", i, err)
		}

		// Calculate parameter positions for this row
		baseIdx := i * 7
		valueClause := fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			baseIdx+1, baseIdx+2, baseIdx+3, baseIdx+4, baseIdx+5, baseIdx+6, baseIdx+7)
		valueClauses = append(valueClauses, valueClause)

		// Add arguments for this row
		args = append(args,
			msg.Message.MustMessageID().String(),
			messageJSON,
			msg.Metadata.Status.String(),
			msg.Metadata.LastErr,
			msg.Message.SourceChainSelector,
			msg.Message.DestChainSelector,
			msg.Metadata.IngestionTimestamp,
		)
	}

	// Complete the query with all value clauses and conflict resolution
	for i, vc := range valueClauses {
		if i > 0 {
			query.WriteString(", ")
		}
		query.WriteString(vc)
	}
	query.WriteString(" ON CONFLICT (message_id) DO NOTHING")

	// Execute the batch insert
	result, err := d.execContext(ctx, query.String(), args...)
	if err != nil {
		d.lggr.Errorw("Failed to batch insert messages", "error", err, "count", len(messages))
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opBatchInsertMessages)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to batch insert messages: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Warnw("Failed to get rows affected", "error", err)
	} else {
		d.lggr.Debugw("Batch insert messages completed", "requested", len(messages), "inserted", rowsAffected)
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// InsertMessage implements common.IndexerStorage.
func (d *PostgresStorage) InsertMessage(ctx context.Context, message common.MessageWithMetadata) error {
	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Serialize message to JSON
	messageJSON, err := json.Marshal(message.Message)
	if err != nil {
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opInsertMessage)
		return fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	query := `
		INSERT INTO indexer.messages (
			message_id,
			message,
			status,
			lastErr,
			source_chain_selector,
			dest_chain_selector,
			ingestion_timestamp
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (message_id) DO NOTHING
	`

	result, err := d.execContext(ctx, query,
		message.Message.MustMessageID().String(),
		messageJSON,
		message.Metadata.Status.String(),
		message.Metadata.LastErr,
		message.Message.SourceChainSelector,
		message.Message.DestChainSelector,
		message.Metadata.IngestionTimestamp,
	)
	if err != nil {
		d.lggr.Errorw("Failed to insert message", "error", err, "messageID", message.Message.MustMessageID().String())
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opInsertMessage)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to insert message: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Warnw("Failed to get rows affected", "error", err)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were affected, it means the data already exists (ON CONFLICT DO NOTHING)
	// This is idempotent behavior, so we don't return an error
	if rowsAffected == 0 {
		d.lggr.Debugw("Message already exists, skipping insert", "messageID", message.Message.MustMessageID().String())
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// GetMessage performs a lookup by messageID in the database.
func (d *PostgresStorage) GetMessage(ctx context.Context, messageID protocol.Bytes32) (common.MessageWithMetadata, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `
		SELECT 
			message_id,
			message,
			status,
			lastErr,
			source_chain_selector,
			dest_chain_selector,
			ingestion_timestamp
		FROM indexer.messages
		WHERE message_id = $1
	`

	row := d.queryRowContext(ctx, query, messageID.String())
	message, err := d.scanMessage(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return common.MessageWithMetadata{}, ErrMessageNotFound
		}
		d.lggr.Errorw("Failed to query message", "error", err, "messageID", messageID.String())
		return common.MessageWithMetadata{}, fmt.Errorf("failed to query message: %w", err)
	}

	return message, nil
}

// QueryMessages retrieves all messages that match the filter set with pagination.
func (d *PostgresStorage) QueryMessages(
	ctx context.Context,
	start, end int64,
	sourceChainSelectors, destChainSelectors []protocol.ChainSelector,
	limit, offset uint64,
) ([]common.MessageWithMetadata, error) {
	startQueryMetric := time.Now()
	var err error
	d.mu.RLock()
	defer d.mu.RUnlock()
	defer func() {
		d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric), opQueryMessages, err != nil)
	}()

	query := `
		SELECT 
			message_id,
			message,
			status,
			lastErr,
			source_chain_selector,
			dest_chain_selector,
			ingestion_timestamp
		FROM indexer.messages
		WHERE ingestion_timestamp >= $1 AND ingestion_timestamp <= $2
	`

	args := []any{time.UnixMilli(start), time.UnixMilli(end)}
	argCounter := 3

	if len(sourceChainSelectors) > 0 {
		query += fmt.Sprintf(" AND source_chain_selector = ANY($%d)", argCounter)
		args = append(args, convertChainSelectorsToUint64Array(sourceChainSelectors))
		argCounter++
	}

	if len(destChainSelectors) > 0 {
		query += fmt.Sprintf(" AND dest_chain_selector = ANY($%d)", argCounter)
		args = append(args, convertChainSelectorsToUint64Array(destChainSelectors))
		argCounter++
	}

	query += fmt.Sprintf(" ORDER BY ingestion_timestamp ASC LIMIT $%d OFFSET $%d", argCounter, argCounter+1)
	args = append(args, limit, offset)

	rows, err := d.queryContext(ctx, query, args...)
	if err != nil {
		d.lggr.Errorw("Failed to query messages", "error", err)
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			d.lggr.Errorw("Failed to close rows", "error", cerr)
		}
	}()

	var results []common.MessageWithMetadata
	for rows.Next() {
		message, err := d.scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		results = append(results, message)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}
	return results, nil
}

// UpdateMessageStatus implements common.IndexerStorage.
func (d *PostgresStorage) UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status common.MessageStatus, lastErr string) error {
	startUpdateMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `
		UPDATE indexer.messages
		SET status = $1, lastErr = $2
		WHERE message_id = $3
	`

	result, err := d.execContext(ctx, query, status.String(), lastErr, messageID.String())
	if err != nil {
		d.lggr.Errorw("Failed to update message status", "error", err, "messageID", messageID.String())
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opUpdateMessageStatus)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
		return fmt.Errorf("failed to update message status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Warnw("Failed to get rows affected", "error", err)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
		return fmt.Errorf("message not found: %s", messageID.String())
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
	return nil
}

func (d *PostgresStorage) CreateDiscoveryState(ctx context.Context, discoveryLocation string, startingSequenceNumber int) error {
	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `
    INSERT INTO indexer.discovery_state (
      discovery_location,
      last_sequence_number
    ) VALUES ($1, $2)
    ON CONFLICT (discovery_location) DO NOTHING
	`

	result, err := d.execContext(ctx, query,
		discoveryLocation,
		startingSequenceNumber,
	)
	if err != nil {
		d.lggr.Errorw("Failed to create discovery state record", "error", err, "discoveryLocation", discoveryLocation, "sequenceNumber", startingSequenceNumber)
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opCreateDiscoveryState)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Warnw("Failed to get rows affected", "error", err)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.lggr.Warnw("Discovery Record already exisits for source", "discoveryLocation", discoveryLocation)
		return nil
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

func (d *PostgresStorage) UpdateDiscoverySequenceNumber(ctx context.Context, discoveryLocation string, sequenceNumber int) error {
	startUpdateMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `
    UPDATE indexer.discovery_state
    SET last_sequence_number = $1
    WHERE discovery_location = $2
	`

	result, err := d.execContext(ctx, query, sequenceNumber, discoveryLocation)
	if err != nil {
		d.lggr.Errorw("Failed to update discovery state record", "error", err, "discoveryLocation", discoveryLocation, "sequenceNumber", sequenceNumber)
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx, opUpdateDiscoverySequenceNumber)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
		return fmt.Errorf("failed to update discovery state record: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		d.lggr.Warnw("Failed to get rows affected", "error", err)
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
		return fmt.Errorf("discovery record not found: %s", discoveryLocation)
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startUpdateMetric))
	return nil
}

func (d *PostgresStorage) GetDiscoverySequenceNumber(ctx context.Context, discoveryLocation string) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT last_sequence_number FROM indexer.discovery_state WHERE discovery_location = $1`
	row := d.queryRowContext(ctx, query, discoveryLocation)

	var sequenceNumber int
	err := row.Scan(&sequenceNumber)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("failed to find discovery sequence number")
		}
		d.lggr.Errorw("Failed to query discovery sequence number", "error", err, "discoveryLocation", discoveryLocation)
		return 0, fmt.Errorf("failed to query discovery sequence number: %w", err)
	}

	return sequenceNumber, nil
}

// trackUniqueMessage checks if this is the first time we're seeing this message ID
// and increments the unique messages counter if so.
func (d *PostgresStorage) trackUniqueMessage(ctx context.Context, messageID protocol.Bytes32) error {
	// Check whether exactly one row exists for this message_id. If so,
	// this indicates the message was first-seen by the storage insert that preceded this call.
	query := `
		SELECT COUNT(*) = 1 as is_first
		FROM indexer.verifier_results
		WHERE message_id = $1
	`

	var isFirst bool
	err := d.queryRowContext(ctx, query, messageID.String()).Scan(&isFirst)
	if err != nil {
		return fmt.Errorf("failed to check unique message: %w", err)
	}

	if isFirst {
		d.monitoring.Metrics().IncrementUniqueMessagesCounter(ctx)
	}

	return nil
}

// scanCCVData scans a database row into a CCVData struct.
func (d *PostgresStorage) scanCCVData(row interface {
	Scan(dest ...any) error
},
) (common.VerifierResultWithMetadata, error) {
	var (
		messageIDStr             string
		sourceVerifierAddrStr    string
		destVerifierAddrStr      string
		attestationTimestamp     time.Time
		ingestionTimestamp       time.Time
		sourceChainSelector      uint64
		destChainSelector        uint64
		ccvDataBytes             []byte
		messageJSON              []byte
		messageCCVAddressesArray []string
		messageExecutorAddrStr   string
	)

	err := row.Scan(
		&messageIDStr,
		&sourceVerifierAddrStr,
		&destVerifierAddrStr,
		&attestationTimestamp,
		&ingestionTimestamp,
		&sourceChainSelector,
		&destChainSelector,
		&ccvDataBytes,
		&messageJSON,
		pq.Array(&messageCCVAddressesArray),
		&messageExecutorAddrStr,
	)
	if err != nil {
		return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to scan row: %w", err)
	}

	// Parse messageID from hex string to Bytes32
	messageID, err := protocol.NewBytes32FromString(messageIDStr)
	if err != nil {
		return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to parse message ID: %w", err)
	}

	// Parse verifier source address from hex string
	verifierSourceAddress, err := protocol.NewUnknownAddressFromHex(sourceVerifierAddrStr)
	if err != nil {
		return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to parse source verifier address: %w", err)
	}

	// Parse verifier dest address from hex string
	verifierDestAddress, err := protocol.NewUnknownAddressFromHex(destVerifierAddrStr)
	if err != nil {
		return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to parse dest verifier address: %w", err)
	}

	// Parse message executor address from hex string
	messageExecutorAddress, err := protocol.NewUnknownAddressFromHex(messageExecutorAddrStr)
	if err != nil {
		return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to parse message executor address: %w", err)
	}

	// Parse message CCV addresses from hex strings
	messageCCVAddresses := make([]protocol.UnknownAddress, len(messageCCVAddressesArray))
	for i, addrStr := range messageCCVAddressesArray {
		addr, err := protocol.NewUnknownAddressFromHex(addrStr)
		if err != nil {
			return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to parse message CCV address at index %d: %w", i, err)
		}
		messageCCVAddresses[i] = addr
	}

	// Deserialize message from JSON
	var message protocol.Message
	if err := json.Unmarshal(messageJSON, &message); err != nil {
		return common.VerifierResultWithMetadata{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{
			MessageID:              messageID,
			Message:                message,
			MessageCCVAddresses:    messageCCVAddresses,
			MessageExecutorAddress: messageExecutorAddress,
			CCVData:                ccvDataBytes,
			Timestamp:              attestationTimestamp,
			VerifierSourceAddress:  verifierSourceAddress,
			VerifierDestAddress:    verifierDestAddress,
		},
		Metadata: common.VerifierResultMetadata{
			AttestationTimestamp: attestationTimestamp,
			IngestionTimestamp:   ingestionTimestamp,
		},
	}, nil
}

// convertChainSelectorsToUint64Array converts a slice of ChainSelector to a slice of uint64
// for use with PostgreSQL DECIMAL arrays.
func convertChainSelectorsToUint64Array(selectors []protocol.ChainSelector) []uint64 {
	result := make([]uint64, len(selectors))
	for i, selector := range selectors {
		result[i] = uint64(selector)
	}
	return result
}

// Close closes the database connection.
func (d *PostgresStorage) Close() error {
	if closer, ok := d.ds.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// queryContext executes a query that returns rows.
func (d *PostgresStorage) queryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	// Try to use the DataSource directly if it supports QueryContext
	if querier, ok := d.ds.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}); ok {
		return querier.QueryContext(ctx, query, args...)
	}
	return nil, fmt.Errorf("DataSource does not support QueryContext")
}

// queryRowContext executes a query that returns a single row.
func (d *PostgresStorage) queryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	// Try to use the DataSource directly if it supports QueryRowContext
	if querier, ok := d.ds.(interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}); ok {
		return querier.QueryRowContext(ctx, query, args...)
	}
	// Return a row that will return an error when scanned
	return &sql.Row{}
}

// execContext executes a query without returning rows.
func (d *PostgresStorage) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	// Try to use the DataSource directly if it supports ExecContext
	if execer, ok := d.ds.(interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}); ok {
		return execer.ExecContext(ctx, query, args...)
	}
	return nil, fmt.Errorf("DataSource does not support ExecContext")
}

// scanMessage scans a database row into a MessageWithMetadata struct.
func (d *PostgresStorage) scanMessage(row interface {
	Scan(dest ...any) error
},
) (common.MessageWithMetadata, error) {
	var (
		messageIDStr        string
		messageJSON         []byte
		statusStr           string
		lastErr             string
		sourceChainSelector uint64
		destChainSelector   uint64
		ingestionTimestamp  time.Time
	)

	err := row.Scan(
		&messageIDStr,
		&messageJSON,
		&statusStr,
		&lastErr,
		&sourceChainSelector,
		&destChainSelector,
		&ingestionTimestamp,
	)
	if err != nil {
		return common.MessageWithMetadata{}, fmt.Errorf("failed to scan row: %w", err)
	}

	var message protocol.Message
	if err := json.Unmarshal(messageJSON, &message); err != nil {
		return common.MessageWithMetadata{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	status, err := common.NewMessageStatusFromString(statusStr)
	if err != nil {
		return common.MessageWithMetadata{}, fmt.Errorf("failed to parse status: %w", err)
	}

	return common.MessageWithMetadata{
		Message: message,
		Metadata: common.MessageMetadata{
			Status:             status,
			IngestionTimestamp: ingestionTimestamp,
			LastErr:            lastErr,
		},
	}, nil
}
