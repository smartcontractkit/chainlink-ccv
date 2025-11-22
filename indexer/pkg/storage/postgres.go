package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
func (d *PostgresStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]protocol.CCVData, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	query := `
		SELECT 
			message_id,
			verifier_source_address,
			verifier_dest_address,
			timestamp,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address,
			source_chain_selector,
			dest_chain_selector
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

	var results []protocol.CCVData
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
) (map[string][]protocol.CCVData, error) {
	startQueryMetric := time.Now()
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Build dynamic query with filters
	query := `
		SELECT 
			message_id,
			verifier_source_address,
			verifier_dest_address,
			timestamp,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address,
			source_chain_selector,
			dest_chain_selector
		FROM indexer.verifier_results
		WHERE timestamp >= $1 AND timestamp <= $2
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
	query += fmt.Sprintf(" ORDER BY timestamp ASC LIMIT $%d OFFSET $%d", argCounter, argCounter+1)
	args = append(args, limit, offset)

	rows, err := d.queryContext(ctx, query, args...)
	if err != nil {
		d.lggr.Errorw("Failed to query CCV data", "error", err)
		d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
		return nil, fmt.Errorf("failed to query CCV data: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			d.lggr.Errorw("Failed to close rows", "error", cerr)
		}
	}()

	// Group results by messageID
	results := make(map[string][]protocol.CCVData)
	for rows.Next() {
		ccvData, err := d.scanCCVData(rows)
		if err != nil {
			d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
			return nil, fmt.Errorf("failed to scan CCV data: %w", err)
		}
		messageID := ccvData.MessageID.String()
		results[messageID] = append(results[messageID], ccvData)
	}

	if err := rows.Err(); err != nil {
		d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}

	d.monitoring.Metrics().RecordStorageQueryDuration(ctx, time.Since(startQueryMetric))
	return results, nil
}

// InsertCCVData inserts a new CCVData entry into the database.
func (d *PostgresStorage) InsertCCVData(ctx context.Context, ccvData protocol.CCVData) error {
	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Serialize message to JSON
	messageJSON, err := json.Marshal(ccvData.Message)
	if err != nil {
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx)
		return fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	// Convert CCV addresses to hex string array
	ccvAddressesHex := make([]string, len(ccvData.MessageCCVAddresses))
	for i, addr := range ccvData.MessageCCVAddresses {
		ccvAddressesHex[i] = addr.String()
	}

	query := `
		INSERT INTO indexer.verifier_results (
			message_id,
			verifier_source_address,
			verifier_dest_address,
			timestamp,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address,
			source_chain_selector,
			dest_chain_selector
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (message_id, verifier_source_address, verifier_dest_address) DO NOTHING
	`

	result, err := d.execContext(ctx, query,
		ccvData.MessageID.String(),
		ccvData.VerifierSourceAddress.String(),
		ccvData.VerifierDestAddress.String(),
		ccvData.Timestamp,
		ccvData.CCVData,
		messageJSON,
		pq.Array(ccvAddressesHex),
		ccvData.MessageExecutorAddress.String(),
		uint64(ccvData.Message.SourceChainSelector),
		uint64(ccvData.Message.DestChainSelector),
	)
	if err != nil {
		d.lggr.Errorw("Failed to insert CCV data", "error", err, "messageID", ccvData.MessageID.String())
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx)
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
	if err := d.trackUniqueMessage(ctx, ccvData.MessageID); err != nil {
		d.lggr.Warnw("Failed to track unique message", "error", err, "messageID", ccvData.MessageID.String())
		// Don't fail the insert if we can't track the unique message
	}

	// Increment the verification records counter
	d.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)
	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))

	return nil
}

// BatchInsertCCVData inserts multiple CCVData entries into the database efficiently using a batch insert.
func (d *PostgresStorage) BatchInsertCCVData(ctx context.Context, ccvDataList []protocol.CCVData) error {
	if len(ccvDataList) == 0 {
		return nil
	}

	startInsertMetric := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Build batch insert query with multiple value sets
	query := `
		INSERT INTO indexer.verifier_results (
			message_id,
			verifier_source_address,
			verifier_dest_address,
			timestamp,
			ccv_data,
			message,
			message_ccv_addresses,
			message_executor_address,
			source_chain_selector,
			dest_chain_selector
		) VALUES
	`

	args := make([]any, 0, len(ccvDataList)*10)
	valueClauses := make([]string, 0, len(ccvDataList))

	for i, ccvData := range ccvDataList {
		// Serialize message to JSON
		messageJSON, err := json.Marshal(ccvData.Message)
		if err != nil {
			d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx)
			return fmt.Errorf("failed to marshal message to JSON at index %d: %w", i, err)
		}

		// Convert CCV addresses to hex string array
		ccvAddressesHex := make([]string, len(ccvData.MessageCCVAddresses))
		for j, addr := range ccvData.MessageCCVAddresses {
			ccvAddressesHex[j] = addr.String()
		}

		// Calculate parameter positions for this row
		baseIdx := i * 10
		valueClause := fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			baseIdx+1, baseIdx+2, baseIdx+3, baseIdx+4, baseIdx+5, baseIdx+6, baseIdx+7, baseIdx+8, baseIdx+9, baseIdx+10)
		valueClauses = append(valueClauses, valueClause)

		// Add arguments for this row
		args = append(args,
			ccvData.MessageID.String(),
			ccvData.VerifierSourceAddress.String(),
			ccvData.VerifierDestAddress.String(),
			ccvData.Timestamp,
			ccvData.CCVData,
			messageJSON,
			pq.Array(ccvAddressesHex),
			ccvData.MessageExecutorAddress.String(),
			uint64(ccvData.Message.SourceChainSelector),
			uint64(ccvData.Message.DestChainSelector),
		)
	}

	// Complete the query with all value clauses and conflict resolution
	for i, vc := range valueClauses {
		if i > 0 {
			query += ", "
		}
		query += vc
	}
	query += " ON CONFLICT (message_id, verifier_source_address, verifier_dest_address) DO NOTHING"

	// Execute the batch insert
	result, err := d.execContext(ctx, query, args...)
	if err != nil {
		d.lggr.Errorw("Failed to batch insert CCV data", "error", err, "count", len(ccvDataList))
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx)
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
		uniqueMessages[ccvData.MessageID.String()] = true
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
	for i := int64(0); i < rowsAffected; i++ {
		d.monitoring.Metrics().IncrementVerificationRecordsCounter(ctx)
	}

	d.monitoring.Metrics().RecordStorageWriteDuration(ctx, time.Since(startInsertMetric))
	return nil
}

// trackUniqueMessage checks if this is the first time we're seeing this message ID
// and increments the unique messages counter if so.
func (d *PostgresStorage) trackUniqueMessage(ctx context.Context, messageID protocol.Bytes32) error {
	query := `
		SELECT COUNT(DISTINCT message_id) = 1 as is_first
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
) (protocol.CCVData, error) {
	var (
		messageIDStr           string
		verifierSourceAddrStr  string
		verifierDestAddrStr    string
		timestamp              time.Time
		ccvDataBytes           []byte
		messageJSON            []byte
		ccvAddressesHex        pq.StringArray
		messageExecutorAddrStr string
		sourceChainSelector    uint64
		destChainSelector      uint64
	)

	err := row.Scan(
		&messageIDStr,
		&verifierSourceAddrStr,
		&verifierDestAddrStr,
		&timestamp,
		&ccvDataBytes,
		&messageJSON,
		&ccvAddressesHex,
		&messageExecutorAddrStr,
		&sourceChainSelector,
		&destChainSelector,
	)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to scan row: %w", err)
	}

	// Parse messageID from hex string to Bytes32
	messageID, err := protocol.NewBytes32FromString(messageIDStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse message ID: %w", err)
	}

	// Parse verifier source address from hex string
	verifierSourceAddress, err := protocol.NewUnknownAddressFromHex(verifierSourceAddrStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse verifier source address: %w", err)
	}

	// Parse verifier dest address from hex string
	verifierDestAddress, err := protocol.NewUnknownAddressFromHex(verifierDestAddrStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse verifier dest address: %w", err)
	}

	// Deserialize message from JSON
	var message protocol.Message
	if err := json.Unmarshal(messageJSON, &message); err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Parse CCV addresses from hex strings
	messageCCVAddresses := make([]protocol.UnknownAddress, len(ccvAddressesHex))
	for i, hexStr := range ccvAddressesHex {
		addr, err := protocol.NewUnknownAddressFromHex(hexStr)
		if err != nil {
			return protocol.CCVData{}, fmt.Errorf("failed to parse CCV address at index %d: %w", i, err)
		}
		messageCCVAddresses[i] = addr
	}

	// Parse executor address from hex string
	messageExecutorAddress, err := protocol.NewUnknownAddressFromHex(messageExecutorAddrStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse executor address: %w", err)
	}

	return protocol.CCVData{
		MessageID:              messageID,
		Message:                message,
		MessageCCVAddresses:    messageCCVAddresses,
		MessageExecutorAddress: messageExecutorAddress,
		CCVData:                ccvDataBytes,
		Timestamp:              timestamp,
		VerifierSourceAddress:  verifierSourceAddress,
		VerifierDestAddress:    verifierDestAddress,
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
