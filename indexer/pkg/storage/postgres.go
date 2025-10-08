package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

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

func NewPostgresStorage(ctx context.Context, lggr logger.Logger, monitoring common.IndexerMonitoring, uri string, config pg.DBConfig) (*PostgresStorage, error) {
	ds, err := config.New(ctx, uri, pg.DriverInMemoryPostgres)
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
			source_verifier_address,
			dest_verifier_address,
			timestamp,
			source_chain_selector,
			dest_chain_selector,
			nonce,
			ccv_data,
			blob_data,
			message,
			receipt_blobs
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
			source_verifier_address,
			dest_verifier_address,
			timestamp,
			source_chain_selector,
			dest_chain_selector,
			nonce,
			ccv_data,
			blob_data,
			message,
			receipt_blobs
		FROM indexer.verifier_results
		WHERE timestamp >= $1 AND timestamp <= $2
	`

	args := []any{start, end}
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

	// Serialize receipt blobs to JSON
	receiptBlobsJSON, err := json.Marshal(ccvData.ReceiptBlobs)
	if err != nil {
		d.monitoring.Metrics().RecordStorageInsertErrorsCounter(ctx)
		return fmt.Errorf("failed to marshal receipt blobs to JSON: %w", err)
	}

	query := `
		INSERT INTO indexer.verifier_results (
			message_id,
			source_verifier_address,
			dest_verifier_address,
			timestamp,
			source_chain_selector,
			dest_chain_selector,
			nonce,
			ccv_data,
			blob_data,
			message,
			receipt_blobs
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (message_id, source_verifier_address, dest_verifier_address) DO NOTHING
	`

	result, err := d.execContext(ctx, query,
		ccvData.MessageID.String(),
		ccvData.SourceVerifierAddress.String(),
		ccvData.DestVerifierAddress.String(),
		ccvData.Timestamp,
		ccvData.SourceChainSelector,
		ccvData.DestChainSelector,
		ccvData.Nonce,
		ccvData.CCVData,
		ccvData.BlobData,
		messageJSON,
		receiptBlobsJSON,
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
		messageIDStr          string
		sourceVerifierAddrStr string
		destVerifierAddrStr   string
		timestamp             int64
		sourceChainSelector   uint64
		destChainSelector     uint64
		nonce                 uint64
		ccvDataBytes          []byte
		blobDataBytes         []byte
		messageJSON           []byte
		receiptBlobsJSON      []byte
	)

	err := row.Scan(
		&messageIDStr,
		&sourceVerifierAddrStr,
		&destVerifierAddrStr,
		&timestamp,
		&sourceChainSelector,
		&destChainSelector,
		&nonce,
		&ccvDataBytes,
		&blobDataBytes,
		&messageJSON,
		&receiptBlobsJSON,
	)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to scan row: %w", err)
	}

	// Parse messageID from hex string to Bytes32
	messageID, err := protocol.NewBytes32FromString(messageIDStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse message ID: %w", err)
	}

	// Parse verifier addresses from hex strings
	sourceVerifierAddress, err := protocol.NewUnknownAddressFromHex(sourceVerifierAddrStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse source verifier address: %w", err)
	}

	destVerifierAddress, err := protocol.NewUnknownAddressFromHex(destVerifierAddrStr)
	if err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to parse dest verifier address: %w", err)
	}

	// Deserialize message from JSON
	var message protocol.Message
	if err := json.Unmarshal(messageJSON, &message); err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Deserialize receipt blobs from JSON
	var receiptBlobs []protocol.ReceiptWithBlob
	if err := json.Unmarshal(receiptBlobsJSON, &receiptBlobs); err != nil {
		return protocol.CCVData{}, fmt.Errorf("failed to unmarshal receipt blobs: %w", err)
	}

	return protocol.CCVData{
		MessageID:             messageID,
		SourceVerifierAddress: sourceVerifierAddress,
		DestVerifierAddress:   destVerifierAddress,
		Timestamp:             timestamp,
		SourceChainSelector:   protocol.ChainSelector(sourceChainSelector),
		DestChainSelector:     protocol.ChainSelector(destChainSelector),
		Nonce:                 protocol.Nonce(nonce),
		CCVData:               ccvDataBytes,
		BlobData:              blobDataBytes,
		Message:               message,
		ReceiptBlobs:          receiptBlobs,
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
