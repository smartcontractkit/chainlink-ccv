package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

// batchGetVerificationRecordIDs resolves signer identifiers to their latest verification record IDs
// for a given message and aggregation key. Used by SubmitAggregatedReport to look up the DB row IDs
// that will be referenced in the junction table. Filters by aggregation_key to prevent mixing
// records from different CCV versions into a single aggregated report.
func (d *DatabaseStorage) batchGetVerificationRecordIDs(ctx context.Context, messageIDHex string, signerIdentifiers []string, aggregationKey model.AggregationKey) (map[string]int64, error) {
	recordIDsMap := make(map[string]int64)
	if len(signerIdentifiers) == 0 {
		return recordIDsMap, nil
	}

	stmt := `SELECT DISTINCT ON (signer_identifier) signer_identifier, id
		FROM commit_verification_records 
		WHERE message_id = $1 AND signer_identifier = ANY($2) AND aggregation_key = $3
		ORDER BY signer_identifier, seq_num DESC`

	type idRecord struct {
		SignerIdentifier string `db:"signer_identifier"`
		ID               int64  `db:"id"`
	}

	var records []idRecord
	err := d.ds.SelectContext(ctx, &records, stmt, messageIDHex, pq.Array(signerIdentifiers), aggregationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get verification record IDs: %w", err)
	}

	for _, record := range records {
		recordIDsMap[record.SignerIdentifier] = record.ID
	}

	return recordIDsMap, nil
}

type DatabaseStorage struct {
	ds           sqlutil.DataSource
	pageSize     int
	queryTimeout time.Duration
	lggr         logger.SugaredLogger
}

func (d *DatabaseStorage) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, d.lggr)
}

var (
	_ pkgcommon.CommitVerificationStore           = (*DatabaseStorage)(nil)
	_ pkgcommon.CommitVerificationAggregatedStore = (*DatabaseStorage)(nil)
	_ protocol.HealthReporter                     = (*DatabaseStorage)(nil)
)

func NewDatabaseStorage(ds sqlutil.DataSource, pageSize int, queryTimeout time.Duration, lggr logger.SugaredLogger) *DatabaseStorage {
	return &DatabaseStorage{
		ds:           ds,
		pageSize:     pageSize,
		queryTimeout: queryTimeout,
		lggr:         lggr,
	}
}

func (d *DatabaseStorage) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if d.queryTimeout == 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, d.queryTimeout)
}

func (d *DatabaseStorage) Ready() error {
	ctx, cancel := d.withTimeout(context.Background())
	defer cancel()

	var count int
	err := d.ds.GetContext(ctx, &count, "SELECT 1")
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

func (d *DatabaseStorage) HealthReport() map[string]error {
	return map[string]error{
		"postgres_storage": d.Ready(),
	}
}

func (d *DatabaseStorage) Name() string {
	return "postgres_storage"
}

// SaveCommitVerification persists a verification record. The operation is append-only and idempotent:
// a duplicate (message_id, signer_identifier, aggregation_key) is silently ignored, but a new
// aggregation key for the same (message_id, signer_identifier) creates a separate row, supporting CCV version changes.
func (d *DatabaseStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if record == nil {
		return fmt.Errorf("commit verification record cannot be nil")
	}

	params, err := recordToInsertParams(record, aggregationKey)
	if err != nil {
		return fmt.Errorf("failed to prepare insert parameters: %w", err)
	}

	stmt := `INSERT INTO commit_verification_records 
		(message_id, signer_identifier, aggregation_key,
		 ccv_version, signature, message_ccv_addresses, message_executor_address, message_data) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (message_id, signer_identifier, aggregation_key) 
		DO NOTHING
		RETURNING id`

	var recordID int64
	err = d.ds.GetContext(ctx, &recordID, stmt,
		params["message_id"],
		params["signer_identifier"],
		params["aggregation_key"],
		params["ccv_version"],
		params["signature"],
		params["message_ccv_addresses"],
		params["message_executor_address"],
		params["message_data"],
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("failed to save commit verification record: %w", err)
	}

	return nil
}

// GetCommitVerification returns the latest verification record for a (message_id, signer_identifier)
// pair across all aggregation keys. Used by the ReadCommitVerification ops API.
func (d *DatabaseStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := fmt.Sprintf(`SELECT %s
		FROM commit_verification_records 
		WHERE message_id = $1 AND signer_identifier = $2
		ORDER BY seq_num DESC LIMIT 1`, allVerificationRecordColumns)

	messageIDHex := protocol.ByteSlice(id.MessageID).String()
	signerIdentifierHex := id.Address.String()

	var row commitVerificationRecordRow
	err := d.ds.GetContext(ctx, &row, stmt, messageIDHex, signerIdentifierHex)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("commit verification record not found")
		}
		return nil, fmt.Errorf("failed to get commit verification record: %w", err)
	}

	record, err := rowToCommitVerificationRecord(&row)
	if err != nil {
		return nil, fmt.Errorf("failed to convert row to record: %w", err)
	}

	return record, nil
}

// ListCommitVerificationByAggregationKey returns the latest verification record per signer for a
// given (message_id, aggregation_key). Used to collect the quorum inputs before creating an
// aggregated report.
func (d *DatabaseStorage) ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := fmt.Sprintf(`SELECT DISTINCT ON (signer_identifier) %s
		FROM commit_verification_records 
		WHERE message_id = $1 AND aggregation_key = $2
		ORDER BY signer_identifier, seq_num DESC`, allVerificationRecordColumns)

	messageIDHex := protocol.ByteSlice(messageID).String()

	var rows []commitVerificationRecordRow
	err := d.ds.SelectContext(ctx, &rows, stmt, messageIDHex, aggregationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query commit verification records: %w", err)
	}

	records := make([]*model.CommitVerificationRecord, 0, len(rows))
	for _, row := range rows {
		record, err := rowToCommitVerificationRecord(&row)
		if err != nil {
			return nil, fmt.Errorf("failed to convert row to record: %w", err)
		}
		records = append(records, record)
	}

	return records, nil
}

// QueryAggregatedReports paginates through all aggregated reports starting from a sequence number.
// No deduplication is applied: if multiple reports exist for the same (message_id, aggregation_key)
// they are all returned, ordered by seq_num ASC. Scan failures on individual rows are logged and
// skipped. Used by the GetMessagesSince discovery API.
func (d *DatabaseStorage) QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64) (*model.AggregatedReportBatch, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := fmt.Sprintf(`
		SELECT 
			car.message_id,
			car.aggregation_key,
			car.created_at,
			car.seq_num,
			%s
		FROM (
			SELECT id, message_id, aggregation_key, created_at, seq_num
			FROM commit_aggregated_reports
			WHERE seq_num >= $1
			ORDER BY seq_num ASC
			LIMIT $2
		) car
		LEFT JOIN commit_aggregated_report_verifications carv ON carv.aggregated_report_id = car.id
		LEFT JOIN commit_verification_records cvr ON cvr.id = carv.verification_record_id
		ORDER BY car.seq_num ASC, carv.ordinal
	`, allVerificationRecordColumnsQualified)

	rows, err := d.ds.QueryContext(ctx, stmt, sinceSequenceInclusive, d.pageSize+1)
	if err != nil {
		return nil, fmt.Errorf("failed to query aggregated reports: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	reportsMap := make(map[string]*model.CommitAggregatedReport)
	reportOrder := make([]string, 0)
	verificationRowsByReport := make(map[string][]*commitVerificationRecordRow)

	for rows.Next() {
		var messageIDReport string
		var reportAggregationKey string
		var createdAt time.Time
		var seqNum int64

		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
			&reportAggregationKey,
			&createdAt,
			&seqNum,
			&verRow.MessageID,
			&verRow.SignerIdentifier,
			&verRow.AggregationKey,
			&verRow.CCVVersion,
			&verRow.Signature,
			&verRow.MessageCCVAddresses,
			&verRow.MessageExecutorAddress,
			&verRow.MessageData,
			&verRow.ID,
			&verRow.CreatedAt,
		)
		if err != nil {
			d.logger(ctx).Errorw("scan failure on aggregated report row, skipping corrupted report", "error", err)
			continue
		}

		reportKey := fmt.Sprintf("%s-%d", messageIDReport, seqNum)

		_, exists := reportsMap[reportKey]
		if !exists {
			msgID, parseErr := protocol.NewByteSliceFromHex(messageIDReport)
			if parseErr != nil {
				d.logger(ctx).Errorw("failed to parse message_id hex in aggregated report, skipping", "error", parseErr, "message_id", messageIDReport)
				continue
			}
			reportsMap[reportKey] = &model.CommitAggregatedReport{
				MessageID:      msgID,
				AggregationKey: reportAggregationKey,
				Verifications:  []*model.CommitVerificationRecord{},
				Sequence:       seqNum,
				WrittenAt:      createdAt,
			}
			reportOrder = append(reportOrder, reportKey)
		}

		verificationRowsByReport[reportKey] = append(verificationRowsByReport[reportKey], &verRow)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	for reportKey, verRows := range verificationRowsByReport {
		report := reportsMap[reportKey]
		for _, verRow := range verRows {
			verification, err := rowToCommitVerificationRecord(verRow)
			if err != nil {
				return nil, fmt.Errorf("failed to convert row to record: %w", err)
			}
			report.Verifications = append(report.Verifications, verification)
		}
	}

	if len(reportOrder) == 0 {
		return &model.AggregatedReportBatch{}, nil
	}

	hasMore := len(reportOrder) > d.pageSize
	if hasMore {
		reportOrder = reportOrder[:d.pageSize]
	}

	reports := make([]*model.CommitAggregatedReport, 0, len(reportOrder))
	for _, key := range reportOrder {
		reports = append(reports, reportsMap[key])
	}

	return &model.AggregatedReportBatch{
		Reports: reports,
		HasMore: hasMore,
	}, nil
}

// GetCommitAggregatedReportByAggregationKey returns the latest aggregated report for a specific
// (message_id, aggregation_key) pair. Used by the aggregator to check whether a quorum-meeting
// report already exists before creating a new one. Returns ErrNotFound when no report exists.
func (d *DatabaseStorage) GetCommitAggregatedReportByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) (*model.CommitAggregatedReport, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	messageIDHex := protocol.ByteSlice(messageID).String()

	stmt := fmt.Sprintf(`
        SELECT 
            car.message_id,
            car.aggregation_key,
            car.created_at,
            car.seq_num,
            %s
        FROM (
            SELECT id, message_id, aggregation_key, created_at, seq_num
            FROM commit_aggregated_reports
            WHERE message_id = $1 AND aggregation_key = $2
            ORDER BY seq_num DESC
            LIMIT 1
        ) car
        LEFT JOIN commit_aggregated_report_verifications carv ON carv.aggregated_report_id = car.id
        LEFT JOIN commit_verification_records cvr ON cvr.id = carv.verification_record_id
        ORDER BY carv.ordinal
    `, allVerificationRecordColumnsQualified)

	rows, err := d.ds.QueryContext(ctx, stmt, messageIDHex, aggregationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query aggregated report: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var report *model.CommitAggregatedReport
	var verificationRows []*commitVerificationRecordRow

	for rows.Next() {
		var messageIDReport string
		var reportAggregationKey string
		var createdAt time.Time
		var seqNum int64
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
			&reportAggregationKey,
			&createdAt,
			&seqNum,
			&verRow.MessageID,
			&verRow.SignerIdentifier,
			&verRow.AggregationKey,
			&verRow.CCVVersion,
			&verRow.Signature,
			&verRow.MessageCCVAddresses,
			&verRow.MessageExecutorAddress,
			&verRow.MessageData,
			&verRow.ID,
			&verRow.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if report == nil {
			msgID, parseErr := protocol.NewByteSliceFromHex(messageIDReport)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse message_id hex: %w", parseErr)
			}
			report = &model.CommitAggregatedReport{
				MessageID:      msgID,
				AggregationKey: reportAggregationKey,
				Verifications:  []*model.CommitVerificationRecord{},
				Sequence:       seqNum,
				WrittenAt:      createdAt,
			}
		}

		verificationRows = append(verificationRows, &verRow)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	if report == nil {
		return nil, pkgcommon.ErrNotFound
	}

	for _, verRow := range verificationRows {
		verification, err := rowToCommitVerificationRecord(verRow)
		if err != nil {
			return nil, fmt.Errorf("failed to convert row to record: %w", err)
		}
		report.Verifications = append(report.Verifications, verification)
	}

	return report, nil
}

// GetBatchAggregatedReportByMessageIDs returns the latest aggregated report per message ID across
// all aggregation keys. The result map is keyed by hex-encoded message ID; missing IDs are omitted.
// Scan failures on individual rows are logged and the corrupted report is excluded.
// Used by the GetVerifierResultsForMessage batch lookup API.
func (d *DatabaseStorage) GetBatchAggregatedReportByMessageIDs(ctx context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if len(messageIDs) == 0 {
		return make(map[string]*model.CommitAggregatedReport), nil
	}

	messageIDHexValues := make([]string, len(messageIDs))
	for i, messageID := range messageIDs {
		messageIDHexValues[i] = protocol.ByteSlice(messageID).String()
	}

	placeholders := make([]string, len(messageIDHexValues))
	args := make([]any, len(messageIDHexValues))
	for i, messageIDHex := range messageIDHexValues {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = messageIDHex
	}

	stmt := fmt.Sprintf(`
		SELECT 
			car.message_id,
			car.aggregation_key,
			car.created_at,
			car.seq_num,
			%s
		FROM (
			SELECT DISTINCT ON (message_id) id, message_id, aggregation_key, created_at, seq_num
			FROM commit_aggregated_reports
			WHERE message_id IN (%s)
			ORDER BY message_id, seq_num DESC
		) car
		LEFT JOIN commit_aggregated_report_verifications carv ON carv.aggregated_report_id = car.id
		LEFT JOIN commit_verification_records cvr ON cvr.id = carv.verification_record_id
		ORDER BY car.message_id, carv.ordinal
	`, allVerificationRecordColumnsQualified, strings.Join(placeholders, ","))

	rows, err := d.ds.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query batch aggregated reports: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	reports := make(map[string]*model.CommitAggregatedReport)
	verificationRowsByMessage := make(map[string][]*commitVerificationRecordRow)

	for rows.Next() {
		var messageIDReport string
		var reportAggregationKey string
		var createdAt time.Time
		var seqNum int64
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
			&reportAggregationKey,
			&createdAt,
			&seqNum,
			&verRow.MessageID,
			&verRow.SignerIdentifier,
			&verRow.AggregationKey,
			&verRow.CCVVersion,
			&verRow.Signature,
			&verRow.MessageCCVAddresses,
			&verRow.MessageExecutorAddress,
			&verRow.MessageData,
			&verRow.ID,
			&verRow.CreatedAt,
		)
		if err != nil {
			d.logger(ctx).Errorw("scan failure on batch aggregated report row, excluding corrupted report", "error", err)
			continue
		}

		_, exists := reports[messageIDReport]
		if !exists {
			messageIDBytes, parseErr := protocol.NewByteSliceFromHex(messageIDReport)
			if parseErr != nil {
				d.logger(ctx).Errorw("failed to parse message_id hex in batch report, skipping", "error", parseErr, "message_id", messageIDReport)
				continue
			}
			reports[messageIDReport] = &model.CommitAggregatedReport{
				MessageID:      messageIDBytes,
				AggregationKey: reportAggregationKey,
				Verifications:  []*model.CommitVerificationRecord{},
				Sequence:       seqNum,
				WrittenAt:      createdAt,
			}
		}

		verificationRowsByMessage[messageIDReport] = append(verificationRowsByMessage[messageIDReport], &verRow)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	for messageID, verRows := range verificationRowsByMessage {
		report := reports[messageID]
		for _, verRow := range verRows {
			verification, err := rowToCommitVerificationRecord(verRow)
			if err != nil {
				return nil, fmt.Errorf("failed to convert row to record: %w", err)
			}
			report.Verifications = append(report.Verifications, verification)
		}
	}

	return reports, nil
}

// SubmitAggregatedReport persists an aggregated report and its verification links atomically.
// Idempotent: a UNIQUE(message_id, aggregation_key, verification_record_ids) constraint with
// ON CONFLICT DO NOTHING prevents duplicate reports. The CTE inserts the parent row and, only
// when it is new, populates the junction table in the same statement.
func (d *DatabaseStorage) SubmitAggregatedReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	if report == nil {
		return fmt.Errorf("aggregated report cannot be nil")
	}

	messageIDHex := protocol.ByteSlice(report.MessageID).String()

	signerIdentifiers := make([]string, 0, len(report.Verifications))
	for _, verification := range report.Verifications {
		signerIdentifierHex := verification.SignerIdentifier.Identifier.String()
		signerIdentifiers = append(signerIdentifiers, signerIdentifierHex)
	}

	recordIDsMap, err := d.batchGetVerificationRecordIDs(ctx, messageIDHex, signerIdentifiers, report.AggregationKey)
	if err != nil {
		return err
	}

	verificationRecordIDs := make([]int64, 0, len(report.Verifications))
	for _, verification := range report.Verifications {
		signerIdentifierHex := verification.SignerIdentifier.Identifier.String()
		recordID, exists := recordIDsMap[signerIdentifierHex]
		if !exists {
			return fmt.Errorf("failed to find verification record ID for signer %s", signerIdentifierHex)
		}
		verificationRecordIDs = append(verificationRecordIDs, recordID)
	}

	slices.Sort(verificationRecordIDs)

	stmt := `
	WITH new_report AS (
		INSERT INTO commit_aggregated_reports (message_id, aggregation_key, verification_record_ids)
		VALUES ($1, $2, $3)
		ON CONFLICT (message_id, aggregation_key, verification_record_ids) DO NOTHING
		RETURNING id
	)
	INSERT INTO commit_aggregated_report_verifications
		(aggregated_report_id, verification_record_id, ordinal)
	SELECT nr.id, v.record_id, v.ord
	FROM new_report nr,
		 UNNEST($3::bigint[]) WITH ORDINALITY AS v(record_id, ord)`

	_, err = d.ds.ExecContext(ctx, stmt,
		messageIDHex,
		report.AggregationKey,
		pq.Array(verificationRecordIDs),
	)
	if err != nil {
		return fmt.Errorf("failed to submit aggregated report: %w", err)
	}

	return nil
}

// ListOrphanedKeys streams (message_id, aggregation_key) pairs that have verification records but
// no matching aggregated report. Joins on both message_id AND aggregation_key so a CCV version
// change correctly surfaces the new key as orphaned even when a report exists for the old key.
// Used by the OrphanRecoverer to trigger re-aggregation.
func (d *DatabaseStorage) ListOrphanedKeys(ctx context.Context, newerThan time.Time, pageSize int) (<-chan model.OrphanedKey, <-chan error) {
	orphanedKeyCh := make(chan model.OrphanedKey)
	errCh := make(chan error, 1)

	sendErr := func(err error) {
		if err == nil {
			return
		}

		select {
		case errCh <- err:
		default:
		}
	}

	go func() {
		defer close(orphanedKeyCh)
		defer close(errCh)

		var cursorMessageID, cursorAggregationKey string
		firstPage := true

		for {
			select {
			case <-ctx.Done():
				sendErr(ctx.Err())
				return
			default:
			}

			pageRowsCount, lastMessageID, lastAggregationKey, err := d.fetchOrphanedKeysPage(ctx, newerThan, firstPage, cursorMessageID, cursorAggregationKey, orphanedKeyCh, pageSize)
			if err != nil {
				sendErr(err)
				return
			}

			if pageRowsCount < pageSize {
				return
			}

			cursorMessageID = lastMessageID
			cursorAggregationKey = lastAggregationKey
			firstPage = false
		}
	}()

	return orphanedKeyCh, errCh
}

func (d *DatabaseStorage) fetchOrphanedKeysPage(ctx context.Context, newerThan time.Time, firstPage bool, cursorMessageID, cursorAggregationKey string, orphanedKeyCh chan<- model.OrphanedKey, pageSize int) (pageCount int, lastMessageID, lastAggregationKey string, err error) {
	queryCtx, cancel := d.withTimeout(ctx)
	defer cancel()

	var rows *sql.Rows
	if firstPage {
		stmt := `
		SELECT DISTINCT cvr.message_id, cvr.aggregation_key
		FROM commit_verification_records cvr
		LEFT JOIN commit_aggregated_reports car
			ON car.message_id = cvr.message_id AND car.aggregation_key = cvr.aggregation_key
		WHERE cvr.created_at >= $1 AND car.message_id IS NULL
		ORDER BY cvr.message_id, cvr.aggregation_key
		LIMIT $2`
		rows, err = d.ds.QueryContext(queryCtx, stmt, newerThan, pageSize)
	} else {
		stmt := `
		SELECT DISTINCT cvr.message_id, cvr.aggregation_key
		FROM commit_verification_records cvr
		LEFT JOIN commit_aggregated_reports car
			ON car.message_id = cvr.message_id AND car.aggregation_key = cvr.aggregation_key
		WHERE cvr.created_at >= $1 AND car.message_id IS NULL
		  AND (cvr.message_id, cvr.aggregation_key) > ($3, $4)
		ORDER BY cvr.message_id, cvr.aggregation_key
		LIMIT $2`
		rows, err = d.ds.QueryContext(queryCtx, stmt, newerThan, pageSize, cursorMessageID, cursorAggregationKey)
	}
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to query orphaned message pairs: %w", err)
	}
	// Uses named return 'err' so rows.Close() failure is propagated when no prior error occurred.
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger(ctx).Errorw("failed to close rows", "error", closeErr)
			if err == nil {
				err = fmt.Errorf("failed to close rows: %w", closeErr)
			}
		}
	}()

	type dbResult struct {
		MessageID      string
		AggregationKey string
	}

	for rows.Next() {
		select {
		case <-ctx.Done():
			return 0, "", "", ctx.Err()
		default:
		}

		var result dbResult
		if err := rows.Scan(&result.MessageID, &result.AggregationKey); err != nil {
			return 0, "", "", fmt.Errorf("failed to scan orphaned pair: %w", err)
		}

		pageCount++
		lastMessageID = result.MessageID
		lastAggregationKey = result.AggregationKey

		messageID, parseErr := protocol.NewByteSliceFromHex(result.MessageID)
		if parseErr != nil {
			d.logger(ctx).Errorw("failed to parse message ID", "error", parseErr)
			continue
		}

		select {
		case orphanedKeyCh <- model.OrphanedKey{
			MessageID:      messageID,
			AggregationKey: result.AggregationKey,
		}:
		case <-ctx.Done():
			return 0, "", "", ctx.Err()
		}
	}

	if err := rows.Err(); err != nil {
		return 0, "", "", fmt.Errorf("error iterating over orphaned pairs: %w", err)
	}

	return pageCount, lastMessageID, lastAggregationKey, nil
}

// OrphanedKeyStats returns aggregate counts of orphaned (message_id, aggregation_key) pairs
// split by a cutoff time. Used for monitoring/health reporting of the orphan recovery process.
func (d *DatabaseStorage) OrphanedKeyStats(ctx context.Context, cutoff time.Time) (*model.OrphanStats, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `
	SELECT 
		COUNT(*) FILTER (WHERE created_at < $1) as expired_count,
		COUNT(*) FILTER (WHERE created_at >= $1) as non_expired_count,
		COUNT(*) as total_count
	FROM (
		SELECT DISTINCT ON (cvr.message_id, cvr.aggregation_key) cvr.message_id, cvr.aggregation_key, cvr.created_at
		FROM commit_verification_records cvr
		LEFT JOIN commit_aggregated_reports car
			ON car.message_id = cvr.message_id AND car.aggregation_key = cvr.aggregation_key
		WHERE car.message_id IS NULL
	) orphans`

	rows, err := d.ds.QueryContext(ctx, stmt, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query orphan stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var stats model.OrphanStats
	if rows.Next() {
		if err := rows.Scan(&stats.ExpiredCount, &stats.NonExpiredCount, &stats.TotalCount); err != nil {
			return nil, fmt.Errorf("failed to scan orphan stats: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading orphan stats: %w", err)
	}

	return &stats, nil
}
