package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
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

func (d *DatabaseStorage) batchGetVerificationRecordIDs(ctx context.Context, messageIDHex string, signerIdentifiers []string) (map[string]int64, error) {
	recordIDsMap := make(map[string]int64)
	if len(signerIdentifiers) == 0 {
		return recordIDsMap, nil
	}

	stmt := `SELECT DISTINCT ON (signer_identifier) signer_identifier, id
		FROM commit_verification_records 
		WHERE message_id = $1 AND signer_identifier = ANY($2)
		ORDER BY signer_identifier, seq_num DESC`

	type idRecord struct {
		SignerIdentifier string `db:"signer_identifier"`
		ID               int64  `db:"id"`
	}

	var records []idRecord
	err := d.ds.SelectContext(ctx, &records, stmt, messageIDHex, pq.Array(signerIdentifiers))
	if err != nil {
		return nil, fmt.Errorf("failed to get verification record IDs: %w", err)
	}

	for _, record := range records {
		recordIDsMap[record.SignerIdentifier] = record.ID
	}

	return recordIDsMap, nil
}

type DatabaseStorage struct {
	ds       sqlutil.DataSource
	pageSize int
	lggr     logger.SugaredLogger
}

func (d *DatabaseStorage) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, d.lggr)
}

var (
	_ pkgcommon.CommitVerificationStore           = (*DatabaseStorage)(nil)
	_ pkgcommon.CommitVerificationAggregatedStore = (*DatabaseStorage)(nil)
	_ protocol.HealthReporter                     = (*DatabaseStorage)(nil)
)

func NewDatabaseStorage(ds sqlutil.DataSource, pageSize int, lggr logger.SugaredLogger) *DatabaseStorage {
	return &DatabaseStorage{
		ds:       ds,
		pageSize: pageSize,
		lggr:     lggr,
	}
}

func (d *DatabaseStorage) Ready() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

func (d *DatabaseStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error {
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

func (d *DatabaseStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	stmt := fmt.Sprintf(`SELECT %s
		FROM commit_verification_records 
		WHERE message_id = $1 AND signer_identifier = $2
		ORDER BY seq_num DESC LIMIT 1`, allVerificationRecordColumns)

	messageIDHex := protocol.HexEncode(id.MessageID)
	signerIdentifierHex := protocol.HexEncode(id.Address)

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

func (d *DatabaseStorage) ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
	stmt := fmt.Sprintf(`SELECT DISTINCT ON (signer_identifier) %s
		FROM commit_verification_records 
		WHERE message_id = $1 AND aggregation_key = $2
		ORDER BY signer_identifier, seq_num DESC`, allVerificationRecordColumns)

	messageIDHex := protocol.HexEncode(messageID)

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

func (d *DatabaseStorage) QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64) (*model.AggregatedReportBatch, error) {
	stmt := fmt.Sprintf(`
		SELECT 
			car.message_id,
			car.created_at,
			car.seq_num,
			%s
		FROM (
			SELECT message_id, created_at, seq_num, verification_record_ids
			FROM commit_aggregated_reports
			WHERE seq_num >= $1
			ORDER BY seq_num ASC
			LIMIT $2
		) car
		LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
		LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
		ORDER BY car.seq_num ASC, vid.ord
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
		var createdAt time.Time
		var seqNum int64

		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
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

		reportKey := fmt.Sprintf("%s-%d", messageIDReport, seqNum)

		_, exists := reportsMap[reportKey]
		if !exists {
			msgID, _ := protocol.HexDecode(messageIDReport)
			reportsMap[reportKey] = &model.CommitAggregatedReport{
				MessageID:     msgID,
				Verifications: []*model.CommitVerificationRecord{},
				Sequence:      seqNum,
				WrittenAt:     createdAt,
			}
			reportOrder = append(reportOrder, reportKey)
		}

		if verRow.ID > 0 {
			verificationRowsByReport[reportKey] = append(verificationRowsByReport[reportKey], &verRow)
		}
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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
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

func (d *DatabaseStorage) GetCommitAggregatedReportByMessageID(ctx context.Context, messageID model.MessageID) (*model.CommitAggregatedReport, error) {
	messageIDHex := protocol.HexEncode(messageID)

	stmt := fmt.Sprintf(`
        SELECT 
            car.message_id,
            car.created_at,
            car.seq_num,
            %s
        FROM commit_aggregated_reports car
        LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
        LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
        WHERE car.message_id = $1
        ORDER BY car.seq_num DESC, vid.ord

    `, allVerificationRecordColumnsQualified)

	rows, err := d.ds.QueryContext(ctx, stmt, messageIDHex)
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
		var createdAt time.Time
		var seqNum int64
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
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
			msgID, _ := protocol.HexDecode(messageIDReport)
			report = &model.CommitAggregatedReport{
				MessageID:     msgID,
				Verifications: []*model.CommitVerificationRecord{},
				Sequence:      seqNum,
				WrittenAt:     createdAt,
			}
		}

		if verRow.ID > 0 {
			verificationRows = append(verificationRows, &verRow)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	if report == nil {
		return nil, nil
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

func (d *DatabaseStorage) GetBatchAggregatedReportByMessageIDs(ctx context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error) {
	if len(messageIDs) == 0 {
		return make(map[string]*model.CommitAggregatedReport), nil
	}

	messageIDHexValues := make([]string, len(messageIDs))
	for i, messageID := range messageIDs {
		messageIDHexValues[i] = protocol.HexEncode(messageID)
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
			car.created_at,
			car.seq_num,
			%s
		FROM commit_aggregated_reports car
		LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
		LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
		WHERE car.message_id IN (%s)
		ORDER BY car.message_id, car.seq_num DESC, vid.ord
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
		var createdAt time.Time
		var seqNum int64
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
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

		_, exists := reports[messageIDReport]
		if !exists {
			messageIDBytes, _ := protocol.HexDecode(messageIDReport)
			reports[messageIDReport] = &model.CommitAggregatedReport{
				MessageID:     messageIDBytes,
				Verifications: []*model.CommitVerificationRecord{},
				Sequence:      seqNum,
				WrittenAt:     createdAt,
			}
		}

		if verRow.ID > 0 {
			verificationRowsByMessage[messageIDReport] = append(verificationRowsByMessage[messageIDReport], &verRow)
		}
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

func (d *DatabaseStorage) SubmitAggregatedReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	if report == nil {
		return fmt.Errorf("aggregated report cannot be nil")
	}

	verificationRecordIDs := make([]int64, 0, len(report.Verifications))
	messageIDHex := protocol.HexEncode(report.MessageID)

	signerIdentifiers := make([]string, 0, len(report.Verifications))
	for _, verification := range report.Verifications {
		signerIdentifierHex := protocol.HexEncode(verification.SignerIdentifier.Identifier)
		signerIdentifiers = append(signerIdentifiers, signerIdentifierHex)
	}

	recordIDsMap, err := d.batchGetVerificationRecordIDs(ctx, messageIDHex, signerIdentifiers)
	if err != nil {
		return err
	}

	for _, verification := range report.Verifications {
		signerIdentifierHex := protocol.HexEncode(verification.SignerIdentifier.Identifier)
		recordID, exists := recordIDsMap[signerIdentifierHex]
		if !exists {
			return fmt.Errorf("failed to find verification record ID for signer %s", signerIdentifierHex)
		}
		verificationRecordIDs = append(verificationRecordIDs, recordID)
	}

	sort.Slice(verificationRecordIDs, func(i, j int) bool {
		return verificationRecordIDs[i] < verificationRecordIDs[j]
	})

	stmt := `INSERT INTO commit_aggregated_reports 
		(message_id, verification_record_ids) 
		VALUES ($1, $2)
		ON CONFLICT (message_id, verification_record_ids) DO NOTHING`

	result, err := d.ds.ExecContext(ctx, stmt,
		messageIDHex,
		pq.Array(verificationRecordIDs),
	)
	if err != nil {
		return fmt.Errorf("failed to submit aggregated report: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		d.logger(ctx).Infow("Duplicate report detected, skipping write", "verifications", len(report.Verifications))
		return nil
	}

	return nil
}

func (d *DatabaseStorage) ListOrphanedKeys(ctx context.Context, newerThan time.Time) (<-chan model.OrphanedKey, <-chan error) {
	orphanedKeyCh := make(chan model.OrphanedKey)
	errCh := make(chan error, 1)

	go func() {
		defer close(orphanedKeyCh)
		defer close(errCh)

		stmt := `
		SELECT DISTINCT cvr.message_id, cvr.aggregation_key
		FROM commit_verification_records cvr
		LEFT JOIN commit_aggregated_reports car ON cvr.message_id = car.message_id
		WHERE cvr.created_at >= $1 AND car.message_id IS NULL
		ORDER BY cvr.message_id, cvr.aggregation_key`

		rows, err := d.ds.QueryContext(ctx, stmt, newerThan)
		if err != nil {
			errCh <- fmt.Errorf("failed to query orphaned message pairs: %w", err)
			return
		}
		defer func() {
			if closeErr := rows.Close(); closeErr != nil {
				errCh <- fmt.Errorf("failed to close rows: %w", closeErr)
			}
		}()

		for rows.Next() {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			type dbResult struct {
				MessageID      string `db:"message_id"`
				AggregationKey string `db:"aggregation_key"`
			}

			var result dbResult
			err := rows.Scan(&result.MessageID, &result.AggregationKey)
			if err != nil {
				errCh <- fmt.Errorf("failed to scan orphaned pair: %w", err)
				return
			}

			messageID, _ := protocol.HexDecode(result.MessageID)

			select {
			case orphanedKeyCh <- model.OrphanedKey{
				MessageID:      messageID,
				AggregationKey: result.AggregationKey,
			}:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}

		if err := rows.Err(); err != nil {
			errCh <- fmt.Errorf("error iterating over orphaned pairs: %w", err)
		}
	}()

	return orphanedKeyCh, errCh
}

func (d *DatabaseStorage) OrphanedKeyStats(ctx context.Context, cutoff time.Time) (*model.OrphanStats, error) {
	stmt := `
	SELECT 
		COUNT(*) FILTER (WHERE created_at < $1) as expired_count,
		COUNT(*) FILTER (WHERE created_at >= $1) as non_expired_count,
		COUNT(*) as total_count
	FROM (
		SELECT DISTINCT ON (cvr.message_id, cvr.aggregation_key) cvr.message_id, cvr.aggregation_key, cvr.created_at
		FROM commit_verification_records cvr
		LEFT JOIN commit_aggregated_reports car ON cvr.message_id = car.message_id
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
