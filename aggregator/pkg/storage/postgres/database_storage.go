package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

func (d *DatabaseStorage) batchGetVerificationRecordIDs(ctx context.Context, messageIDHex, committeeID string, signerAddresses []string) (map[string]int64, error) {
	recordIDsMap := make(map[string]int64)
	if len(signerAddresses) == 0 {
		return recordIDsMap, nil
	}

	stmt := `SELECT DISTINCT ON (signer_address) signer_address, id
		FROM commit_verification_records 
		WHERE message_id = $1 AND committee_id = $2 AND signer_address = ANY($3)
		ORDER BY signer_address, seq_num DESC`

	type idRecord struct {
		SignerAddress string `db:"signer_address"`
		ID            int64  `db:"id"`
	}

	var records []idRecord
	err := d.ds.SelectContext(ctx, &records, stmt, messageIDHex, committeeID, pq.Array(signerAddresses))
	if err != nil {
		return nil, fmt.Errorf("failed to get verification record IDs: %w", err)
	}

	for _, record := range records {
		recordIDsMap[record.SignerAddress] = record.ID
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
)

func NewDatabaseStorage(ds sqlutil.DataSource, pageSize int, lggr logger.SugaredLogger) *DatabaseStorage {
	return &DatabaseStorage{
		ds:       ds,
		pageSize: pageSize,
		lggr:     lggr,
	}
}

func (d *DatabaseStorage) HealthCheck(ctx context.Context) *pkgcommon.ComponentHealth {
	result := &pkgcommon.ComponentHealth{
		Name:      "postgres_storage",
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var count int
	err := d.ds.GetContext(ctx, &count, "SELECT 1")
	if err != nil {
		result.Status = pkgcommon.HealthStatusUnhealthy
		result.Message = fmt.Sprintf("query failed: %v", err)
		return result
	}

	result.Status = pkgcommon.HealthStatusHealthy
	result.Message = "connected and responsive"
	return result
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
		(message_id, committee_id, participant_id, signer_address, 
		 signature_r, signature_s, verification_timestamp, idempotency_key, aggregation_key,
		 source_verifier_address, blob_data, ccv_data, message_data, receipt_blobs) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (message_id, committee_id, signer_address, idempotency_key, aggregation_key) 
		DO NOTHING
		RETURNING id`

	var recordID int64
	err = d.ds.GetContext(ctx, &recordID, stmt,
		params["message_id"],
		params["committee_id"],
		params["participant_id"],
		params["signer_address"],
		params["signature_r"],
		params["signature_s"],
		params["verification_timestamp"],
		params["idempotency_key"],
		params["aggregation_key"],
		params["source_verifier_address"],
		params["blob_data"],
		params["ccv_data"],
		params["message_data"],
		params["receipt_blobs"],
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
		WHERE message_id = $1 AND committee_id = $2 AND signer_address = $3
		ORDER BY seq_num DESC LIMIT 1`, allVerificationRecordColumns)

	messageIDHex := common.Bytes2Hex(id.MessageID)
	signerAddressHex := common.BytesToAddress(id.Address).Hex()

	var row commitVerificationRecordRow
	err := d.ds.GetContext(ctx, &row, stmt, messageIDHex, id.CommitteeID, signerAddressHex)
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

func (d *DatabaseStorage) ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey, committee string) ([]*model.CommitVerificationRecord, error) {
	stmt := fmt.Sprintf(`SELECT DISTINCT ON (signer_address) %s
		FROM commit_verification_records 
		WHERE message_id = $1 AND committee_id = $2 AND aggregation_key = $3
		ORDER BY signer_address, seq_num DESC`, allVerificationRecordColumns)

	messageIDHex := common.Bytes2Hex(messageID)

	var rows []commitVerificationRecordRow
	err := d.ds.SelectContext(ctx, &rows, stmt, messageIDHex, committee, aggregationKey)
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

type PaginationToken struct {
	CommitteeID            string `json:"committee_id"`
	SinceSequenceInclusive int64  `json:"since_sequence_inclusive"`
}

func parsePostgresPaginationToken(token *string) (*PaginationToken, error) {
	if token == nil || *token == "" {
		return nil, nil
	}

	var parsedToken PaginationToken
	err := json.Unmarshal([]byte(*token), &parsedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pagination token: %w", err)
	}

	return &parsedToken, nil
}

func serializePostgresPaginationToken(token *PaginationToken) (*string, error) {
	if token == nil {
		return nil, nil
	}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize pagination token: %w", err)
	}

	tokenStr := string(tokenBytes)
	return &tokenStr, nil
}

func (d *DatabaseStorage) QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error) {
	var effectiveSequence int64
	if token != nil && *token != "" {
		parsedToken, err := parsePostgresPaginationToken(token)
		if err != nil {
			return nil, fmt.Errorf("invalid pagination token: %w", err)
		}
		if parsedToken.CommitteeID != committeeID {
			return nil, fmt.Errorf("pagination token committee mismatch: expected %s, got %s", committeeID, parsedToken.CommitteeID)
		}
		effectiveSequence = parsedToken.SinceSequenceInclusive
	} else {
		effectiveSequence = sinceSequenceInclusive
	}

	stmt := fmt.Sprintf(`
		SELECT 
			car.message_id,
			car.committee_id,
			car.created_at,
			car.seq_num,
			car.winning_receipt_blobs,
			%s
		FROM commit_aggregated_reports car
		LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
		LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
		WHERE car.committee_id = $1 AND car.seq_num >= $2
		ORDER BY car.seq_num ASC, vid.ord
	`, allVerificationRecordColumnsQualified)

	rows, err := d.ds.QueryContext(ctx, stmt, committeeID, effectiveSequence)
	if err != nil {
		return nil, fmt.Errorf("failed to query aggregated reports: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	reportsMap := make(map[string]*model.CommitAggregatedReport)
	reportOrder := make([]string, 0)
	reportCount := 0
	verificationRowsByReport := make(map[string][]*commitVerificationRecordRow)

	for rows.Next() {
		var messageIDReport, committeeID string
		var createdAt time.Time
		var seqNum int64
		var winningReceiptBlobsStr sql.NullString
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
			&committeeID,
			&createdAt,
			&seqNum,
			&winningReceiptBlobsStr,
			&verRow.MessageID,
			&verRow.CommitteeID,
			&verRow.ParticipantID,
			&verRow.SignerAddress,
			&verRow.SignatureR,
			&verRow.SignatureS,
			&verRow.VerificationTimestamp,
			&verRow.IdempotencyKey,
			&verRow.AggregationKey,
			&verRow.SourceVerifierAddress,
			&verRow.BlobData,
			&verRow.CcvData,
			&verRow.MessageData,
			&verRow.ReceiptBlobs,
			&verRow.ID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		reportKey := fmt.Sprintf("%s-%d", messageIDReport, seqNum)

		_, exists := reportsMap[reportKey]
		if !exists {
			if reportCount >= d.pageSize {
				break
			}

			var winningReceiptBlobs []*model.ReceiptBlob
			if winningReceiptBlobsStr.Valid && winningReceiptBlobsStr.String != "" {
				var err error
				winningReceiptBlobs, err = model.DeserializeReceiptBlobsJSON([]byte(winningReceiptBlobsStr.String))
				if err != nil {
					return nil, fmt.Errorf("failed to deserialize winning receipt blobs from JSON: %w", err)
				}
			}

			reportsMap[reportKey] = &model.CommitAggregatedReport{
				MessageID:           common.Hex2Bytes(messageIDReport),
				CommitteeID:         committeeID,
				Verifications:       []*model.CommitVerificationRecord{},
				Sequence:            seqNum,
				WrittenAt:           createdAt,
				WinningReceiptBlobs: winningReceiptBlobs,
			}
			reportOrder = append(reportOrder, reportKey)
			reportCount++
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
		return &model.PaginatedAggregatedReports{}, nil
	}

	reports := make([]*model.CommitAggregatedReport, 0, len(reportOrder))
	for _, key := range reportOrder {
		reports = append(reports, reportsMap[key])
	}

	var nextPageToken *string
	hasMore := false

	for rows.Next() {
		hasMore = true
		break
	}

	if hasMore && len(reports) > 0 {
		lastReport := reports[len(reports)-1]
		nextToken := &PaginationToken{
			CommitteeID:            committeeID,
			SinceSequenceInclusive: lastReport.Sequence + 1,
		}

		nextPageToken, err = serializePostgresPaginationToken(nextToken)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize next page token: %w", err)
		}
	}

	return &model.PaginatedAggregatedReports{
		Reports:       reports,
		NextPageToken: nextPageToken,
	}, nil
}

func (d *DatabaseStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	messageIDHex := common.Bytes2Hex(messageID)

	stmt := fmt.Sprintf(`
        SELECT 
            car.message_id,
            car.committee_id,
            car.created_at,
            car.seq_num,
            car.winning_receipt_blobs,
            %s
        FROM commit_aggregated_reports car
        LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
        LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
        WHERE car.message_id = $1 AND car.committee_id = $2
        ORDER BY car.seq_num DESC, vid.ord

    `, allVerificationRecordColumnsQualified)

	rows, err := d.ds.QueryContext(ctx, stmt, messageIDHex, committeeID)
	if err != nil {
		return nil, fmt.Errorf("failed to query aggregated report: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var report *model.CommitAggregatedReport
	var verificationRows []*commitVerificationRecordRow

	for rows.Next() {
		var messageIDReport, committeeIDStr string
		var createdAt time.Time
		var seqNum int64
		var winningReceiptBlobsStr sql.NullString
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
			&committeeIDStr,
			&createdAt,
			&seqNum,
			&winningReceiptBlobsStr,
			&verRow.MessageID,
			&verRow.CommitteeID,
			&verRow.ParticipantID,
			&verRow.SignerAddress,
			&verRow.SignatureR,
			&verRow.SignatureS,
			&verRow.VerificationTimestamp,
			&verRow.IdempotencyKey,
			&verRow.AggregationKey,
			&verRow.SourceVerifierAddress,
			&verRow.BlobData,
			&verRow.CcvData,
			&verRow.MessageData,
			&verRow.ReceiptBlobs,
			&verRow.ID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if report == nil {
			var winningReceiptBlobs []*model.ReceiptBlob
			if winningReceiptBlobsStr.Valid && winningReceiptBlobsStr.String != "" {
				var err error
				winningReceiptBlobs, err = model.DeserializeReceiptBlobsJSON([]byte(winningReceiptBlobsStr.String))
				if err != nil {
					return nil, fmt.Errorf("failed to deserialize winning receipt blobs from JSON: %w", err)
				}
			}

			report = &model.CommitAggregatedReport{
				MessageID:           common.Hex2Bytes(messageIDReport),
				CommitteeID:         committeeIDStr,
				Verifications:       []*model.CommitVerificationRecord{},
				Sequence:            seqNum,
				WrittenAt:           createdAt,
				WinningReceiptBlobs: winningReceiptBlobs,
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

func (d *DatabaseStorage) GetBatchCCVData(ctx context.Context, messageIDs []model.MessageID, committeeID string) (map[string]*model.CommitAggregatedReport, error) {
	if len(messageIDs) == 0 {
		return make(map[string]*model.CommitAggregatedReport), nil
	}

	messageIDHexValues := make([]string, len(messageIDs))
	for i, messageID := range messageIDs {
		messageIDHexValues[i] = common.Bytes2Hex(messageID)
	}

	placeholders := make([]string, len(messageIDHexValues))
	args := make([]any, len(messageIDHexValues)+1)
	for i, messageIDHex := range messageIDHexValues {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = messageIDHex
	}
	args[len(messageIDHexValues)] = committeeID

	stmt := fmt.Sprintf(`
		SELECT 
			car.message_id,
			car.committee_id,
			car.created_at,
			car.seq_num,
			car.winning_receipt_blobs,
			%s
		FROM commit_aggregated_reports car
		LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
		LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
		WHERE car.message_id IN (%s) AND car.committee_id = $%d
		ORDER BY car.message_id, car.seq_num DESC, vid.ord
	`, allVerificationRecordColumnsQualified, strings.Join(placeholders, ","), len(messageIDHexValues)+1)

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
		var messageIDReport, committeeIDStr string
		var createdAt time.Time
		var seqNum int64
		var winningReceiptBlobsStr sql.NullString
		var verRow commitVerificationRecordRow

		err := rows.Scan(
			&messageIDReport,
			&committeeIDStr,
			&createdAt,
			&seqNum,
			&winningReceiptBlobsStr,
			&verRow.MessageID,
			&verRow.CommitteeID,
			&verRow.ParticipantID,
			&verRow.SignerAddress,
			&verRow.SignatureR,
			&verRow.SignatureS,
			&verRow.VerificationTimestamp,
			&verRow.IdempotencyKey,
			&verRow.AggregationKey,
			&verRow.SourceVerifierAddress,
			&verRow.BlobData,
			&verRow.CcvData,
			&verRow.MessageData,
			&verRow.ReceiptBlobs,
			&verRow.ID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		_, exists := reports[messageIDReport]
		if !exists {
			messageIDBytes := common.Hex2Bytes(messageIDReport)
			var winningReceiptBlobs []*model.ReceiptBlob
			if winningReceiptBlobsStr.Valid && winningReceiptBlobsStr.String != "" {
				var err error
				winningReceiptBlobs, err = model.DeserializeReceiptBlobsJSON([]byte(winningReceiptBlobsStr.String))
				if err != nil {
					return nil, fmt.Errorf("failed to deserialize winning receipt blobs from JSON: %w", err)
				}
			}
			reports[messageIDReport] = &model.CommitAggregatedReport{
				MessageID:           messageIDBytes,
				CommitteeID:         committeeIDStr,
				Verifications:       []*model.CommitVerificationRecord{},
				Sequence:            seqNum,
				WrittenAt:           createdAt,
				WinningReceiptBlobs: winningReceiptBlobs,
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

func (d *DatabaseStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	if report == nil {
		return fmt.Errorf("aggregated report cannot be nil")
	}

	verificationRecordIDs := make([]int64, 0, len(report.Verifications))
	messageIDHex := common.Bytes2Hex(report.MessageID)

	signerAddresses := make([]string, 0, len(report.Verifications))
	for _, verification := range report.Verifications {
		signerAddressHex := common.BytesToAddress(verification.IdentifierSigner.Address).Hex()
		signerAddresses = append(signerAddresses, signerAddressHex)
	}

	recordIDsMap, err := d.batchGetVerificationRecordIDs(ctx, messageIDHex, report.CommitteeID, signerAddresses)
	if err != nil {
		return err
	}

	for _, verification := range report.Verifications {
		signerAddressHex := common.BytesToAddress(verification.IdentifierSigner.Address).Hex()
		recordID, exists := recordIDsMap[signerAddressHex]
		if !exists {
			return fmt.Errorf("failed to find verification record ID for signer %s", signerAddressHex)
		}
		verificationRecordIDs = append(verificationRecordIDs, recordID)
	}

	sort.Slice(verificationRecordIDs, func(i, j int) bool {
		return verificationRecordIDs[i] < verificationRecordIDs[j]
	})

	// Serialize winning receipt blobs using JSON for better debugging visibility
	var winningReceiptBlobsData any
	if len(report.WinningReceiptBlobs) > 0 {
		jsonBytes, err := model.SerializeReceiptBlobsJSON(report.WinningReceiptBlobs)
		if err != nil {
			return fmt.Errorf("failed to serialize winning receipt blobs to JSON: %w", err)
		}
		// Convert to string for JSONB column
		winningReceiptBlobsData = string(jsonBytes)
	}

	stmt := `INSERT INTO commit_aggregated_reports 
		(message_id, committee_id, verification_record_ids, winning_receipt_blobs) 
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (message_id, committee_id, verification_record_ids) DO NOTHING`

	result, err := d.ds.ExecContext(ctx, stmt,
		messageIDHex,
		report.CommitteeID,
		pq.Array(verificationRecordIDs),
		winningReceiptBlobsData,
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

func (d *DatabaseStorage) ListOrphanedKeys(ctx context.Context, committeeID model.CommitteeID) (<-chan model.OrphanedKey, <-chan error) {
	orphanedKeyCh := make(chan model.OrphanedKey, 10) // Buffered for performance
	errCh := make(chan error, 1)

	go func() {
		defer close(orphanedKeyCh)
		defer close(errCh)

		// Query to find distinct  pairs from verification records
		// that don't have corresponding aggregated reports
		stmt := `
		SELECT DISTINCT cvr.message_id, cvr.aggregation_key
		FROM commit_verification_records cvr
		LEFT JOIN commit_aggregated_reports car ON cvr.message_id = car.message_id AND cvr.committee_id = car.committee_id
		WHERE car.message_id IS NULL AND cvr.committee_id = $1`

		rows, err := d.ds.QueryContext(ctx, stmt, committeeID)
		if err != nil {
			errCh <- fmt.Errorf("failed to query orphaned message committee pairs: %w", err)
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

			messageID := common.Hex2Bytes(result.MessageID)

			select {
			case orphanedKeyCh <- model.OrphanedKey{
				MessageID:      messageID,
				AggregationKey: result.AggregationKey,
				CommitteeID:    committeeID,
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
