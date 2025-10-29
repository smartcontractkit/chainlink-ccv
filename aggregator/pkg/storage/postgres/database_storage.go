package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func copyMessageWithCCVNodeData(src *pb.MessageWithCCVNodeData) pb.MessageWithCCVNodeData {
	return pb.MessageWithCCVNodeData{
		MessageId:             src.MessageId,
		SourceVerifierAddress: src.SourceVerifierAddress,
		Message:               src.Message,
		BlobData:              src.BlobData,
		CcvData:               src.CcvData,
		Timestamp:             src.Timestamp,
		ReceiptBlobs:          src.ReceiptBlobs,
	}
}

func reconstructIdentifierSigner(participantID, signerAddressHex, committeeID string, signatureR, signatureS []byte) *model.IdentifierSigner {
	signerAddrBytes := common.HexToAddress(signerAddressHex).Bytes()

	var sigR, sigS [32]byte
	copy(sigR[:], signatureR)
	copy(sigS[:], signatureS)

	return &model.IdentifierSigner{
		Signer: model.Signer{
			ParticipantID: participantID,
		},
		Address:     signerAddrBytes,
		SignatureR:  sigR,
		SignatureS:  sigS,
		CommitteeID: committeeID,
	}
}

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

func (d *DatabaseStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	if record == nil {
		return fmt.Errorf("commit verification record cannot be nil")
	}

	id, err := record.GetID()
	if err != nil {
		return fmt.Errorf("failed to get record ID: %w", err)
	}

	messageIDHex := common.Bytes2Hex(id.MessageID)
	signerAddressHex := common.BytesToAddress(record.IdentifierSigner.Address).Hex()

	stmt := `INSERT INTO commit_verification_records 
		(message_id, committee_id, participant_id, signer_address, source_chain_selector, dest_chain_selector, 
		 onramp_address, offramp_address, signature_r, signature_s, ccv_node_data, verification_timestamp) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (message_id, committee_id, signer_address, verification_timestamp) 
		DO NOTHING`

	ccvNodeData, err := proto.Marshal(&record.MessageWithCCVNodeData)
	if err != nil {
		return fmt.Errorf("failed to marshal ccv node data: %w", err)
	}

	var sourceChainSelector, destChainSelector, onrampAddress, offrampAddress string

	if record.Message != nil {
		sourceChainSelector = strconv.FormatUint(record.Message.SourceChainSelector, 10)
		destChainSelector = strconv.FormatUint(record.Message.DestChainSelector, 10)
		onrampAddress = common.BytesToAddress(record.Message.OnRampAddress).Hex()
		offrampAddress = common.BytesToAddress(record.Message.OffRampAddress).Hex()
	}

	_, err = d.ds.ExecContext(ctx, stmt,
		messageIDHex,
		record.CommitteeID,
		record.IdentifierSigner.ParticipantID,
		signerAddressHex,
		sourceChainSelector,
		destChainSelector,
		onrampAddress,
		offrampAddress,
		record.IdentifierSigner.SignatureR[:],
		record.IdentifierSigner.SignatureS[:],
		ccvNodeData,
		record.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("failed to save commit verification record: %w", err)
	}

	return nil
}

func (d *DatabaseStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	stmt := `SELECT message_id, committee_id, participant_id, signer_address, source_chain_selector, dest_chain_selector,
		onramp_address, offramp_address, signature_r, signature_s, ccv_node_data, created_at
		FROM commit_verification_records 
		WHERE message_id = $1 AND committee_id = $2 AND signer_address = $3
		ORDER BY seq_num DESC LIMIT 1`

	var record struct {
		MessageID           string       `db:"message_id"`
		CommitteeID         string       `db:"committee_id"`
		ParticipantID       string       `db:"participant_id"`
		SignerAddress       string       `db:"signer_address"`
		SourceChainSelector string       `db:"source_chain_selector"`
		DestChainSelector   string       `db:"dest_chain_selector"`
		OnrampAddress       string       `db:"onramp_address"`
		OfframpAddress      string       `db:"offramp_address"`
		SignatureR          []byte       `db:"signature_r"`
		SignatureS          []byte       `db:"signature_s"`
		CCVNodeData         []byte       `db:"ccv_node_data"`
		CreatedAt           sql.NullTime `db:"created_at"`
	}

	messageIDHex := common.Bytes2Hex(id.MessageID)
	signerAddressHex := common.BytesToAddress(id.Address).Hex()

	err := d.ds.GetContext(ctx, &record, stmt, messageIDHex, id.CommitteeID, signerAddressHex)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("commit verification record not found")
		}
		return nil, fmt.Errorf("failed to get commit verification record: %w", err)
	}

	var msgWithCCV pb.MessageWithCCVNodeData
	err = proto.Unmarshal(record.CCVNodeData, &msgWithCCV)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
	}

	result := model.CommitVerificationRecord{
		MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
		IdentifierSigner:       reconstructIdentifierSigner(record.ParticipantID, record.SignerAddress, record.CommitteeID, record.SignatureR, record.SignatureS),
		CommitteeID:            record.CommitteeID,
	}

	return &result, nil
}

func (d *DatabaseStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	stmt := `SELECT DISTINCT ON (signer_address) message_id, committee_id, participant_id, signer_address, 
		source_chain_selector, dest_chain_selector, onramp_address, offramp_address, 
		signature_r, signature_s, ccv_node_data, created_at
		FROM commit_verification_records 
		WHERE message_id = $1 AND committee_id = $2
		ORDER BY signer_address, seq_num DESC`

	type dbRecord struct {
		MessageID           string       `db:"message_id"`
		CommitteeID         string       `db:"committee_id"`
		ParticipantID       string       `db:"participant_id"`
		SignerAddress       string       `db:"signer_address"`
		SourceChainSelector string       `db:"source_chain_selector"`
		DestChainSelector   string       `db:"dest_chain_selector"`
		OnrampAddress       string       `db:"onramp_address"`
		OfframpAddress      string       `db:"offramp_address"`
		SignatureR          []byte       `db:"signature_r"`
		SignatureS          []byte       `db:"signature_s"`
		CCVNodeData         []byte       `db:"ccv_node_data"`
		CreatedAt           sql.NullTime `db:"created_at"`
	}

	messageIDHex := common.Bytes2Hex(messageID)

	var dbRecords []dbRecord
	err := d.ds.SelectContext(ctx, &dbRecords, stmt, messageIDHex, committee)
	if err != nil {
		return nil, fmt.Errorf("failed to query commit verification records: %w", err)
	}

	records := make([]*model.CommitVerificationRecord, 0, len(dbRecords))
	for _, dbRec := range dbRecords {
		var msgWithCCV pb.MessageWithCCVNodeData
		err = proto.Unmarshal(dbRec.CCVNodeData, &msgWithCCV)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
		}

		record := model.CommitVerificationRecord{
			MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
			IdentifierSigner:       reconstructIdentifierSigner(dbRec.ParticipantID, dbRec.SignerAddress, dbRec.CommitteeID, dbRec.SignatureR, dbRec.SignatureS),
			CommitteeID:            dbRec.CommitteeID,
		}

		records = append(records, &record)
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

	stmt := `
		SELECT 
			car.message_id,
			car.committee_id,
			car.created_at,
			car.seq_num,
			car.winning_receipt_blobs,
			cvr.participant_id,
			cvr.signer_address,
			cvr.signature_r,
			cvr.signature_s,
			cvr.ccv_node_data
		FROM commit_aggregated_reports car
		LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
		LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
		WHERE car.committee_id = $1 AND car.seq_num >= $2
		ORDER BY car.seq_num ASC, vid.ord
	`

	type joinedRecord struct {
		MessageID           string         `db:"message_id"`
		CommitteeID         string         `db:"committee_id"`
		CreatedAt           time.Time      `db:"created_at"`
		SeqNum              int64          `db:"seq_num"`
		WinningReceiptBlobs sql.NullString `db:"winning_receipt_blobs"`
		ParticipantID       sql.NullString `db:"participant_id"`
		SignerAddress       sql.NullString `db:"signer_address"`
		SignatureR          []byte         `db:"signature_r"`
		SignatureS          []byte         `db:"signature_s"`
		CCVNodeData         []byte         `db:"ccv_node_data"`
	}

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

	for rows.Next() {
		var record joinedRecord
		err := rows.Scan(
			&record.MessageID,
			&record.CommitteeID,
			&record.CreatedAt,
			&record.SeqNum,
			&record.WinningReceiptBlobs,
			&record.ParticipantID,
			&record.SignerAddress,
			&record.SignatureR,
			&record.SignatureS,
			&record.CCVNodeData,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		reportKey := fmt.Sprintf("%s-%d", record.MessageID, record.SeqNum)

		report, exists := reportsMap[reportKey]
		if !exists {
			if reportCount >= d.pageSize {
				break
			}

			// Deserialize winning receipt blobs from JSON
			var winningReceiptBlobs []*model.ReceiptBlob
			if record.WinningReceiptBlobs.Valid && record.WinningReceiptBlobs.String != "" {
				var err error
				winningReceiptBlobs, err = model.DeserializeReceiptBlobsJSON([]byte(record.WinningReceiptBlobs.String))
				if err != nil {
					return nil, fmt.Errorf("failed to deserialize winning receipt blobs from JSON: %w", err)
				}
			}

			report = &model.CommitAggregatedReport{
				MessageID:           common.Hex2Bytes(record.MessageID),
				CommitteeID:         record.CommitteeID,
				Verifications:       []*model.CommitVerificationRecord{},
				Sequence:            record.SeqNum,
				WrittenAt:           record.CreatedAt.Unix(),
				WinningReceiptBlobs: winningReceiptBlobs,
			}
			reportsMap[reportKey] = report
			reportOrder = append(reportOrder, reportKey)
			reportCount++
		}

		if record.ParticipantID.Valid && record.SignerAddress.Valid && len(record.CCVNodeData) > 0 {
			var msgWithCCV pb.MessageWithCCVNodeData
			err = proto.Unmarshal(record.CCVNodeData, &msgWithCCV)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
			}

			verification := &model.CommitVerificationRecord{
				MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
				IdentifierSigner:       reconstructIdentifierSigner(record.ParticipantID.String, record.SignerAddress.String, record.CommitteeID, record.SignatureR, record.SignatureS),
				CommitteeID:            record.CommitteeID,
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

	stmt := `
		SELECT 
			car.message_id,
			car.committee_id,
			car.created_at,
			car.seq_num,
			cvr.participant_id,
			cvr.signer_address,
			cvr.signature_r,
			cvr.signature_s,
			cvr.ccv_node_data
		FROM commit_aggregated_reports car
		LEFT JOIN LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord) ON true
		LEFT JOIN commit_verification_records cvr ON cvr.id = vid.id
		WHERE car.message_id = $1 AND car.committee_id = $2
		ORDER BY car.seq_num DESC, vid.ord
		LIMIT 100
	`

	type joinedRecord struct {
		MessageID     string         `db:"message_id"`
		CommitteeID   string         `db:"committee_id"`
		CreatedAt     time.Time      `db:"created_at"`
		SeqNum        int64          `db:"seq_num"`
		ParticipantID sql.NullString `db:"participant_id"`
		SignerAddress sql.NullString `db:"signer_address"`
		SignatureR    []byte         `db:"signature_r"`
		SignatureS    []byte         `db:"signature_s"`
		CCVNodeData   []byte         `db:"ccv_node_data"`
	}

	rows, err := d.ds.QueryContext(ctx, stmt, messageIDHex, committeeID)
	if err != nil {
		return nil, fmt.Errorf("failed to query aggregated report: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var report *model.CommitAggregatedReport

	for rows.Next() {
		var record joinedRecord
		err := rows.Scan(
			&record.MessageID,
			&record.CommitteeID,
			&record.CreatedAt,
			&record.SeqNum,
			&record.ParticipantID,
			&record.SignerAddress,
			&record.SignatureR,
			&record.SignatureS,
			&record.CCVNodeData,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if report == nil {
			report = &model.CommitAggregatedReport{
				MessageID:     common.Hex2Bytes(record.MessageID),
				CommitteeID:   record.CommitteeID,
				Verifications: []*model.CommitVerificationRecord{},
				Sequence:      record.SeqNum,
				WrittenAt:     record.CreatedAt.Unix(),
			}
		}

		if record.ParticipantID.Valid && record.SignerAddress.Valid && len(record.CCVNodeData) > 0 {
			var msgWithCCV pb.MessageWithCCVNodeData
			err = proto.Unmarshal(record.CCVNodeData, &msgWithCCV)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
			}

			verification := &model.CommitVerificationRecord{
				MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
				IdentifierSigner:       reconstructIdentifierSigner(record.ParticipantID.String, record.SignerAddress.String, record.CommitteeID, record.SignatureR, record.SignatureS),
				CommitteeID:            record.CommitteeID,
			}

			report.Verifications = append(report.Verifications, verification)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return report, nil
}

func (d *DatabaseStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	if report == nil {
		return fmt.Errorf("aggregated report cannot be nil")
	}

	report.Sequence = time.Now().Unix()

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

	reportData := []byte(fmt.Sprintf("verification_count:%d", len(report.Verifications)))

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
		(message_id, committee_id, verification_record_ids, report_data, winning_receipt_blobs) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (message_id, committee_id, verification_record_ids) DO NOTHING`

	result, err := d.ds.ExecContext(ctx, stmt,
		messageIDHex,
		report.CommitteeID,
		pq.Array(verificationRecordIDs),
		reportData,
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

func (d *DatabaseStorage) ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error) {
	messageIDCh := make(chan model.MessageID, 10) // Buffered for performance
	errCh := make(chan error, 1)

	go func() {
		defer close(messageIDCh)
		defer close(errCh)

		// Query to find distinct (message_id, committee_id) pairs from verification records
		// that don't have corresponding aggregated reports
		stmt := `
		SELECT DISTINCT cvr.message_id
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

			var messageIDHex string
			err := rows.Scan(&messageIDHex)
			if err != nil {
				errCh <- fmt.Errorf("failed to scan orphaned pair: %w", err)
				return
			}

			messageID := common.Hex2Bytes(messageIDHex)

			select {
			case messageIDCh <- messageID:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}

		if err := rows.Err(); err != nil {
			errCh <- fmt.Errorf("error iterating over orphaned pairs: %w", err)
		}
	}()

	return messageIDCh, errCh
}
