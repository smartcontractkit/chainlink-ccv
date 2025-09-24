package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
)

// copyMessageWithCCVNodeData safely copies MessageWithCCVNodeData without mutex issues.
func copyMessageWithCCVNodeData(src *aggregator.MessageWithCCVNodeData) aggregator.MessageWithCCVNodeData {
	return aggregator.MessageWithCCVNodeData{
		MessageId:             src.MessageId,
		SourceVerifierAddress: src.SourceVerifierAddress,
		Message:               src.Message,
		BlobData:              src.BlobData,
		CcvData:               src.CcvData,
		Timestamp:             src.Timestamp,
		ReceiptBlobs:          src.ReceiptBlobs,
	}
}

// processVerificationFromReportRow converts database row data into a CommitVerificationRecord.
// Returns nil if the row doesn't contain verification data (e.g., from LEFT JOIN).
func processVerificationFromReportRow(row *dbReportWithVerification) (*model.CommitVerificationRecord, error) {
	// Check if verification data exists (LEFT JOIN might return NULL verification data)
	if row.SignerAddress == nil || row.ParticipantID == nil || len(row.CCVNodeData) == 0 {
		return nil, nil
	}

	// Reconstruct the MessageWithCCVNodeData
	var msgWithCCV aggregator.MessageWithCCVNodeData
	err := proto.Unmarshal(row.CCVNodeData, &msgWithCCV)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
	}

	// Convert signer address back to bytes
	signerAddrBytes := common.HexToAddress(*row.SignerAddress).Bytes()

	// Convert signature components back to arrays
	var signatureR, signatureS [32]byte
	copy(signatureR[:], row.SignatureR)
	copy(signatureS[:], row.SignatureS)

	verification := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
		IdentifierSigner: &model.IdentifierSigner{
			Signer: model.Signer{
				ParticipantID: *row.ParticipantID,
			},
			Address:     signerAddrBytes,
			SignatureR:  signatureR,
			SignatureS:  signatureS,
			CommitteeID: row.CommitteeID,
		},
		CommitteeID: row.CommitteeID,
	}

	return verification, nil
}

// dbReportWithVerification represents a joined query result from aggregated reports and verification records.
type dbReportWithVerification struct {
	MessageID     string    `db:"message_id"`
	CommitteeID   string    `db:"committee_id"`
	ReportData    []byte    `db:"report_data"`
	UpdatedAt     time.Time `db:"updated_at"`
	ParticipantID *string   `db:"participant_id"` // NULL if no verifications
	SignerAddress *string   `db:"signer_address"` // NULL if no verifications
	SignatureR    []byte    `db:"signature_r"`    // NULL if no verifications
	SignatureS    []byte    `db:"signature_s"`    // NULL if no verifications
	CCVNodeData   []byte    `db:"ccv_node_data"`  // NULL if no verifications
}

// DatabaseStorage implements CommitVerificationStore and CommitVerificationAggregatedStore
// using either PostgreSQL or SQLite as the backing database.
type DatabaseStorage struct {
	ds sqlutil.DataSource
}

// Ensure DatabaseStorage implements the required interfaces.
var (
	_ pkgcommon.CommitVerificationStore           = (*DatabaseStorage)(nil)
	_ pkgcommon.CommitVerificationAggregatedStore = (*DatabaseStorage)(nil)
)

// NewDatabaseStorage creates a new database storage instance.
func NewDatabaseStorage(ds sqlutil.DataSource) *DatabaseStorage {
	return &DatabaseStorage{
		ds: ds,
	}
}

// SaveCommitVerification persists a commit verification record.
func (d *DatabaseStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	if record == nil {
		return fmt.Errorf("commit verification record cannot be nil")
	}

	id, err := record.GetID()
	if err != nil {
		return fmt.Errorf("failed to get record ID: %w", err)
	}

	stmt := `INSERT INTO commit_verification_records 
		(message_id, committee_id, participant_id, signer_address, source_chain_selector, dest_chain_selector, 
		 onramp_address, offramp_address, signature_r, signature_s, ccv_node_data, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (message_id, signer_address, committee_id) 
		DO UPDATE SET 
			participant_id = EXCLUDED.participant_id,
			source_chain_selector = EXCLUDED.source_chain_selector,
			dest_chain_selector = EXCLUDED.dest_chain_selector,
			onramp_address = EXCLUDED.onramp_address,
			offramp_address = EXCLUDED.offramp_address,
			signature_r = EXCLUDED.signature_r,
			signature_s = EXCLUDED.signature_s,
			ccv_node_data = EXCLUDED.ccv_node_data,
			updated_at = NOW()`

	// Serialize the CCVNodeData for storage
	ccvNodeData, err := proto.Marshal(&record.MessageWithCCVNodeData)
	if err != nil {
		return fmt.Errorf("failed to marshal ccv node data: %w", err)
	}

	// Extract message fields, handling nil cases and convert to strings
	var sourceChainSelector, destChainSelector, onrampAddress, offrampAddress string

	if record.Message != nil {
		sourceChainSelector = strconv.FormatUint(record.Message.SourceChainSelector, 10)
		destChainSelector = strconv.FormatUint(record.Message.DestChainSelector, 10)
		onrampAddress = common.BytesToAddress(record.Message.OnRampAddress).Hex()
		offrampAddress = common.BytesToAddress(record.Message.OffRampAddress).Hex()
	}

	// Convert message ID and signer address to hex strings
	messageIDHex := common.Bytes2Hex(id.MessageID)
	signerAddressHex := common.BytesToAddress(record.IdentifierSigner.Address).Hex()

	now := time.Now()
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
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to save commit verification record: %w", err)
	}

	return nil
}

// GetCommitVerification retrieves a commit verification record by its identifier.
func (d *DatabaseStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	stmt := `SELECT message_id, committee_id, participant_id, signer_address, source_chain_selector, dest_chain_selector,
		onramp_address, offramp_address, signature_r, signature_s, ccv_node_data, created_at
		FROM commit_verification_records 
		WHERE message_id = $1 AND signer_address = $2 AND committee_id = $3`

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

	// Convert identifiers to strings for query
	messageIDHex := common.Bytes2Hex(id.MessageID)
	signerAddressHex := common.BytesToAddress(id.Address).Hex()

	err := d.ds.GetContext(ctx, &record, stmt, messageIDHex, signerAddressHex, id.CommitteeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("commit verification record not found")
		}
		return nil, fmt.Errorf("failed to get commit verification record: %w", err)
	}

	// Reconstruct the MessageWithCCVNodeData
	var msgWithCCV aggregator.MessageWithCCVNodeData
	err = proto.Unmarshal(record.CCVNodeData, &msgWithCCV)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
	}

	// Convert signer address back to bytes
	signerAddrBytes := common.HexToAddress(record.SignerAddress).Bytes()

	// Convert signature components back to arrays
	var signatureR, signatureS [32]byte
	copy(signatureR[:], record.SignatureR)
	copy(signatureS[:], record.SignatureS)

	// Create record with embedded protobuf message using safe copy
	result := model.CommitVerificationRecord{
		MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
		IdentifierSigner: &model.IdentifierSigner{
			Signer: model.Signer{
				ParticipantID: record.ParticipantID,
			},
			Address:     signerAddrBytes,
			SignatureR:  signatureR,
			SignatureS:  signatureS,
			CommitteeID: record.CommitteeID,
		},
		CommitteeID: record.CommitteeID,
	}

	return &result, nil
}

// ListCommitVerificationByMessageID retrieves all commit verification records for a specific message ID and committee ID.
func (d *DatabaseStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	stmt := `SELECT message_id, committee_id, participant_id, signer_address, source_chain_selector, dest_chain_selector,
		onramp_address, offramp_address, signature_r, signature_s, ccv_node_data, created_at
		FROM commit_verification_records 
		WHERE message_id = $1 AND committee_id = $2
		ORDER BY created_at ASC`

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
		// Reconstruct the MessageWithCCVNodeData
		var msgWithCCV aggregator.MessageWithCCVNodeData
		err = proto.Unmarshal(dbRec.CCVNodeData, &msgWithCCV)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
		}

		// Convert signer address back to bytes
		signerAddrBytes := common.HexToAddress(dbRec.SignerAddress).Bytes()

		// Convert signature components back to arrays
		var signatureR, signatureS [32]byte
		copy(signatureR[:], dbRec.SignatureR)
		copy(signatureS[:], dbRec.SignatureS)

		record := model.CommitVerificationRecord{
			MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
			IdentifierSigner: &model.IdentifierSigner{
				Signer: model.Signer{
					ParticipantID: dbRec.ParticipantID,
				},
				Address:     signerAddrBytes,
				SignatureR:  signatureR,
				SignatureS:  signatureS,
				CommitteeID: dbRec.CommitteeID,
			},
			CommitteeID: dbRec.CommitteeID,
		}

		records = append(records, &record)
	}

	return records, nil
}

// QueryAggregatedReports retrieves all aggregated reports within a specific time range.
func (d *DatabaseStorage) QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string) ([]*model.CommitAggregatedReport, error) {
	startTime := time.Unix(start, 0)
	endTime := time.Unix(end, 0)

	stmt := `SELECT 
		ar.message_id, ar.committee_id, ar.report_data, ar.updated_at,
		cvr.participant_id, cvr.signer_address, cvr.signature_r, cvr.signature_s, cvr.ccv_node_data
		FROM commit_aggregated_reports ar
		LEFT JOIN commit_verification_records cvr ON ar.message_id = cvr.message_id AND ar.committee_id = cvr.committee_id
		WHERE ar.committee_id = $1 AND ar.updated_at >= $2 AND ar.updated_at <= $3
		ORDER BY ar.updated_at ASC, cvr.created_at ASC`

	var dbRows []dbReportWithVerification
	err := d.ds.SelectContext(ctx, &dbRows, stmt, committeeID, startTime, endTime)
	if err != nil {
		return []*model.CommitAggregatedReport{}, err
	}

	// Group rows by message_id to construct reports
	reportsMap := make(map[string]*model.CommitAggregatedReport)

	for _, row := range dbRows {
		messageIDBytes := common.Hex2Bytes(row.MessageID)

		// Get or create the report
		report, exists := reportsMap[row.MessageID]
		if !exists {
			report = &model.CommitAggregatedReport{
				MessageID:     messageIDBytes,
				CommitteeID:   row.CommitteeID,
				Verifications: []*model.CommitVerificationRecord{},
				Timestamp:     row.UpdatedAt.Unix(),
			}
			reportsMap[row.MessageID] = report
		}

		// Add verification if it exists (LEFT JOIN might return NULL verification data)
		verification, err := processVerificationFromReportRow(&row)
		if err != nil {
			return nil, err
		}
		if verification != nil {
			report.Verifications = append(report.Verifications, verification)
		}
	} // Convert map to slice
	reports := make([]*model.CommitAggregatedReport, 0, len(reportsMap))
	for _, report := range reportsMap {
		reports = append(reports, report)
	}

	return reports, nil
}

// GetCCVData retrieves the aggregated CCV data for a specific message ID.
func (d *DatabaseStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	stmt := `SELECT 
		ar.message_id, ar.committee_id, ar.report_data, ar.updated_at,
		cvr.participant_id, cvr.signer_address, cvr.signature_r, cvr.signature_s, cvr.ccv_node_data
		FROM commit_aggregated_reports ar
		LEFT JOIN commit_verification_records cvr ON ar.message_id = cvr.message_id AND ar.committee_id = cvr.committee_id
		WHERE ar.message_id = $1 AND ar.committee_id = $2
		ORDER BY cvr.created_at ASC`

	messageIDHex := common.Bytes2Hex(messageID)

	var dbRows []dbReportWithVerification
	err := d.ds.SelectContext(ctx, &dbRows, stmt, messageIDHex, committeeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, err
	}

	if len(dbRows) == 0 {
		return nil, nil // Not found
	}

	// Use first row for report metadata
	firstRow := dbRows[0]
	report := &model.CommitAggregatedReport{
		MessageID:     common.Hex2Bytes(firstRow.MessageID),
		CommitteeID:   firstRow.CommitteeID,
		Verifications: []*model.CommitVerificationRecord{},
		Timestamp:     firstRow.UpdatedAt.Unix(),
	}

	// Process all verifications
	for i := range dbRows {
		// Add verification if it exists (LEFT JOIN might return NULL verification data)
		verification, err := processVerificationFromReportRow(&dbRows[i])
		if err != nil {
			return nil, err
		}
		if verification != nil {
			report.Verifications = append(report.Verifications, verification)
		}
	}

	return report, nil
}

// SubmitReport stores an aggregated report (used by in-memory storage interface).
func (d *DatabaseStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	if report == nil {
		return fmt.Errorf("aggregated report cannot be nil")
	}

	// Set timestamp in the storage layer (following in-memory storage pattern)
	report.Timestamp = time.Now().Unix()

	// Serialize the verifications for storage (simplified - in production you'd serialize the full data)
	reportData := []byte(fmt.Sprintf("verification_count:%d", len(report.Verifications)))

	stmt := `INSERT INTO commit_aggregated_reports 
		(message_id, committee_id, report_data, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (message_id, committee_id) 
		DO UPDATE SET 
			report_data = EXCLUDED.report_data,
			updated_at = NOW()`

	now := time.Now()
	_, err := d.ds.ExecContext(ctx, stmt,
		common.Bytes2Hex(report.MessageID),
		report.CommitteeID,
		reportData,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to submit aggregated report: %w", err)
	}

	return nil
}
