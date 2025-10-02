package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
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

func (d *DatabaseStorage) batchGetVerificationRecords(ctx context.Context, verificationIDs []int64) (map[int64]*model.CommitVerificationRecord, error) {
	verificationRecordsMap := make(map[int64]*model.CommitVerificationRecord)
	if len(verificationIDs) == 0 {
		return verificationRecordsMap, nil
	}

	verificationStmt := `SELECT id, message_id, committee_id, participant_id, signer_address, 
		source_chain_selector, dest_chain_selector, onramp_address, offramp_address, 
		signature_r, signature_s, ccv_node_data, created_at
		FROM commit_verification_records 
		WHERE id = ANY($1)`

	type dbRecord struct {
		ID                  int64     `db:"id"`
		MessageID           string    `db:"message_id"`
		CommitteeID         string    `db:"committee_id"`
		ParticipantID       string    `db:"participant_id"`
		SignerAddress       string    `db:"signer_address"`
		SourceChainSelector string    `db:"source_chain_selector"`
		DestChainSelector   string    `db:"dest_chain_selector"`
		OnrampAddress       string    `db:"onramp_address"`
		OfframpAddress      string    `db:"offramp_address"`
		SignatureR          []byte    `db:"signature_r"`
		SignatureS          []byte    `db:"signature_s"`
		CCVNodeData         []byte    `db:"ccv_node_data"`
		CreatedAt           time.Time `db:"created_at"`
	}

	var dbRecords []dbRecord
	err := d.ds.SelectContext(ctx, &dbRecords, verificationStmt, pq.Array(verificationIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve verification records: %w", err)
	}

	for _, dbRec := range dbRecords {
		var msgWithCCV pb.MessageWithCCVNodeData
		err = proto.Unmarshal(dbRec.CCVNodeData, &msgWithCCV)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ccv node data: %w", err)
		}

		verification := &model.CommitVerificationRecord{
			MessageWithCCVNodeData: copyMessageWithCCVNodeData(&msgWithCCV),
			IdentifierSigner:       reconstructIdentifierSigner(dbRec.ParticipantID, dbRec.SignerAddress, dbRec.CommitteeID, dbRec.SignatureR, dbRec.SignatureS),
			CommitteeID:            dbRec.CommitteeID,
		}

		verificationRecordsMap[dbRec.ID] = verification
	}

	return verificationRecordsMap, nil
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
	ds sqlutil.DataSource
}

var (
	_ pkgcommon.CommitVerificationStore           = (*DatabaseStorage)(nil)
	_ pkgcommon.CommitVerificationAggregatedStore = (*DatabaseStorage)(nil)
)

func NewDatabaseStorage(ds sqlutil.DataSource) *DatabaseStorage {
	return &DatabaseStorage{
		ds: ds,
	}
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
		 onramp_address, offramp_address, signature_r, signature_s, ccv_node_data, created_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

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

func (d *DatabaseStorage) QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string) ([]*model.CommitAggregatedReport, error) {
	startTime := time.Unix(start, 0)
	endTime := time.Unix(end, 0)

	reportStmt := `SELECT DISTINCT ON (message_id) message_id, committee_id, verification_record_ids, report_data, created_at
		FROM commit_aggregated_reports 
		WHERE committee_id = $1 AND created_at >= $2 AND created_at <= $3
		ORDER BY message_id, seq_num DESC`

	type reportRecord struct {
		MessageID             string        `db:"message_id"`
		CommitteeID           string        `db:"committee_id"`
		VerificationRecordIDs pq.Int64Array `db:"verification_record_ids"`
		ReportData            []byte        `db:"report_data"`
		CreatedAt             time.Time     `db:"created_at"`
	}

	var reportRecords []reportRecord
	err := d.ds.SelectContext(ctx, &reportRecords, reportStmt, committeeID, startTime, endTime)
	if err != nil {
		return []*model.CommitAggregatedReport{}, err
	}

	if len(reportRecords) == 0 {
		return []*model.CommitAggregatedReport{}, nil
	}

	allVerificationIDs := make([]int64, 0)
	for _, record := range reportRecords {
		allVerificationIDs = append(allVerificationIDs, []int64(record.VerificationRecordIDs)...)
	}

	verificationRecordsMap, err := d.batchGetVerificationRecords(ctx, allVerificationIDs)
	if err != nil {
		return nil, err
	}

	reports := make([]*model.CommitAggregatedReport, 0, len(reportRecords))
	for _, record := range reportRecords {
		report := &model.CommitAggregatedReport{
			MessageID:     common.Hex2Bytes(record.MessageID),
			CommitteeID:   record.CommitteeID,
			Verifications: make([]*model.CommitVerificationRecord, 0, len(record.VerificationRecordIDs)),
			Timestamp:     record.CreatedAt.Unix(),
		}

		for _, verificationID := range []int64(record.VerificationRecordIDs) {
			if verification, exists := verificationRecordsMap[verificationID]; exists {
				report.Verifications = append(report.Verifications, verification)
			}
		}

		reports = append(reports, report)
	}

	return reports, nil
}

func (d *DatabaseStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	messageIDHex := common.Bytes2Hex(messageID)

	// Get latest aggregated report
	var reportRecord struct {
		MessageID             string        `db:"message_id"`
		CommitteeID           string        `db:"committee_id"`
		VerificationRecordIDs pq.Int64Array `db:"verification_record_ids"`
		ReportData            []byte        `db:"report_data"`
		CreatedAt             time.Time     `db:"created_at"`
	}

	reportStmt := `SELECT message_id, committee_id, verification_record_ids, report_data, created_at
		FROM commit_aggregated_reports 
		WHERE message_id = $1 AND committee_id = $2
		ORDER BY seq_num DESC LIMIT 1`

	err := d.ds.GetContext(ctx, &reportRecord, reportStmt, messageIDHex, committeeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, err
	}

	report := &model.CommitAggregatedReport{
		MessageID:     common.Hex2Bytes(reportRecord.MessageID),
		CommitteeID:   reportRecord.CommitteeID,
		Verifications: []*model.CommitVerificationRecord{},
		Timestamp:     reportRecord.CreatedAt.Unix(),
	}

	if len(reportRecord.VerificationRecordIDs) > 0 {
		verificationRecordsMap, err := d.batchGetVerificationRecords(ctx, []int64(reportRecord.VerificationRecordIDs))
		if err != nil {
			return nil, err
		}

		for _, verificationID := range []int64(reportRecord.VerificationRecordIDs) {
			if verification, exists := verificationRecordsMap[verificationID]; exists {
				report.Verifications = append(report.Verifications, verification)
			}
		}
	}

	return report, nil
}

func (d *DatabaseStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	if report == nil {
		return fmt.Errorf("aggregated report cannot be nil")
	}

	report.Timestamp = time.Now().Unix()

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

	reportData := []byte(fmt.Sprintf("verification_count:%d", len(report.Verifications)))

	stmt := `INSERT INTO commit_aggregated_reports 
		(message_id, committee_id, verification_record_ids, report_data, created_at) 
		VALUES ($1, $2, $3, $4, $5)`

	now := time.Now()
	_, err = d.ds.ExecContext(ctx, stmt,
		messageIDHex,
		report.CommitteeID,
		pq.Array(verificationRecordIDs),
		reportData,
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to submit aggregated report: %w", err)
	}

	return nil
}
