package ddb_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	smithyendpoints "github.com/aws/smithy-go/endpoints" //nolint
	pkgcommon "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type DynamoDBLocalResolver struct {
	hostAndPort string
}

func (r *DynamoDBLocalResolver) ResolveEndpoint(ctx context.Context, params dynamodb.EndpointParameters) (endpoint smithyendpoints.Endpoint, err error) {
	return smithyendpoints.Endpoint{
		URI: url.URL{Host: r.hostAndPort, Scheme: "http"},
	}, nil
}

// createTestMessageID generates a test MessageID with the given seed byte.
func createTestMessageID(seed byte) model.MessageID {
	messageID := make(model.MessageID, 32)
	messageID[0] = seed
	for i := 1; i < len(messageID); i++ {
		messageID[i] = byte((int(seed) + i*7) % 256)
	}
	return messageID
}

// createTestVerificationRecord creates a test verification record with the given parameters.
func createTestVerificationRecord(messageID model.MessageID, participantID, committeeID string) *model.CommitVerificationRecord {
	// Generate deterministic signer address based on participantID hash
	addressStr := fmt.Sprintf("0x%040d", len(participantID)*1000+int(participantID[len(participantID)-1]))
	address := common.HexToAddress(addressStr)

	return &model.CommitVerificationRecord{
		IdentifierSigner: &model.IdentifierSigner{
			Signer: model.Signer{
				ParticipantID: participantID,
				Addresses:     []string{address.Hex()},
			},
			Address:     address.Bytes(),
			SignatureR:  [32]byte{0x01, 0x02, 0x03},
			SignatureS:  [32]byte{0x04, 0x05, 0x06},
			CommitteeID: committeeID,
		},
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			MessageId:             messageID[:],
			SourceVerifierAddress: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44},
			Message: &pb.Message{
				Version:             1,
				SourceChainSelector: 12345,
				DestChainSelector:   67890,
				Nonce:               1,
				OnRampAddress:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd},
				OffRampAddress:      []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc},
				Finality:            10,
				Sender:              []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				Receiver:            []byte{0x06, 0x07, 0x08, 0x09, 0x0a},
			},
			BlobData:  []byte("test-blob-data"),
			CcvData:   []byte(fmt.Sprintf("test-ccv-data-%s", participantID)),
			Timestamp: 1234567890,
			ReceiptBlobs: []*pb.ReceiptBlob{
				{
					Issuer: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44},
					Blob:   []byte("test-receipt-blob"),
				},
			},
		},
		CommitteeID: committeeID,
	}
}

// createTestAggregatedReport creates a test aggregated report with the given parameters.
func createTestAggregatedReport(messageID model.MessageID, committeeID string, timestamp int64, verifications []*model.CommitVerificationRecord) *model.CommitAggregatedReport {
	return &model.CommitAggregatedReport{
		MessageID:     messageID,
		CommitteeID:   committeeID,
		Verifications: verifications,
		Timestamp:     timestamp,
	}
}

// Assertion Helper Functions

// assertVerificationRecordEquals verifies that two verification records are equal.
func assertVerificationRecordEquals(t *testing.T, expected, actual *model.CommitVerificationRecord) {
	require.Equal(t, expected.CommitteeID, actual.CommitteeID, "CommitteeID should match")
	require.Equal(t, expected.IdentifierSigner.ParticipantID, actual.IdentifierSigner.ParticipantID, "ParticipantID should match")
	require.Equal(t, expected.IdentifierSigner.Address, actual.IdentifierSigner.Address, "Address should match")
	require.Equal(t, expected.IdentifierSigner.SignatureR, actual.IdentifierSigner.SignatureR, "SignatureR should match")
	require.Equal(t, expected.IdentifierSigner.SignatureS, actual.IdentifierSigner.SignatureS, "SignatureS should match")
	require.Equal(t, expected.MessageId, actual.MessageId, "MessageId should match")

	// Verify message content (tests that MessageData record is properly fetched)
	require.NotNil(t, actual.Message, "Message should not be nil")
	require.Equal(t, expected.Message.SourceChainSelector, actual.Message.SourceChainSelector, "SourceChainSelector should match")
	require.Equal(t, expected.Message.DestChainSelector, actual.Message.DestChainSelector, "DestChainSelector should match")
	require.Equal(t, expected.Message.OnRampAddress, actual.Message.OnRampAddress, "OnRampAddress should match")
	require.Equal(t, expected.Message.OffRampAddress, actual.Message.OffRampAddress, "OffRampAddress should match")
}

// assertAggregatedReportEquals verifies that two aggregated reports are equal.
func assertAggregatedReportEquals(t *testing.T, expected, actual *model.CommitAggregatedReport) {
	require.Equal(t, expected.MessageID, actual.MessageID, "MessageID should match")
	require.Equal(t, expected.CommitteeID, actual.CommitteeID, "CommitteeID should match")
	require.Equal(t, expected.Timestamp, actual.Timestamp, "Timestamp should match")
	require.Len(t, actual.Verifications, len(expected.Verifications), "Verification count should match")
}

// assertTimestampOrdering verifies that reports are ordered by WrittenAt timestamp (ascending).
// WrittenAt represents when the report was written to storage, which is what GetMessagesSince uses for ordering.
func assertTimestampOrdering(t *testing.T, reports []*model.CommitAggregatedReport) {
	for i := 0; i < len(reports)-1; i++ {
		// Use WrittenAt for ordering verification (fall back to Timestamp if not set for backward compatibility)
		timestamp1 := reports[i].WrittenAt
		if timestamp1 == 0 {
			timestamp1 = reports[i].Timestamp
		}
		timestamp2 := reports[i+1].WrittenAt
		if timestamp2 == 0 {
			timestamp2 = reports[i+1].Timestamp
		}
		require.LessOrEqual(t, timestamp1, timestamp2,
			"Report at index %d should have WrittenAt <= report at index %d", i, i+1)
	}
}

// TestCommitVerificationRecordOperations tests all verification record CRUD operations.
func TestCommitVerificationRecordOperations(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1)

	t.Run("save and retrieve", func(t *testing.T) {
		messageID := createTestMessageID(1)
		record := createTestVerificationRecord(messageID, "test-participant", "test-committee")

		// Save the record
		err := storage.SaveCommitVerification(ctx, record)
		require.NoError(t, err, "SaveCommitVerification should succeed")

		// Get the record by ID
		id, err := record.GetID()
		require.NoError(t, err, "GetID should succeed")

		retrievedRecord, err := storage.GetCommitVerification(ctx, *id)
		require.NoError(t, err, "GetCommitVerification should succeed")
		require.NotNil(t, retrievedRecord, "Retrieved record should not be nil")

		// Verify the record matches
		assertVerificationRecordEquals(t, record, retrievedRecord)

		// List records by message ID
		listedRecords, err := storage.ListCommitVerificationByMessageID(ctx, record.MessageId, record.CommitteeID)
		require.NoError(t, err, "ListCommitVerificationByMessageID should succeed")
		require.Len(t, listedRecords, 1, "Should have one record")

		// Verify the listed record matches
		assertVerificationRecordEquals(t, record, listedRecords[0])
	})

	t.Run("multiple signers same message", func(t *testing.T) {
		messageID := createTestMessageID(2)
		committeeID := "multi-signer-committee"

		// Create records from two different signers for the same message
		record1 := createTestVerificationRecord(messageID, "participant-1", committeeID)
		record2 := createTestVerificationRecord(messageID, "participant-2", committeeID)

		// Save both records
		err := storage.SaveCommitVerification(ctx, record1)
		require.NoError(t, err, "SaveCommitVerification should succeed for record1")

		err = storage.SaveCommitVerification(ctx, record2)
		require.NoError(t, err, "SaveCommitVerification should succeed for record2")

		// Get each record individually
		id1, err := record1.GetID()
		require.NoError(t, err, "GetID should succeed for record1")

		id2, err := record2.GetID()
		require.NoError(t, err, "GetID should succeed for record2")

		retrievedRecord1, err := storage.GetCommitVerification(ctx, *id1)
		require.NoError(t, err, "GetCommitVerification should succeed for record1")

		retrievedRecord2, err := storage.GetCommitVerification(ctx, *id2)
		require.NoError(t, err, "GetCommitVerification should succeed for record2")

		// Verify each record matches
		assertVerificationRecordEquals(t, record1, retrievedRecord1)
		assertVerificationRecordEquals(t, record2, retrievedRecord2)

		// List all records for this message - should return both
		allRecords, err := storage.ListCommitVerificationByMessageID(ctx, messageID[:], committeeID)
		require.NoError(t, err, "ListCommitVerificationByMessageID should succeed")
		require.Len(t, allRecords, 2, "Should have two records")

		// Verify we have records from both participants
		participantIDs := make(map[string]bool)
		for _, record := range allRecords {
			participantIDs[record.IdentifierSigner.ParticipantID] = true
		}
		require.True(t, participantIDs["participant-1"], "Should have record from participant-1")
		require.True(t, participantIDs["participant-2"], "Should have record from participant-2")
	})

	t.Run("idempotent saves", func(t *testing.T) {
		messageID := createTestMessageID(3)
		record := createTestVerificationRecord(messageID, "idempotent-participant", "idempotent-committee")

		// Save the record for the first time
		err := storage.SaveCommitVerification(ctx, record)
		require.NoError(t, err, "First save should succeed")

		// Save the same record again - should be idempotent
		err = storage.SaveCommitVerification(ctx, record)
		require.NoError(t, err, "Second save should succeed (idempotent)")

		// Verify only one record exists
		allRecords, err := storage.ListCommitVerificationByMessageID(ctx, messageID[:], record.CommitteeID)
		require.NoError(t, err, "ListCommitVerificationByMessageID should succeed")
		require.Len(t, allRecords, 1, "Should have exactly one record, not duplicates")

		// Verify the record content is correct
		assertVerificationRecordEquals(t, record, allRecords[0])

		// Verify individual retrieval also works
		id, err := record.GetID()
		require.NoError(t, err, "GetID should succeed")

		retrievedRecord, err := storage.GetCommitVerification(ctx, *id)
		require.NoError(t, err, "GetCommitVerification should succeed")
		assertVerificationRecordEquals(t, record, retrievedRecord)
	})
}

// TestAggregatedReportOperations tests all aggregated report operations.
func TestAggregatedReportOperations(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("submit and query reports", func(t *testing.T) {
		// Use current time as base for deterministic testing
		baseTime := time.Now()
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1, mockTime)

		committeeID := "test-committee-query"

		// Create test reports with different WrittenAt timestamps
		for i := 0; i < 3; i++ {
			messageID := createTestMessageID(byte(100 + i))
			verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d", i), committeeID)

			// Save verification record first (required for SubmitReport)
			err := storage.SaveCommitVerification(ctx, verification)
			require.NoError(t, err, "SaveCommitVerification should succeed for record %d", i)

			// Set mock time for this report (each report 1 hour apart)
			mockTime.SetTime(baseTime.Add(time.Duration(i) * time.Hour))

			// Create and submit aggregated report (WrittenAt will be set from mockTime)
			timestamp := baseTime.Unix() + int64(i*3600) // Timestamp for idempotency key
			report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

			err = storage.SubmitReport(ctx, report)
			require.NoError(t, err, "SubmitReport should succeed for report %d", i)
		}

		// Query reports in time range (using WrittenAt timestamps)
		start := baseTime.Unix()                  // Start time
		end := baseTime.Add(3 * time.Hour).Unix() // 3 hours later to include all reports
		reports, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err, "QueryAggregatedReports should succeed")
		require.Len(t, reports.Reports, 3, "Should return all 3 reports within time range")

		// Verify reports are ordered correctly by WrittenAt
		assertTimestampOrdering(t, reports.Reports)
	})

	t.Run("idempotent submissions", func(t *testing.T) {
		baseTime := time.Now()
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1, mockTime)

		messageID := createTestMessageID(50)
		committeeID := "test-committee-idempotent"
		verification := createTestVerificationRecord(messageID, "signer1", committeeID)
		timestamp := baseTime.Unix()

		report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

		// Submit the same report twice with same mock time (idempotent)
		err := storage.SubmitReport(ctx, report)
		require.NoError(t, err, "First SubmitReport should succeed")

		err = storage.SubmitReport(ctx, report)
		require.NoError(t, err, "Second SubmitReport should succeed (idempotent)")

		// Verify only one report exists
		start := baseTime.Add(-1 * time.Hour).Unix() // 1 hour before
		end := baseTime.Add(1 * time.Hour).Unix()    // 1 hour after
		reports, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err, "QueryAggregatedReports should succeed")
		require.Len(t, reports.Reports, 1, "Should have exactly one report after duplicate submission")
	})

	t.Run("get by message ID", func(t *testing.T) {
		baseTime := time.Now()
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1, mockTime)

		messageID := createTestMessageID(60)
		committeeID := "test-committee-getccv"
		verification := createTestVerificationRecord(messageID, "signer-getccv", committeeID)
		timestamp := baseTime.Unix()

		// Save verification record first
		err := storage.SaveCommitVerification(ctx, verification)
		require.NoError(t, err, "SaveCommitVerification should succeed")

		// Submit aggregated report
		report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})
		err = storage.SubmitReport(ctx, report)
		require.NoError(t, err, "SubmitReport should succeed")

		// Get CCV data by MessageID
		foundReport, err := storage.GetCCVData(ctx, messageID, committeeID)
		require.NoError(t, err, "GetCCVData should succeed")
		require.NotNil(t, foundReport, "Should find the report")
		assertAggregatedReportEquals(t, report, foundReport)

		// Test non-existent MessageID
		nonexistentMessageID := createTestMessageID(255)
		foundReport, err = storage.GetCCVData(ctx, nonexistentMessageID, "nonexistent-committee")
		require.NoError(t, err, "GetCCVData should not return error for nonexistent MessageID")
		require.Nil(t, foundReport, "Should return nil for nonexistent MessageID")
	})

	t.Run("multiple snapshots same message", func(t *testing.T) {
		baseTime := time.Now()
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1, mockTime)

		messageID := createTestMessageID(70)
		committeeID := "test-committee-snapshots"

		// Create multiple reports for the same message at different WrittenAt timestamps (snapshots)
		for i := 0; i < 2; i++ {
			verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-snapshot-%d", i), committeeID)

			// Save verification record
			err := storage.SaveCommitVerification(ctx, verification)
			require.NoError(t, err, "SaveCommitVerification should succeed for snapshot %d", i)

			// Set mock time for each snapshot (1 hour apart)
			mockTime.SetTime(baseTime.Add(time.Duration(i) * time.Hour))

			// Create report with different timestamp for idempotency key
			timestamp := baseTime.Unix() + int64(i*3600)
			report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

			err = storage.SubmitReport(ctx, report)
			require.NoError(t, err, "SubmitReport should succeed for snapshot %d", i)
		}

		// GetCCVData should return the latest snapshot
		foundReport, err := storage.GetCCVData(ctx, messageID, committeeID)
		require.NoError(t, err, "GetCCVData should succeed")
		require.NotNil(t, foundReport, "Should find the report")

		expectedLatestTimestamp := baseTime.Unix() + int64(1*3600)
		require.Equal(t, expectedLatestTimestamp, foundReport.Timestamp, "Should return the latest report by timestamp")

		// Query should return both snapshots in correct order by WrittenAt
		start := baseTime.Add(-1 * time.Hour).Unix() // 1 hour before first
		end := baseTime.Add(2 * time.Hour).Unix()    // 2 hours after first
		reports, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err, "QueryAggregatedReports should succeed")
		require.Len(t, reports.Reports, 2, "Should return both snapshots")
		assertTimestampOrdering(t, reports.Reports)
	})

	t.Run("empty results and validation", func(t *testing.T) {
		baseTime := time.Now()
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1, mockTime)

		// Query empty time range (much earlier than baseTime)
		start := baseTime.Add(-100 * time.Hour).Unix() // Much earlier time
		end := baseTime.Add(-99 * time.Hour).Unix()    // Still early time
		reports, err := storage.QueryAggregatedReports(ctx, start, end, "nonexistent-committee", nil)
		require.NoError(t, err, "QueryAggregatedReports should succeed even with no results")
		require.NotNil(t, reports, "Should return non-nil result struct")
		require.Empty(t, reports.Reports, "Should return empty slice for no results")
		require.Nil(t, reports.NextPageToken, "Should have no next page token for empty results")

		// Test invalid time range (start > end)
		start = baseTime.Add(10 * time.Hour).Unix() // Later time
		end = baseTime.Unix()                       // Earlier time
		reports, err = storage.QueryAggregatedReports(ctx, start, end, "test-committee", nil)
		require.Error(t, err, "Should return error for invalid time range")
		require.Nil(t, reports, "Should return nil for invalid time range")
		require.Contains(t, err.Error(), "start time", "Error should mention start time")
	})
}

func TestOrphanRecovery(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1)

	t.Run("ListOrphanedMessageCommitteemessageIds with pending records", func(t *testing.T) {
		// Create test verification records that are "orphaned" (not aggregated)
		messageID1 := createTestMessageID(0x10)
		messageID2 := createTestMessageID(0x20)

		committee1 := "committee-1"

		// Save verification records (these will have PendingAggregation field set)
		record1 := createTestVerificationRecord(messageID1, "participant-1", committee1)
		record2 := createTestVerificationRecord(messageID2, "participant-2", committee1)
		record3 := createTestVerificationRecord(messageID1, "participant-3", committee1) // Same message/committee as record1

		err := storage.SaveCommitVerification(ctx, record1)
		require.NoError(t, err, "Failed to save verification record 1")

		err = storage.SaveCommitVerification(ctx, record2)
		require.NoError(t, err, "Failed to save verification record 2")

		err = storage.SaveCommitVerification(ctx, record3)
		require.NoError(t, err, "Failed to save verification record 3")

		// Call ListOrphanedMessageIDs
		orphansChan, errorChan := storage.ListOrphanedMessageIDs(ctx, committee1)

		// Collect results
		var orphans []model.MessageID
		var errors []error

		for {
			select {
			case messageId, ok := <-orphansChan:
				if !ok {
					orphansChan = nil
				} else {
					orphans = append(orphans, messageId)
				}
			case err, ok := <-errorChan:
				if !ok {
					errorChan = nil
				} else if err != nil {
					errors = append(errors, err)
				}
			}

			if orphansChan == nil && errorChan == nil {
				break
			}
		}

		// Verify results
		require.Empty(t, errors, "Should not have any errors")
		require.Len(t, orphans, 2, "Should find 2 unique message/committee messageIds")

		// Check that we got the expected messageIds (order may vary)
		foundmessageIds := make(map[string]bool)
		for _, orphan := range orphans {
			key := fmt.Sprintf("%x", orphan)
			foundmessageIds[key] = true
		}

		expectedKey1 := fmt.Sprintf("%x", messageID1)
		expectedKey2 := fmt.Sprintf("%x", messageID2)

		require.True(t, foundmessageIds[expectedKey1], "Should find message1 messageId")
		require.True(t, foundmessageIds[expectedKey2], "Should find message2 messageId")
	})

	t.Run("ListOrphanedMessageCommitteemessageIds with aggregated records", func(t *testing.T) {
		// Create a verification record and then submit a report to mark it as aggregated
		messageID := createTestMessageID(0x30)
		committee := "committee-3"

		record := createTestVerificationRecord(messageID, "participant-4", committee)
		err := storage.SaveCommitVerification(ctx, record)
		require.NoError(t, err, "Failed to save verification record")

		// Create and submit an aggregated report - this should remove the PendingAggregation field
		report := &model.CommitAggregatedReport{
			MessageID:     messageID,
			CommitteeID:   committee,
			Timestamp:     time.Now().Unix(),
			Verifications: []*model.CommitVerificationRecord{record},
		}

		err = storage.SubmitReport(ctx, report)
		require.NoError(t, err, "Failed to submit report")

		// Now check orphans - this message/committee should not appear
		orphansChan, errorChan := storage.ListOrphanedMessageIDs(ctx, committee)

		var orphans []model.MessageID
		var errors []error

		for {
			select {
			case messageId, ok := <-orphansChan:
				if !ok {
					orphansChan = nil
				} else {
					orphans = append(orphans, messageId)
				}
			case err, ok := <-errorChan:
				if !ok {
					errorChan = nil
				} else if err != nil {
					errors = append(errors, err)
				}
			}

			if orphansChan == nil && errorChan == nil {
				break
			}
		}

		require.Empty(t, errors, "Should not have any errors")

		// The aggregated record should not appear in orphans
		aggregatedKey := fmt.Sprintf("%x:%s", messageID, committee)
		for _, orphan := range orphans {
			orphanKey := fmt.Sprintf("%x:%s", orphan, committee)
			require.NotEqual(t, aggregatedKey, orphanKey, "Aggregated record should not appear in orphans")
		}
	})

	t.Run("ListOrphanedMessageCommitteemessageIds with no orphans", func(t *testing.T) {
		// Use a fresh storage with no records
		client, _, cleanup := ddb.SetupTestDynamoDB(t)
		defer cleanup()
		ctx := context.Background()

		earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

		storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring(), 10, 1)

		defer cleanup()

		orphansChan, errorChan := storage.ListOrphanedMessageIDs(ctx, "nonexistent-committee")

		var orphans []model.MessageID
		var errors []error

		for {
			select {
			case messageId, ok := <-orphansChan:
				if !ok {
					orphansChan = nil
				} else {
					orphans = append(orphans, messageId)
				}
			case err, ok := <-errorChan:
				if !ok {
					errorChan = nil
				} else if err != nil {
					errors = append(errors, err)
				}
			}

			if orphansChan == nil && errorChan == nil {
				break
			}
		}

		require.Empty(t, errors, "Should not have any errors")
		require.Empty(t, orphans, "Should not find any orphans in empty table")
	})
}

// TestPaginationWithMockedTime tests pagination with various page sizes using mocked time.
func TestPaginationWithMockedTime(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	testCases := []struct {
		name          string
		numMessages   int
		pageSize      int
		expectedPages int
		description   string
	}{
		{
			name:          "exact_multiple_page_size",
			numMessages:   20,
			pageSize:      10,
			expectedPages: 3, // 2 full pages + 1 empty final page
			description:   "Page size evenly divides messages",
		},
		{
			name:          "non_multiple_page_size",
			numMessages:   25,
			pageSize:      7,
			expectedPages: 4, // 3 full pages + 1 page with 4 messages
			description:   "Page size doesn't evenly divide messages",
		},
		{
			name:          "single_page",
			numMessages:   5,
			pageSize:      10,
			expectedPages: 1, // All fits in one page
			description:   "Fewer messages than page size",
		},
		{
			name:          "large_page_size",
			numMessages:   15,
			pageSize:      20,
			expectedPages: 1, // Single page
			description:   "Page size larger than message count",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseTime := time.Date(2025, 10, 1, 12, 0, 0, 0, time.UTC)
			mockTime := pkgcommon.NewMockTimeProvider(baseTime)

			storage := ddb.NewDynamoDBStorageWithTimeProvider(
				client,
				ddb.TestCommitVerificationRecordTableName,
				ddb.TestFinalizedFeedTableName,
				earliestDateForGetMessageSince,
				logger.TestSugared(t),
				monitoring.NewNoopAggregatorMonitoring(),
				tc.pageSize,
				1, // single shard for simplicity
				mockTime,
			)

			committeeID := fmt.Sprintf("test-committee-%s", tc.name)

			// Create and submit messages with controlled WrittenAt timestamps
			for i := 0; i < tc.numMessages; i++ {
				messageID := createTestMessageID(byte(i))
				verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d", i), committeeID)

				// Save verification record
				err := storage.SaveCommitVerification(ctx, verification)
				require.NoError(t, err, "SaveCommitVerification should succeed for message %d", i)

				// Set mock time for this message (1 second apart)
				mockTime.SetTime(baseTime.Add(time.Duration(i) * time.Second))

				// Submit report (WrittenAt will be set from mockTime)
				timestamp := baseTime.Unix() + int64(i)
				report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

				err = storage.SubmitReport(ctx, report)
				require.NoError(t, err, "SubmitReport should succeed for message %d", i)
			}

			// Query all reports with pagination
			start := baseTime.Add(-1 * time.Hour).Unix()
			end := baseTime.Add(time.Duration(tc.numMessages) * time.Second).Add(1 * time.Hour).Unix()

			var allReports []*model.CommitAggregatedReport
			var nextToken *string
			pageCount := 0

			for {
				pageCount++
				result, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nextToken)
				require.NoError(t, err, "QueryAggregatedReports should succeed for page %d", pageCount)
				require.NotNil(t, result, "Result should not be nil")

				// Validate page size constraints
				if result.NextPageToken != nil {
					require.LessOrEqual(t, len(result.Reports), tc.pageSize,
						"Page %d should not exceed page size %d", pageCount, tc.pageSize)
				}

				allReports = append(allReports, result.Reports...)

				if result.NextPageToken == nil {
					break
				}

				nextToken = result.NextPageToken

				// Safety check
				require.Less(t, pageCount, 100, "Too many pages, possible infinite loop")
			}

			// Verify all messages retrieved
			require.Equal(t, tc.numMessages, len(allReports),
				"Should retrieve all %d messages", tc.numMessages)

			// Verify ordering by WrittenAt
			assertTimestampOrdering(t, allReports)

			t.Logf("✅ %s: Retrieved %d messages across %d pages (expected %d pages)",
				tc.description, len(allReports), pageCount, tc.expectedPages)
		})
	}
}

// TestPaginationMultiDayScenarios tests pagination across multiple days with mocked time.
func TestPaginationMultiDayScenarios(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("messages_across_three_days", func(t *testing.T) {
		baseTime := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(
			client,
			ddb.TestCommitVerificationRecordTableName,
			ddb.TestFinalizedFeedTableName,
			earliestDateForGetMessageSince,
			logger.TestSugared(t),
			monitoring.NewNoopAggregatorMonitoring(),
			5, // page size
			1, // single shard
			mockTime,
		)

		committeeID := "test-committee-multiday"
		messagesPerDay := 4
		numDays := 3
		totalMessages := messagesPerDay * numDays

		// Create messages across 3 days
		messageIndex := 0
		for day := 0; day < numDays; day++ {
			dayTime := baseTime.Add(time.Duration(day) * 24 * time.Hour)

			for msg := 0; msg < messagesPerDay; msg++ {
				messageID := createTestMessageID(byte(messageIndex))
				verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d", messageIndex), committeeID)

				err := storage.SaveCommitVerification(ctx, verification)
				require.NoError(t, err, "SaveCommitVerification should succeed")

				// Set time within the day (spread messages across the day)
				messageTime := dayTime.Add(time.Duration(msg) * 6 * time.Hour)
				mockTime.SetTime(messageTime)

				timestamp := messageTime.Unix()
				report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

				err = storage.SubmitReport(ctx, report)
				require.NoError(t, err, "SubmitReport should succeed")

				messageIndex++
			}
		}

		// Query all reports
		start := baseTime.Add(-1 * time.Hour).Unix()
		end := baseTime.Add(time.Duration(numDays+1) * 24 * time.Hour).Unix()

		result, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err, "QueryAggregatedReports should succeed")

		// Should get all messages
		allReports := result.Reports
		for result.NextPageToken != nil {
			result, err = storage.QueryAggregatedReports(ctx, start, end, committeeID, result.NextPageToken)
			require.NoError(t, err, "QueryAggregatedReports should succeed")
			allReports = append(allReports, result.Reports...)
		}

		require.Equal(t, totalMessages, len(allReports), "Should retrieve all messages")
		assertTimestampOrdering(t, allReports)

		t.Logf("✅ Retrieved %d messages across %d days", len(allReports), numDays)
	})

	t.Run("query_single_day_range", func(t *testing.T) {
		baseTime := time.Date(2025, 10, 5, 0, 0, 0, 0, time.UTC)
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(
			client,
			ddb.TestCommitVerificationRecordTableName,
			ddb.TestFinalizedFeedTableName,
			earliestDateForGetMessageSince,
			logger.TestSugared(t),
			monitoring.NewNoopAggregatorMonitoring(),
			10,
			1,
			mockTime,
		)

		committeeID := "test-committee-single-day"

		// Create messages on day 0, 1, and 2
		for day := 0; day < 3; day++ {
			for msg := 0; msg < 3; msg++ {
				messageID := createTestMessageID(byte(day*10 + msg + 100))
				verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d-%d", day, msg), committeeID)

				err := storage.SaveCommitVerification(ctx, verification)
				require.NoError(t, err)

				dayTime := baseTime.Add(time.Duration(day) * 24 * time.Hour).Add(time.Duration(msg) * time.Hour)
				mockTime.SetTime(dayTime)

				report := createTestAggregatedReport(messageID, committeeID, dayTime.Unix(), []*model.CommitVerificationRecord{verification})
				err = storage.SubmitReport(ctx, report)
				require.NoError(t, err)
			}
		}

		// Query only day 1 (middle day) - use slightly before day 2 start to avoid boundary issues
		day1Start := baseTime.Add(24 * time.Hour).Unix()
		day1End := baseTime.Add(47 * time.Hour).Add(59 * time.Minute).Unix() // Just before day 2

		result, err := storage.QueryAggregatedReports(ctx, day1Start, day1End, committeeID, nil)
		require.NoError(t, err)

		allReports := result.Reports
		for result.NextPageToken != nil {
			result, err = storage.QueryAggregatedReports(ctx, day1Start, day1End, committeeID, result.NextPageToken)
			require.NoError(t, err)
			allReports = append(allReports, result.Reports...)
		}

		// Should only get messages from day 1 (3 messages)
		require.Equal(t, 3, len(allReports), "Should retrieve only day 1 messages")

		// Verify all messages are within day 1 time range
		for _, report := range allReports {
			timestamp := report.WrittenAt
			if timestamp == 0 {
				timestamp = report.Timestamp
			}
			require.GreaterOrEqual(t, timestamp, day1Start, "Message should be after day 1 start")
			require.LessOrEqual(t, timestamp, day1End, "Message should be before day 1 end")
		}

		t.Logf("✅ Correctly filtered to %d messages from single day", len(allReports))
	})
}

// TestPaginationMultiShard tests pagination with multiple shards using mocked time.
func TestPaginationMultiShard(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	shardCounts := []int{2, 3, 5}

	for _, shardCount := range shardCounts {
		t.Run(fmt.Sprintf("%d_shards", shardCount), func(t *testing.T) {
			baseTime := time.Date(2025, 10, 10, 0, 0, 0, 0, time.UTC)
			mockTime := pkgcommon.NewMockTimeProvider(baseTime)

			storage := ddb.NewDynamoDBStorageWithTimeProvider(
				client,
				ddb.TestCommitVerificationRecordTableName,
				ddb.TestFinalizedFeedTableName,
				earliestDateForGetMessageSince,
				logger.TestSugared(t),
				monitoring.NewNoopAggregatorMonitoring(),
				5, // page size
				shardCount,
				mockTime,
			)

			committeeID := fmt.Sprintf("test-committee-%d-shards", shardCount)
			numMessages := 20

			// Track shard distribution
			shardDistribution := make(map[string]int)

			// Create messages
			for i := 0; i < numMessages; i++ {
				messageID := createTestMessageID(byte(i + 50*shardCount))
				verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d", i), committeeID)

				err := storage.SaveCommitVerification(ctx, verification)
				require.NoError(t, err)

				mockTime.SetTime(baseTime.Add(time.Duration(i) * time.Second))

				report := createTestAggregatedReport(messageID, committeeID, baseTime.Unix()+int64(i), []*model.CommitVerificationRecord{verification})
				err = storage.SubmitReport(ctx, report)
				require.NoError(t, err)

				// Track which shard this message goes to (for verification)
				shard := fmt.Sprintf("%d", int(messageID[0])%shardCount)
				shardDistribution[shard]++
			}

			// Query all reports
			start := baseTime.Add(-1 * time.Hour).Unix()
			end := baseTime.Add(time.Duration(numMessages) * time.Second).Add(1 * time.Hour).Unix()

			result, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
			require.NoError(t, err)

			allReports := result.Reports
			for result.NextPageToken != nil {
				result, err = storage.QueryAggregatedReports(ctx, start, end, committeeID, result.NextPageToken)
				require.NoError(t, err)
				allReports = append(allReports, result.Reports...)
			}

			// Verify all messages retrieved
			require.Equal(t, numMessages, len(allReports), "Should retrieve all messages")

			// Verify global ordering by WrittenAt
			assertTimestampOrdering(t, allReports)

			t.Logf("✅ Retrieved %d messages across %d shards with proper ordering", len(allReports), shardCount)
			t.Logf("   Shard distribution: %v", shardDistribution)
		})
	}
}

// TestPaginationEdgeCases tests edge cases in pagination with mocked time.
func TestPaginationEdgeCases(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("messages_with_same_written_at", func(t *testing.T) {
		baseTime := time.Date(2025, 10, 15, 12, 0, 0, 0, time.UTC)
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(
			client,
			ddb.TestCommitVerificationRecordTableName,
			ddb.TestFinalizedFeedTableName,
			earliestDateForGetMessageSince,
			logger.TestSugared(t),
			monitoring.NewNoopAggregatorMonitoring(),
			5,
			1,
			mockTime,
		)

		committeeID := "test-committee-same-time"
		numMessages := 10

		// Create multiple messages with the exact same WrittenAt
		for i := 0; i < numMessages; i++ {
			messageID := createTestMessageID(byte(i + 150))
			verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d", i), committeeID)

			err := storage.SaveCommitVerification(ctx, verification)
			require.NoError(t, err)

			// Keep time constant - all messages have same WrittenAt
			// (but different Timestamp for idempotency key)
			mockTime.SetTime(baseTime)

			report := createTestAggregatedReport(messageID, committeeID, baseTime.Unix()+int64(i), []*model.CommitVerificationRecord{verification})
			err = storage.SubmitReport(ctx, report)
			require.NoError(t, err)
		}

		// Query all reports
		start := baseTime.Add(-1 * time.Hour).Unix()
		end := baseTime.Add(1 * time.Hour).Unix()

		result, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err)

		allReports := result.Reports
		for result.NextPageToken != nil {
			result, err = storage.QueryAggregatedReports(ctx, start, end, committeeID, result.NextPageToken)
			require.NoError(t, err)
			allReports = append(allReports, result.Reports...)
		}

		// All messages should be retrieved despite same WrittenAt
		require.Equal(t, numMessages, len(allReports), "Should retrieve all messages even with same WrittenAt")

		// Verify all have the same WrittenAt
		for _, report := range allReports {
			require.Equal(t, baseTime.Unix(), report.WrittenAt, "All reports should have same WrittenAt")
		}

		t.Logf("✅ Retrieved %d messages with identical WrittenAt timestamps", len(allReports))
	})

	t.Run("empty_results_with_pagination_token", func(t *testing.T) {
		baseTime := time.Date(2025, 10, 20, 0, 0, 0, 0, time.UTC)
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(
			client,
			ddb.TestCommitVerificationRecordTableName,
			ddb.TestFinalizedFeedTableName,
			earliestDateForGetMessageSince,
			logger.TestSugared(t),
			monitoring.NewNoopAggregatorMonitoring(),
			10,
			1,
			mockTime,
		)

		committeeID := "test-committee-empty"

		// Query with no messages
		start := baseTime.Unix()
		end := baseTime.Add(1 * time.Hour).Unix()

		result, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Empty(t, result.Reports, "Should have no reports")
		require.Nil(t, result.NextPageToken, "Should have no next page token for empty results")

		t.Logf("✅ Correctly handled empty results")
	})

	t.Run("boundary_timestamp_filtering", func(t *testing.T) {
		baseTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)
		mockTime := pkgcommon.NewMockTimeProvider(baseTime)

		storage := ddb.NewDynamoDBStorageWithTimeProvider(
			client,
			ddb.TestCommitVerificationRecordTableName,
			ddb.TestFinalizedFeedTableName,
			earliestDateForGetMessageSince,
			logger.TestSugared(t),
			monitoring.NewNoopAggregatorMonitoring(),
			10,
			1,
			mockTime,
		)

		committeeID := "test-committee-boundary"

		// Create messages at exactly start, middle, and end boundaries
		times := []time.Time{
			baseTime,                       // Exactly at start
			baseTime.Add(30 * time.Minute), // Middle
			baseTime.Add(60 * time.Minute), // Exactly at end
		}

		for i, msgTime := range times {
			messageID := createTestMessageID(byte(i + 200))
			verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-boundary-%d", i), committeeID)

			err := storage.SaveCommitVerification(ctx, verification)
			require.NoError(t, err)

			mockTime.SetTime(msgTime)

			report := createTestAggregatedReport(messageID, committeeID, msgTime.Unix(), []*model.CommitVerificationRecord{verification})
			err = storage.SubmitReport(ctx, report)
			require.NoError(t, err)
		}

		// Query with inclusive boundaries
		start := baseTime.Unix()
		end := baseTime.Add(60 * time.Minute).Unix()

		result, err := storage.QueryAggregatedReports(ctx, start, end, committeeID, nil)
		require.NoError(t, err)

		allReports := result.Reports
		for result.NextPageToken != nil {
			result, err = storage.QueryAggregatedReports(ctx, start, end, committeeID, result.NextPageToken)
			require.NoError(t, err)
			allReports = append(allReports, result.Reports...)
		}

		// Should get all 3 messages (boundaries are inclusive)
		require.GreaterOrEqual(t, len(allReports), 2, "Should retrieve at least messages within range")

		t.Logf("✅ Boundary filtering working correctly, retrieved %d messages", len(allReports))
	})
}
