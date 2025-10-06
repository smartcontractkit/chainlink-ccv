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

	smithyendpoints "github.com/aws/smithy-go/endpoints" //nolint:goimports
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

// assertTimestampOrdering verifies that reports are ordered by timestamp (ascending).
func assertTimestampOrdering(t *testing.T, reports []*model.CommitAggregatedReport) {
	for i := 0; i < len(reports)-1; i++ {
		require.LessOrEqual(t, reports[i].Timestamp, reports[i+1].Timestamp,
			"Report at index %d should have timestamp <= report at index %d", i, i+1)
	}
}

// TestCommitVerificationRecordOperations tests all verification record CRUD operations.
func TestCommitVerificationRecordOperations(t *testing.T) {
	client, _, cleanup := ddb.SetupTestDynamoDB(t)
	defer cleanup()
	ctx := context.Background()

	earliestDateForGetMessageSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring())

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

	storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring())

	t.Run("submit and query reports", func(t *testing.T) {
		baseTime := int64(1704067200) // 2024-01-01 00:00:00 UTC in seconds
		committeeID := "test-committee-query"

		// Create test reports with different timestamps
		for i := 0; i < 3; i++ {
			messageID := createTestMessageID(byte(100 + i))
			verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-%d", i), committeeID)

			// Save verification record first (required for SubmitReport)
			err := storage.SaveCommitVerification(ctx, verification)
			require.NoError(t, err, "SaveCommitVerification should succeed for record %d", i)

			// Create and submit aggregated report
			timestamp := baseTime + int64(i*3600) // each report 1 hour apart in seconds
			report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

			err = storage.SubmitReport(ctx, report)
			require.NoError(t, err, "SubmitReport should succeed for report %d", i)
		}

		// Query reports in time range (using seconds for API)
		start := baseTime          // Start time in seconds
		end := start + int64(7200) // 2 hours later in seconds
		reports, err := storage.QueryAggregatedReports(ctx, start, end, committeeID)
		require.NoError(t, err, "QueryAggregatedReports should succeed")
		require.Len(t, reports, 3, "Should return all 3 reports within time range")

		// Verify reports are ordered correctly
		assertTimestampOrdering(t, reports)
	})

	t.Run("idempotent submissions", func(t *testing.T) {
		messageID := createTestMessageID(50)
		committeeID := "test-committee-idempotent"
		verification := createTestVerificationRecord(messageID, "signer1", committeeID)
		timestamp := int64(1704067200) // Seconds timestamp

		report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

		// Submit the same report twice
		err := storage.SubmitReport(ctx, report)
		require.NoError(t, err, "First SubmitReport should succeed")

		err = storage.SubmitReport(ctx, report)
		require.NoError(t, err, "Second SubmitReport should succeed (idempotent)")

		// Verify only one report exists (using seconds for API)
		start := timestamp - int64(3600) // 1 hour before in seconds
		end := timestamp + int64(3600)   // 1 hour after in seconds
		reports, err := storage.QueryAggregatedReports(ctx, start, end, committeeID)
		require.NoError(t, err, "QueryAggregatedReports should succeed")
		require.Len(t, reports, 1, "Should have exactly one report after duplicate submission")
	})

	t.Run("get by message ID", func(t *testing.T) {
		messageID := createTestMessageID(60)
		committeeID := "test-committee-getccv"
		verification := createTestVerificationRecord(messageID, "signer-getccv", committeeID)
		timestamp := int64(1704067200)

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
		messageID := createTestMessageID(70)
		committeeID := "test-committee-snapshots"
		baseTime := int64(1704067200) // Seconds timestamp

		// Create multiple reports for the same message at different timestamps (snapshots)
		for i := 0; i < 2; i++ {
			verification := createTestVerificationRecord(messageID, fmt.Sprintf("signer-snapshot-%d", i), committeeID)

			// Save verification record
			err := storage.SaveCommitVerification(ctx, verification)
			require.NoError(t, err, "SaveCommitVerification should succeed for snapshot %d", i)

			// Create report with different timestamp
			timestamp := baseTime + int64(i*3600) // 1 hour apart in seconds
			report := createTestAggregatedReport(messageID, committeeID, timestamp, []*model.CommitVerificationRecord{verification})

			err = storage.SubmitReport(ctx, report)
			require.NoError(t, err, "SubmitReport should succeed for snapshot %d", i)
		}

		// GetCCVData should return the latest snapshot
		foundReport, err := storage.GetCCVData(ctx, messageID, committeeID)
		require.NoError(t, err, "GetCCVData should succeed")
		require.NotNil(t, foundReport, "Should find the report")

		expectedLatestTimestamp := baseTime + int64(1*3600) // Seconds timestamp
		require.Equal(t, expectedLatestTimestamp, foundReport.Timestamp, "Should return the latest report by timestamp")

		// Query should return both snapshots in correct order (using seconds for API)
		start := baseTime - int64(3600) // 1 hour before first in seconds
		end := baseTime + int64(7200)   // 2 hours after first in seconds
		reports, err := storage.QueryAggregatedReports(ctx, start, end, committeeID)
		require.NoError(t, err, "QueryAggregatedReports should succeed")
		require.Len(t, reports, 2, "Should return both snapshots")
		assertTimestampOrdering(t, reports)
	})

	t.Run("empty results and validation", func(t *testing.T) {
		// Query empty time range (using seconds for API)
		start := int64(1500000000) // Much earlier time in seconds
		end := int64(1500001000)   // Still early time in seconds
		reports, err := storage.QueryAggregatedReports(ctx, start, end, "nonexistent-committee")
		require.NoError(t, err, "QueryAggregatedReports should succeed even with no results")
		require.Empty(t, reports, "Should return empty slice for no results")

		// Test invalid time range (start > end) in seconds
		start = int64(2000000000) // Later time in seconds
		end = int64(1000000000)   // Earlier time in seconds
		reports, err = storage.QueryAggregatedReports(ctx, start, end, "test-committee")
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

	storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring())

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

		storage := ddb.NewDynamoDBStorage(client, ddb.TestCommitVerificationRecordTableName, ddb.TestFinalizedFeedTableName, earliestDateForGetMessageSince, logger.TestSugared(t), monitoring.NewNoopAggregatorMonitoring())

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
