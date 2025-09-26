package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func setupTestDatabase(t *testing.T) *DatabaseStorage {
	// Use in-memory SQLite for testing
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	// Create test tables (simplified schema for testing)
	_, err = db.Exec(`
		CREATE TABLE commit_verification_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			seq_num INTEGER NOT NULL DEFAULT 1,
			message_id TEXT NOT NULL,
			committee_id TEXT NOT NULL,
			participant_id TEXT NOT NULL DEFAULT '',
			signer_address TEXT NOT NULL,
			source_chain_selector TEXT NOT NULL,
			dest_chain_selector TEXT NOT NULL,
			onramp_address TEXT NOT NULL,
			offramp_address TEXT NOT NULL,
			signature_r BLOB NOT NULL DEFAULT '',
			signature_s BLOB NOT NULL DEFAULT '',
			ccv_node_data BLOB NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	_, err = db.Exec(`
		CREATE TABLE commit_aggregated_reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			seq_num INTEGER NOT NULL DEFAULT 1,
			message_id TEXT NOT NULL,
			committee_id TEXT NOT NULL,
			verification_record_ids TEXT NOT NULL,  -- JSON array for SQLite
			report_data BLOB NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create indexes
	_, err = db.Exec(`CREATE INDEX idx_verification_message_committee ON commit_verification_records(message_id, committee_id)`)
	require.NoError(t, err)

	_, err = db.Exec(`CREATE INDEX idx_aggregated_message_committee ON commit_aggregated_reports(message_id, committee_id)`)
	require.NoError(t, err)

	sqlxDB := sqlx.NewDb(db, "sqlite")

	return NewDatabaseStorage(sqlxDB)
}

func createTestVerificationRecord(messageID, committeeID, signerAddress string) *model.CommitVerificationRecord {
	messageIDBytes := common.Hex2Bytes(messageID)
	signerAddrBytes := common.HexToAddress(signerAddress).Bytes()

	var sigR, sigS [32]byte
	copy(sigR[:], []byte("test_signature_r_"+signerAddress))
	copy(sigS[:], []byte("test_signature_s_"+signerAddress))

	return &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			MessageId: messageIDBytes,
			Message: &pb.Message{
				SourceChainSelector: 1,
				DestChainSelector:   2,
				OnRampAddress:       common.HexToAddress("0x1234").Bytes(),
				OffRampAddress:      common.HexToAddress("0x5678").Bytes(),
			},
			Timestamp: time.Now().Unix(),
		},
		IdentifierSigner: &model.IdentifierSigner{
			Signer: model.Signer{
				ParticipantID: "participant_" + signerAddress,
			},
			Address:     signerAddrBytes,
			SignatureR:  sigR,
			SignatureS:  sigS,
			CommitteeID: committeeID,
		},
		CommitteeID: committeeID,
	}
}

func TestDatabaseStorage_ListOrphanedMessageCommitteePairs_NoOrphans(t *testing.T) {
	storage := setupTestDatabase(t)
	ctx := context.Background()

	// Test with empty database
	pairCh, errCh := storage.ListOrphanedMessageCommitteePairs(ctx)

	// Should close without sending anything
	pairs := collectPairs(t, pairCh, errCh)
	require.Empty(t, pairs, "Expected no orphaned pairs in empty database")
}

func TestDatabaseStorage_ListOrphanedMessageCommitteePairs_WithOrphans(t *testing.T) {
	storage := setupTestDatabase(t)
	ctx := context.Background()

	// Create test verification records
	record1 := createTestVerificationRecord("aabbcc", "committee1", "0x1111111111111111111111111111111111111111")
	record2 := createTestVerificationRecord("ddeeff", "committee1", "0x2222222222222222222222222222222222222222")
	record3 := createTestVerificationRecord("aabbcc", "committee2", "0x3333333333333333333333333333333333333333")

	// Save verification records
	require.NoError(t, storage.SaveCommitVerification(ctx, record1))
	require.NoError(t, storage.SaveCommitVerification(ctx, record2))
	require.NoError(t, storage.SaveCommitVerification(ctx, record3))

	// Query for orphaned pairs
	pairCh, errCh := storage.ListOrphanedMessageCommitteePairs(ctx)
	pairs := collectPairs(t, pairCh, errCh)

	// Should find 3 orphaned pairs since no aggregated reports exist
	require.Len(t, pairs, 3, "Expected 3 orphaned pairs")

	// Verify pairs contain expected combinations
	expectedPairs := []struct {
		messageID   string
		committeeID string
	}{
		{"aabbcc", "committee1"},
		{"ddeeff", "committee1"},
		{"aabbcc", "committee2"},
	}

	for _, expected := range expectedPairs {
		found := false
		for _, pair := range pairs {
			if common.Bytes2Hex(pair.MessageID) == expected.messageID && pair.CommitteeID == expected.committeeID {
				found = true
				break
			}
		}
		require.True(t, found, "Expected pair not found: messageID=%s, committeeID=%s", expected.messageID, expected.committeeID)
	}
}

func TestDatabaseStorage_ListOrphanedMessageCommitteePairs_ContextCancellation(t *testing.T) {
	storage := setupTestDatabase(t)

	// Create a context that will be cancelled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	pairCh, errCh := storage.ListOrphanedMessageCommitteePairs(ctx)

	// Should receive a context cancellation error
	select {
	case pair := <-pairCh:
		require.Nil(t, pair, "Should not receive any pairs when context is cancelled")
	case err := <-errCh:
		require.Error(t, err, "Expected context cancellation error")
		require.ErrorIs(t, err, context.Canceled, "Expected context.Canceled error")
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for error or completion")
	}
}

// Helper function to collect all pairs from channels
func collectPairs(t *testing.T, pairCh <-chan *model.MessageCommitteePair, errCh <-chan error) []*model.MessageCommitteePair {
	var pairs []*model.MessageCommitteePair
	timeout := time.After(5 * time.Second)

	for {
		select {
		case pair, ok := <-pairCh:
			if !ok {
				// Channel closed, we're done
				return pairs
			}
			pairs = append(pairs, pair)

		case err, ok := <-errCh:
			if ok && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !ok {
				// Error channel closed, continue reading pairs
				errCh = nil
			}

		case <-timeout:
			t.Fatal("Timed out waiting for orphaned pairs")
		}
	}
}
