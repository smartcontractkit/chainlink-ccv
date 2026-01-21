package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/ccvstorage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func setupTestDB(t *testing.T) *sqlx.DB {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	t.Helper()
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_chainstatus_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	dbx, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	sqlxDB := sqlx.NewDb(dbx, "postgres")

	err = db.RunPostgresMigrations(sqlxDB)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	return sqlxDB
}

func TestAttestationCCVWriterAndReader_Postgres(t *testing.T) {
	db := setupTestDB(t)
	lggr := logger.Test(t)

	storage := ccvstorage.NewPostgres(db, lggr)

	// Setup verifier addresses for test chains
	verifierAddresses := map[protocol.ChainSelector]protocol.UnknownAddress{
		1: {0xa1, 0xa2, 0xa3},
		2: {0xb1, 0xb2, 0xb3},
	}

	writer := NewAttestationCCVWriter(lggr, verifierAddresses, storage)
	reader := NewAttestationCCVReader(storage)

	ctx := t.Context()

	// Create test messages
	message1, err := protocol.NewMessage(
		protocol.ChainSelector(1),
		protocol.ChainSelector(2),
		protocol.SequenceNumber(1),
		protocol.UnknownAddress{0x01, 0x02},
		protocol.UnknownAddress{0x03, 0x04},
		100,
		50000,
		40000,
		protocol.Bytes32{},
		protocol.UnknownAddress{0x05, 0x06},
		protocol.UnknownAddress{0x07, 0x08},
		[]byte{},
		[]byte("test data 1"),
		nil,
	)
	require.NoError(t, err)

	message2, err := protocol.NewMessage(
		protocol.ChainSelector(1),
		protocol.ChainSelector(2),
		protocol.SequenceNumber(2),
		protocol.UnknownAddress{0x01, 0x02},
		protocol.UnknownAddress{0x03, 0x04},
		100,
		50000,
		40000,
		protocol.Bytes32{},
		protocol.UnknownAddress{0x05, 0x06},
		protocol.UnknownAddress{0x07, 0x08},
		[]byte{},
		[]byte("test data 2"),
		nil,
	)
	require.NoError(t, err)

	msgID1, err := message1.MessageID()
	require.NoError(t, err)

	msgID2, err := message2.MessageID()
	require.NoError(t, err)

	t.Run("Write and Read single message", func(t *testing.T) {
		// Write CCV node data
		ccvData := []protocol.VerifierNodeResult{
			{
				MessageID:       msgID1,
				Message:         *message1,
				CCVVersion:      protocol.ByteSlice{0x01},
				CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
				ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
				Signature:       protocol.ByteSlice{0x0d, 0x0e, 0x0f},
			},
		}

		err := writer.WriteCCVNodeData(ctx, ccvData)
		require.NoError(t, err)

		// Read back the data
		results, err := reader.GetVerifications(ctx, []protocol.Bytes32{msgID1})
		require.NoError(t, err)
		require.Len(t, results, 1)

		result, ok := results[msgID1]
		require.True(t, ok)

		// Verify the result
		assert.Equal(t, msgID1, result.MessageID)
		assert.Equal(t, message1.SourceChainSelector, result.Message.SourceChainSelector)
		assert.Equal(t, message1.DestChainSelector, result.Message.DestChainSelector)
		assert.Equal(t, message1.SequenceNumber, result.Message.SequenceNumber)
		assert.Equal(t, []protocol.UnknownAddress{{0x09, 0x0a}}, result.MessageCCVAddresses)
		assert.Equal(t, protocol.UnknownAddress{0x0b, 0x0c}, result.MessageExecutorAddress)
		assert.Equal(t, protocol.ByteSlice{0x0d, 0x0e, 0x0f}, result.CCVData)

		// Verify verifier addresses were set correctly from the writer's config
		assert.Equal(t, verifierAddresses[1], result.VerifierSourceAddress)
		assert.Equal(t, verifierAddresses[2], result.VerifierDestAddress)

		// Verify timestamp is recent
		assert.WithinDuration(t, time.Now(), result.Timestamp, 5*time.Second)
	})

	t.Run("Write and Read multiple messages", func(t *testing.T) {
		// Write multiple CCV node data entries
		ccvData := []protocol.VerifierNodeResult{
			{
				MessageID:       msgID1,
				Message:         *message1,
				CCVVersion:      protocol.ByteSlice{0x01},
				CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
				ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
				Signature:       protocol.ByteSlice{0x01, 0x02, 0x03},
			},
			{
				MessageID:       msgID2,
				Message:         *message2,
				CCVVersion:      protocol.ByteSlice{0x02},
				CCVAddresses:    []protocol.UnknownAddress{{0x19, 0x1a}},
				ExecutorAddress: protocol.UnknownAddress{0x1b, 0x1c},
				Signature:       protocol.ByteSlice{0x04, 0x05, 0x06},
			},
		}

		err := writer.WriteCCVNodeData(ctx, ccvData)
		require.NoError(t, err)

		// Read back both messages
		results, err := reader.GetVerifications(ctx, []protocol.Bytes32{msgID1, msgID2})
		require.NoError(t, err)
		require.Len(t, results, 2)

		// Verify both results exist
		result1, ok := results[msgID1]
		require.True(t, ok)
		assert.Equal(t, protocol.ByteSlice{0x01, 0x02, 0x03}, result1.CCVData)

		result2, ok := results[msgID2]
		require.True(t, ok)
		assert.Equal(t, protocol.ByteSlice{0x04, 0x05, 0x06}, result2.CCVData)
		assert.Equal(t, protocol.SequenceNumber(2), result2.Message.SequenceNumber)
	})

	t.Run("Read non-existent message", func(t *testing.T) {
		nonExistentID := protocol.Bytes32{0xff, 0xff, 0xff}
		results, err := reader.GetVerifications(ctx, []protocol.Bytes32{nonExistentID})
		require.NoError(t, err)
		assert.Len(t, results, 0)
	})

	t.Run("Update existing message", func(t *testing.T) {
		// Write initial data
		ccvData := []protocol.VerifierNodeResult{
			{
				MessageID:       msgID1,
				Message:         *message1,
				CCVVersion:      protocol.ByteSlice{0x01},
				CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
				ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
				Signature:       protocol.ByteSlice{0xaa, 0xbb},
			},
		}
		err := writer.WriteCCVNodeData(ctx, ccvData)
		require.NoError(t, err)

		// Update with new signature
		updatedCCVData := []protocol.VerifierNodeResult{
			{
				MessageID:       msgID1,
				Message:         *message1,
				CCVVersion:      protocol.ByteSlice{0x01},
				CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
				ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
				Signature:       protocol.ByteSlice{0xcc, 0xdd}, // Updated
			},
		}
		err = writer.WriteCCVNodeData(ctx, updatedCCVData)
		require.NoError(t, err)

		// Read back and verify update
		results, err := reader.GetVerifications(ctx, []protocol.Bytes32{msgID1})
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[msgID1]
		assert.Equal(t, protocol.ByteSlice{0xcc, 0xdd}, result.CCVData)
	})

	t.Run("Read partial results when some messages exist", func(t *testing.T) {
		nonExistentID := protocol.Bytes32{0xee, 0xee, 0xee}

		// Request both existing and non-existing messages
		results, err := reader.GetVerifications(ctx, []protocol.Bytes32{msgID1, nonExistentID})
		require.NoError(t, err)

		// Should only get the existing one
		assert.Len(t, results, 1)
		_, ok := results[msgID1]
		assert.True(t, ok)
		_, ok = results[nonExistentID]
		assert.False(t, ok)
	})

	t.Run("Handle missing verifier addresses gracefully", func(t *testing.T) {
		// Create a message with chain selectors not in verifierAddresses map
		message3, err := protocol.NewMessage(
			protocol.ChainSelector(999), // Not in verifierAddresses
			protocol.ChainSelector(888), // Not in verifierAddresses
			protocol.SequenceNumber(3),
			protocol.UnknownAddress{0x01, 0x02},
			protocol.UnknownAddress{0x03, 0x04},
			100,
			50000,
			40000,
			protocol.Bytes32{},
			protocol.UnknownAddress{0x05, 0x06},
			protocol.UnknownAddress{0x07, 0x08},
			[]byte{},
			[]byte("test data 3"),
			nil,
		)
		require.NoError(t, err)

		msgID3, err := message3.MessageID()
		require.NoError(t, err)

		ccvData := []protocol.VerifierNodeResult{
			{
				MessageID:       msgID3,
				Message:         *message3,
				CCVVersion:      protocol.ByteSlice{0x01},
				CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
				ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
				Signature:       protocol.ByteSlice{0x0d, 0x0e, 0x0f},
			},
		}

		// Should not error, but log warnings about missing addresses
		err = writer.WriteCCVNodeData(ctx, ccvData)
		require.NoError(t, err)

		// Should be able to read back the data with empty verifier addresses
		results, err := reader.GetVerifications(ctx, []protocol.Bytes32{msgID3})
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[msgID3]
		assert.Equal(t, protocol.UnknownAddress{}, result.VerifierSourceAddress)
		assert.Equal(t, protocol.UnknownAddress{}, result.VerifierDestAddress)
	})
}
