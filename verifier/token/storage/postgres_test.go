package storage

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
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

	db, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	sqlxDB := sqlx.NewDb(db, "postgres")

	err = chainstatus.RunPostgresMigrations(sqlxDB)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	return sqlxDB
}

func TestPostgresStorage(t *testing.T) {
	db := setupTestDB(t)
	lggr := logger.Test(t)

	storage := NewPostgres(db, lggr)

	ctx := context.Background()

	// Create a test message
	message, err := protocol.NewMessage(
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
		[]byte("test data"),
		nil,
	)
	require.NoError(t, err)

	msgID, err := message.MessageID()
	require.NoError(t, err)

	// Create test entries
	entries := []Entry{
		{
			value: protocol.VerifierNodeResult{
				MessageID:       msgID,
				Message:         *message,
				CCVVersion:      protocol.ByteSlice{0x01},
				CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
				ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
				Signature:       protocol.ByteSlice{0x0d, 0x0e},
			},
			verifierSourceAddress: protocol.UnknownAddress{0x0f, 0x10},
			verifierDestAddress:   protocol.UnknownAddress{0x11, 0x12},
			timestamp:             time.Now().UTC().Truncate(time.Microsecond),
		},
	}

	t.Run("Set and Get", func(t *testing.T) {
		// Test Set
		err := storage.Set(ctx, entries)
		require.NoError(t, err)

		// Test Get
		results, err := storage.Get(ctx, []protocol.Bytes32{msgID})
		require.NoError(t, err)
		require.Len(t, results, 1)

		entry, ok := results[msgID]
		require.True(t, ok)

		assert.Equal(t, entries[0].value.MessageID, entry.value.MessageID)
		assert.Equal(t, entries[0].value.CCVVersion, entry.value.CCVVersion)
		assert.Equal(t, entries[0].value.CCVAddresses, entry.value.CCVAddresses)
		assert.Equal(t, entries[0].value.ExecutorAddress, entry.value.ExecutorAddress)
		assert.Equal(t, entries[0].value.Signature, entry.value.Signature)
		assert.Equal(t, entries[0].verifierSourceAddress, entry.verifierSourceAddress)
		assert.Equal(t, entries[0].verifierDestAddress, entry.verifierDestAddress)
		assert.WithinDuration(t, entries[0].timestamp, entry.timestamp, time.Second)

		// Verify message fields
		assert.Equal(t, entries[0].value.Message.SourceChainSelector, entry.value.Message.SourceChainSelector)
		assert.Equal(t, entries[0].value.Message.DestChainSelector, entry.value.Message.DestChainSelector)
		assert.Equal(t, entries[0].value.Message.SequenceNumber, entry.value.Message.SequenceNumber)
	})

	t.Run("Get non-existent", func(t *testing.T) {
		nonExistentID := protocol.Bytes32{0xff, 0xff, 0xff}
		results, err := storage.Get(ctx, []protocol.Bytes32{nonExistentID})
		require.NoError(t, err)
		assert.Len(t, results, 0)
	})

	t.Run("Update existing", func(t *testing.T) {
		// Update the entry with new signature
		updatedEntries := []Entry{
			{
				value: protocol.VerifierNodeResult{
					MessageID:       msgID,
					Message:         *message,
					CCVVersion:      protocol.ByteSlice{0x01},
					CCVAddresses:    []protocol.UnknownAddress{{0x09, 0x0a}},
					ExecutorAddress: protocol.UnknownAddress{0x0b, 0x0c},
					Signature:       protocol.ByteSlice{0xff, 0xff}, // Updated
				},
				verifierSourceAddress: protocol.UnknownAddress{0x0f, 0x10},
				verifierDestAddress:   protocol.UnknownAddress{0x11, 0x12},
				timestamp:             time.Now().UTC().Truncate(time.Microsecond),
			},
		}

		err := storage.Set(ctx, updatedEntries)
		require.NoError(t, err)

		results, err := storage.Get(ctx, []protocol.Bytes32{msgID})
		require.NoError(t, err)
		require.Len(t, results, 1)

		entry := results[msgID]
		assert.Equal(t, protocol.ByteSlice{0xff, 0xff}, entry.value.Signature)
	})
}

func TestPostgresJSONSerialization(t *testing.T) {
	// Test that Message and UnknownAddress can be properly marshaled/unmarshaled to JSON
	message, err := protocol.NewMessage(
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
		[]byte("test data"),
		protocol.NewEmptyTokenTransfer(),
	)
	require.NoError(t, err)

	// Test Message JSON serialization
	messageJSON, err := json.Marshal(message)
	require.NoError(t, err)

	var unmarshaledMessage protocol.Message
	err = json.Unmarshal(messageJSON, &unmarshaledMessage)
	require.NoError(t, err)

	assert.Equal(t, message.SourceChainSelector, unmarshaledMessage.SourceChainSelector)
	assert.Equal(t, message.DestChainSelector, unmarshaledMessage.DestChainSelector)
	assert.Equal(t, message.SequenceNumber, unmarshaledMessage.SequenceNumber)

	// Test CCV addresses JSON serialization
	ccvAddresses := []protocol.UnknownAddress{
		{0x01, 0x02},
		{0x03, 0x04, 0x05},
	}

	ccvJSON, err := json.Marshal(ccvAddresses)
	require.NoError(t, err)

	var unmarshaledCCV []protocol.UnknownAddress
	err = json.Unmarshal(ccvJSON, &unmarshaledCCV)
	require.NoError(t, err)

	assert.Equal(t, ccvAddresses, unmarshaledCCV)
}
