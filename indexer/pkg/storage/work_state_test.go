package storage

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/testutil"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

const testWindow = time.Hour

func testMessage(seq int) common.MessageWithMetadata {
	return common.MessageWithMetadata{
		Message: protocol.Message{
			Sender:               []byte{0x0d, 0x0e, 0x0f},
			Data:                 []byte{0x10, 0x11, 0x12},
			OnRampAddress:        []byte{0x13, 0x14, 0x15},
			OffRampAddress:       []byte{0x19, 0x1a, 0x1b},
			DestBlob:             []byte{0x1c, 0x1d, 0x1e},
			Receiver:             []byte{0x1f, 0x20, 0x21},
			SourceChainSelector:  1,
			DestChainSelector:    2,
			SequenceNumber:       protocol.SequenceNumber(seq),
			Finality:             1,
			DestBlobLength:       3,
			DataLength:           3,
			ReceiverLength:       3,
			SenderLength:         3,
			Version:              1,
			OffRampAddressLength: 3,
			OnRampAddressLength:  3,
		},
		Metadata: common.MessageMetadata{Status: common.MessageProcessing, IngestionTimestamp: time.Now().UTC()},
	}
}

func newWorkStateStorage(t *testing.T) *PostgresStorage {
	t.Helper()
	uri, cleanup := testutil.SetupTestPostgresURI(t)
	t.Cleanup(cleanup)
	db, err := sqlx.Open("postgres", uri)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, RunMigrationsContext(t.Context(), db))
	s, err := NewPostgresStorage(t.Context(), logger.Test(t), monitoring.NewNoopIndexerMonitoring(), uri, pg.DriverPostgres, pg.DBConfig{MaxOpenConns: 5}, 0, 0)
	require.NoError(t, err)
	return s
}

func insertMessages(t *testing.T, s *PostgresStorage, msgs ...common.MessageWithMetadata) []protocol.Bytes32 {
	t.Helper()
	require.NoError(t, s.UpsertMessages(t.Context(), msgs, false))
	ids := make([]protocol.Bytes32, len(msgs))
	for i, m := range msgs {
		ids[i] = m.Message.MustMessageID()
	}
	return ids
}

func statusOf(t *testing.T, s *PostgresStorage, id protocol.Bytes32) common.MessageStatus {
	t.Helper()
	m, err := s.GetMessage(t.Context(), id)
	require.NoError(t, err)
	return m.Metadata.Status
}

// A claimed message is leased; when the lease ends, a second claim gets it with a higher attempt.
func TestClaimWork_LeasesUntilExpiry(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(1))

	claims, err := s.ClaimWork(t.Context(), 10, time.Second, testWindow)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[0], Attempt: 1}}, claims)

	claims, err = s.ClaimWork(t.Context(), 10, time.Second, testWindow)
	require.NoError(t, err)
	require.Empty(t, claims, "a leased message is not claimed again")

	require.Eventually(t, func() bool {
		claims, err = s.ClaimWork(t.Context(), 10, time.Second, testWindow)
		require.NoError(t, err)
		return len(claims) == 1
	}, 5*time.Second, 100*time.Millisecond)
	require.Equal(t, 2, claims[0].Attempt)
}

// Only the current claim can settle; a worker that lost its claim changes nothing.
func TestSettleWork_RequiresCurrentClaim(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(2))
	_, err := s.ClaimWork(t.Context(), 1, time.Millisecond, testWindow)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	claims, err := s.ClaimWork(t.Context(), 1, time.Minute, testWindow)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	_, err = s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: 1, Status: common.MessageTimeout, Window: testWindow})
	require.ErrorIs(t, err, common.ErrClaimLost)
	require.Equal(t, common.MessageProcessing, statusOf(t, s, ids[0]))

	status, err := s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: 2, Status: common.MessageSuccessful, Window: testWindow})
	require.NoError(t, err)
	require.Equal(t, common.MessageSuccessful, status)
	require.Equal(t, common.MessageSuccessful, statusOf(t, s, ids[0]))
}

// A retry waits for its delay; a retry that would start after the deadline becomes TIMEOUT in the database.
func TestSettleWork_RetryOrTimeout(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(3), testMessage(4))
	claims, err := s.ClaimWork(t.Context(), 10, time.Minute, testWindow)
	require.NoError(t, err)
	require.Len(t, claims, 2)
	attempt := map[protocol.Bytes32]int{}
	for _, c := range claims {
		attempt[c.MessageID] = c.Attempt
	}

	status, err := s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: attempt[ids[0]], Status: common.MessageProcessing, RetryDelay: 500 * time.Millisecond, LastErr: "not yet", Window: testWindow})
	require.NoError(t, err)
	require.Equal(t, common.MessageProcessing, status)
	claims, err = s.ClaimWork(t.Context(), 10, time.Minute, testWindow)
	require.NoError(t, err)
	require.Empty(t, claims, "the retry waits for its delay")
	require.Eventually(t, func() bool {
		claims, err = s.ClaimWork(t.Context(), 10, time.Minute, testWindow)
		require.NoError(t, err)
		return len(claims) == 1
	}, 5*time.Second, 100*time.Millisecond)

	status, err = s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[1], Attempt: attempt[ids[1]], Status: common.MessageProcessing, RetryDelay: 2 * testWindow, Window: testWindow})
	require.NoError(t, err)
	require.Equal(t, common.MessageTimeout, status)
	require.Equal(t, common.MessageTimeout, statusOf(t, s, ids[1]))
}

// A message past its deadline is not claimed. Expire times it out, unless a worker holds its lease.
func TestExpireWork_TimesOutUnleasedMessagesPastDeadline(t *testing.T) {
	s := newWorkStateStorage(t)
	old, leased := testMessage(5), testMessage(6)
	old.Metadata.IngestionTimestamp = time.Now().UTC().Add(-2 * testWindow)
	ids := insertMessages(t, s, old, leased)

	claims, err := s.ClaimWork(t.Context(), 10, time.Minute, testWindow)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[1], Attempt: 1}}, claims, "the old message is past its deadline")

	// The leased message passes its deadline while a worker holds it.
	n, err := s.ExpireWork(t.Context(), time.Nanosecond, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	require.Equal(t, common.MessageTimeout, statusOf(t, s, ids[0]))
	require.Equal(t, common.MessageProcessing, statusOf(t, s, ids[1]))
}

// The discovery traceparent is stored with the message and returned with each claim.
func TestClaimWork_ReturnsTraceParent(t *testing.T) {
	s := newWorkStateStorage(t)
	msg := testMessage(11)
	msg.Metadata.TraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	ids := insertMessages(t, s, msg)

	claims, err := s.ClaimWork(t.Context(), 1, time.Minute, testWindow)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[0], Attempt: 1, TraceParent: msg.Metadata.TraceParent}}, claims)
}

func TestPersistDiscoveryBatch_CallsOnMessagesPersisted(t *testing.T) {
	s := newWorkStateStorage(t)
	called := 0
	s.SetOnMessagesPersisted(func() { called++ })
	require.NoError(t, s.PersistDiscoveryBatch(t.Context(), common.DiscoveryBatch{
		Messages: []common.MessageWithMetadata{testMessage(9)}, SequenceNumber: common.SequenceNumberNotSupported,
	}))
	require.Equal(t, 1, called)
}
