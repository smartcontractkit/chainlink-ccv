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
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
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
	s.SetRetryWindow(testWindow)
	return s
}

func setDeadline(t *testing.T, s *PostgresStorage, id protocol.Bytes32, deadline *time.Time) {
	t.Helper()
	_, err := s.ds.ExecContext(t.Context(), `UPDATE indexer.messages SET retry_deadline = $1 WHERE message_id = $2`, deadline, id.String())
	require.NoError(t, err)
}

func deadlineOf(t *testing.T, s *PostgresStorage, id protocol.Bytes32) *time.Time {
	t.Helper()
	var d *time.Time
	require.NoError(t, s.ds.GetContext(t.Context(), &d, `SELECT retry_deadline FROM indexer.messages WHERE message_id = $1`, id.String()))
	return d
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

	claims, err := s.ClaimWork(t.Context(), 10, time.Second)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[0], Attempt: 1}}, claims)

	claims, err = s.ClaimWork(t.Context(), 10, time.Second)
	require.NoError(t, err)
	require.Empty(t, claims, "a leased message is not claimed again")

	require.Eventually(t, func() bool {
		claims, err = s.ClaimWork(t.Context(), 10, time.Second)
		require.NoError(t, err)
		return len(claims) == 1
	}, tests.WaitTimeout(t), 100*time.Millisecond)
	require.Equal(t, 2, claims[0].Attempt)
}

// Only the current claim can settle; a worker that lost its claim changes nothing.
func TestSettleWork_RequiresCurrentClaim(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(2))
	_, err := s.ClaimWork(t.Context(), 1, time.Millisecond)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	claims, err := s.ClaimWork(t.Context(), 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	_, err = s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: 1, Status: common.MessageTimeout})
	require.ErrorIs(t, err, common.ErrClaimLost)
	require.Equal(t, common.MessageProcessing, statusOf(t, s, ids[0]))

	status, err := s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: 2, Status: common.MessageSuccessful})
	require.NoError(t, err)
	require.Equal(t, common.MessageSuccessful, status)
	require.Equal(t, common.MessageSuccessful, statusOf(t, s, ids[0]))
}

// A retry waits for its delay; a retry that would start after the deadline becomes TIMEOUT in the database.
func TestSettleWork_RetryOrTimeout(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(3), testMessage(4))
	claims, err := s.ClaimWork(t.Context(), 10, time.Minute)
	require.NoError(t, err)
	require.Len(t, claims, 2)
	attempt := map[protocol.Bytes32]int{}
	for _, c := range claims {
		attempt[c.MessageID] = c.Attempt
	}

	status, err := s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: attempt[ids[0]], Status: common.MessageProcessing, RetryDelay: 500 * time.Millisecond, LastErr: "not yet"})
	require.NoError(t, err)
	require.Equal(t, common.MessageProcessing, status)
	claims, err = s.ClaimWork(t.Context(), 10, time.Minute)
	require.NoError(t, err)
	require.Empty(t, claims, "the retry waits for its delay")
	require.Eventually(t, func() bool {
		claims, err = s.ClaimWork(t.Context(), 10, time.Minute)
		require.NoError(t, err)
		return len(claims) == 1
	}, tests.WaitTimeout(t), 100*time.Millisecond)

	status, err = s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[1], Attempt: attempt[ids[1]], Status: common.MessageProcessing, RetryDelay: 2 * testWindow})
	require.NoError(t, err)
	require.Equal(t, common.MessageTimeout, status)
	require.Equal(t, common.MessageTimeout, statusOf(t, s, ids[1]))
}

// A message past its deadline is not claimed. Expire times it out, unless a worker holds its lease.
func TestExpireWork_TimesOutUnleasedMessagesPastDeadline(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(5), testMessage(6))
	past := time.Now().Add(-time.Minute)
	setDeadline(t, s, ids[0], &past)

	claims, err := s.ClaimWork(t.Context(), 10, time.Minute)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[1], Attempt: 1}}, claims, "the old message is past its deadline")

	// The leased message passes its deadline while a worker holds it.
	setDeadline(t, s, ids[1], &past)
	n, err := s.ExpireWork(t.Context(), 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	require.Equal(t, common.MessageTimeout, statusOf(t, s, ids[0]))
	require.Equal(t, common.MessageProcessing, statusOf(t, s, ids[1]))
}

// A row without a deadline is never claimed, and expire times it out.
func TestExpireWork_NullDeadline(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(7))
	setDeadline(t, s, ids[0], nil)

	claims, err := s.ClaimWork(t.Context(), 10, time.Minute)
	require.NoError(t, err)
	require.Empty(t, claims)
	n, err := s.ExpireWork(t.Context(), 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	require.Equal(t, common.MessageTimeout, statusOf(t, s, ids[0]))
}

// The insert stamps NOW() + window; a later window change or a forced upsert does not move it.
func TestUpsertMessages_StampsRetryDeadline(t *testing.T) {
	s := newWorkStateStorage(t)
	msg := testMessage(8)
	before := time.Now()
	ids := insertMessages(t, s, msg)
	stamped := deadlineOf(t, s, ids[0])
	require.NotNil(t, stamped)
	require.WithinDuration(t, before.Add(testWindow), *stamped, 5*time.Second)

	s.SetRetryWindow(3 * testWindow)
	msg.Metadata.IngestionTimestamp = time.Now().UTC().Add(time.Hour)
	require.NoError(t, s.UpsertMessages(t.Context(), []common.MessageWithMetadata{msg}, true))
	require.True(t, stamped.Equal(*deadlineOf(t, s, ids[0])), "a forced upsert keeps the deadline")
}

// Without a window the insert uses the column default of 24 hours.
func TestUpsertMessages_DefaultRetryDeadline(t *testing.T) {
	s := newWorkStateStorage(t)
	s.SetRetryWindow(0)
	before := time.Now()
	ids := insertMessages(t, s, testMessage(10))
	d := deadlineOf(t, s, ids[0])
	require.NotNil(t, d)
	require.WithinDuration(t, before.Add(24*time.Hour), *d, 5*time.Second)
}

// Requeue gives a timed-out message a new deadline, so an old message is claimed again; SUCCESS is not changed.
func TestRequeueMessages_GivesNewWindow(t *testing.T) {
	s := newWorkStateStorage(t)
	timedOut, done := testMessage(7), testMessage(8)
	timedOut.Metadata.Status = common.MessageTimeout
	done.Metadata.Status = common.MessageSuccessful
	ids := insertMessages(t, s, timedOut, done)
	past := time.Now().Add(-time.Minute)
	setDeadline(t, s, ids[0], &past)

	requeued, err := s.RequeueMessages(t.Context(), ids, testWindow)
	require.NoError(t, err)
	require.Equal(t, []protocol.Bytes32{ids[0]}, requeued)
	require.Equal(t, common.MessageProcessing, statusOf(t, s, ids[0]))
	require.Equal(t, common.MessageSuccessful, statusOf(t, s, ids[1]))

	claims, err := s.ClaimWork(t.Context(), 10, time.Minute)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[0], Attempt: 2}}, claims, "reopening a final message gives a new token")

	// A requeue during an attempt keeps the lease and the claim token.
	_, err = s.RequeueMessages(t.Context(), ids[:1], testWindow)
	require.NoError(t, err)
	claims, err = s.ClaimWork(t.Context(), 10, time.Minute)
	require.NoError(t, err)
	require.Empty(t, claims)
	_, err = s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: 2, Status: common.MessageSuccessful})
	require.NoError(t, err)
}

// A worker whose claim expired cannot settle the message after a replay reopens it.
func TestRequeueMessages_InvalidatesExpiredClaim(t *testing.T) {
	s := newWorkStateStorage(t)
	ids := insertMessages(t, s, testMessage(10))
	claims, err := s.ClaimWork(t.Context(), 1, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, 1, claims[0].Attempt)
	time.Sleep(10 * time.Millisecond)

	// The lease and the deadline end, so the message times out.
	past := time.Now().Add(-time.Minute)
	setDeadline(t, s, ids[0], &past)
	n, err := s.ExpireWork(t.Context(), 10)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	_, err = s.RequeueMessages(t.Context(), ids, testWindow)
	require.NoError(t, err)

	// The old worker resumes before the next claim.
	_, err = s.SettleWork(t.Context(), common.WorkSettlement{MessageID: ids[0], Attempt: 1, Status: common.MessageTimeout})
	require.ErrorIs(t, err, common.ErrClaimLost)
	require.Equal(t, common.MessageProcessing, statusOf(t, s, ids[0]))

	claims, err = s.ClaimWork(t.Context(), 1, time.Minute)
	require.NoError(t, err)
	require.Equal(t, []common.WorkClaim{{MessageID: ids[0], Attempt: 3}}, claims)
}

// The discovery traceparent is stored with the message and returned with each claim.
func TestClaimWork_ReturnsTraceParent(t *testing.T) {
	s := newWorkStateStorage(t)
	msg := testMessage(11)
	msg.Metadata.TraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	ids := insertMessages(t, s, msg)

	claims, err := s.ClaimWork(t.Context(), 1, time.Minute)
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
