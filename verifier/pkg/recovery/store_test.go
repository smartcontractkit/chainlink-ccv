package recovery_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type recoveryJob struct{ ID []byte }

func (j recoveryJob) JobKey() (uint64, []byte) { return 42, j.ID }

func TestDurableRequestAndChunkTransactions(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	s := recovery.NewStore(db)
	require.NoError(t, s.RegisterReader(ctx, "owner", "42", "node", false))
	head := uint64(200)
	require.NoError(t, s.Heartbeat(ctx, "owner", "42", &head, false, 0))
	request := recovery.SubmitRequest{ID: uuid.NewString(), OwnerID: "owner", SourceChain: "00042", FromBlock: 100, Mode: "replay", Actor: "operator", Note: "restore missed range"}
	o, err := s.Submit(ctx, request)
	require.NoError(t, err)
	require.Equal(t, uint64(200), o.ToBlock)
	head = 300
	require.NoError(t, s.Heartbeat(ctx, "owner", "42", &head, false, 0))
	request.ID = strings.ToUpper(request.ID)
	repeated, err := s.Submit(ctx, request)
	require.NoError(t, err)
	require.Equal(t, o, repeated, "repeated submission keeps the original target")
	request.FromBlock++
	_, err = s.Submit(ctx, request)
	require.ErrorContains(t, err, "different request")
	q, err := jobqueue.NewPostgresJobQueue[recoveryJob](db, jobqueue.QueueConfig{Name: "ccv_task_verifier_jobs", OwnerID: "owner", RetryDuration: time.Hour}, logger.Test(t))
	require.NoError(t, err)
	failure := errors.New("process failed before committing progress")
	err = s.Step(ctx, o.ID, func(tx *recovery.Store, current *recovery.Operation) error {
		_, err := q.PublishInTransaction(ctx, tx.DataSource(), recoveryJob{ID: []byte{1}})
		if err != nil {
			return err
		}
		current.NextBlock = 150
		return failure
	})
	require.ErrorIs(t, err, failure)
	size, err := q.Size(ctx)
	require.NoError(t, err)
	require.Zero(t, size, "queue insertion must roll back with chunk progress")
	restarted := recovery.NewStore(db)
	current, err := restarted.Get(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(100), current.NextBlock)
	require.NoError(t, restarted.Step(ctx, o.ID, func(tx *recovery.Store, current *recovery.Operation) error {
		count, err := q.PublishInTransaction(ctx, tx.DataSource(), recoveryJob{ID: []byte{1}})
		current.Admitted += count
		current.NextBlock = 150
		return err
	}))
	current, err = s.Get(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(150), current.NextBlock)
	require.Equal(t, int64(1), current.Admitted)
	cancelled, err := s.ChangeState(ctx, o.ID, "cancel")
	require.NoError(t, err)
	require.Equal(t, "cancelled", cancelled.State)
	require.NoError(t, s.Step(ctx, o.ID, func(*recovery.Store, *recovery.Operation) error {
		t.Error("cancelled operation must not scan")
		return nil
	}))
	resumed, err := s.ChangeState(ctx, o.ID, "resume")
	require.NoError(t, err)
	require.Equal(t, uint64(150), resumed.NextBlock)
	require.NoError(t, s.Step(ctx, o.ID, func(tx *recovery.Store, current *recovery.Operation) error {
		count, err := q.PublishInTransaction(ctx, tx.DataSource(), recoveryJob{ID: []byte{1}})
		current.Conflicts += 1 - count
		current.NextBlock, current.State = 201, "completed"
		return err
	}))
	current, err = s.Get(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), current.Conflicts)
	_, err = s.ChangeState(ctx, o.ID, "resume")
	require.Error(t, err, "completed operations are immutable")
}

func TestEventHistoryDeduplicationPaginationAndCoverage(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	s := recovery.NewStore(db)
	require.NoError(t, s.RegisterReader(ctx, "owner", "42", "node", false))
	id, block, dest := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "100", "18446744073709551615"
	event := recovery.Event{
		OwnerID: "owner", NodeID: "node", SourceChain: "42", DestChain: &dest, MessageID: &id,
		SourceBlock: &block, Kind: "drop", Stage: "admission", Reason: "remote_chain_cursed",
	}
	require.NoError(t, s.RecordEvents(ctx, event, event))
	filter := recovery.EventFilter{OwnerID: "owner", SourceChain: "42", DestChain: dest, MessageIDs: []string{id}, Limit: 1}
	page, err := s.ListEvents(ctx, filter)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	require.Equal(t, "2", page.Events[0].Observations)
	require.Nil(t, page.Events[0].TxHash)
	require.Nil(t, page.Events[0].BlockHash)
	require.Contains(t, page.Coverage, "Unobserved disabled intervals")
	event.Reason = "message_disablement_rule"
	require.NoError(t, s.RecordEvents(ctx, event))
	page, err = recovery.NewStore(db).ListEvents(ctx, filter)
	require.NoError(t, err)
	require.NotEmpty(t, page.NextCursor)
	filter.BeforeID = page.NextCursor
	older, err := s.ListEvents(ctx, filter)
	require.NoError(t, err)
	require.Len(t, older.Events, 1)
	require.Equal(t, "remote_chain_cursed", older.Events[0].Reason)
	require.NoError(t, s.Heartbeat(ctx, "owner", "42", nil, true, 1))
	_, err = db.ExecContext(ctx, "UPDATE ccv_recovery_events SET expires_at=NOW()-INTERVAL '1 second'")
	require.NoError(t, err)
	require.NoError(t, s.Cleanup(ctx, "owner"))
	page, err = s.ListEvents(ctx, filter)
	require.NoError(t, err)
	require.Empty(t, page.Events)
	require.Contains(t, string(page.Readers), `"audit_failures": "1"`)
}

func TestCancellationWaitsForCommittedChunkAndStaleFailureCannotUndoResume(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := recovery.NewStore(db)
	require.NoError(t, s.RegisterReader(ctx, "owner", "42", "node", false))
	end := uint64(200)
	o, err := s.Submit(ctx, recovery.SubmitRequest{
		OwnerID: "owner", SourceChain: "42", FromBlock: 100,
		ToBlock: &end, Mode: "replay", Actor: "operator", Note: "cancellation test",
	})
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	stepDone, cancelDone := make(chan error, 1), make(chan error, 1)
	go func() {
		stepDone <- s.Step(ctx, o.ID, func(_ *recovery.Store, current *recovery.Operation) error {
			close(entered)
			select {
			case <-release:
				current.NextBlock = 150
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		_, err := s.ChangeState(ctx, o.ID, "cancel")
		cancelDone <- err
	}()
	select {
	case err := <-cancelDone:
		t.Errorf("cancel returned before the in-flight chunk committed: %v", err)
		cancelDone <- err
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-stepDone)
	require.NoError(t, <-cancelDone)
	current, err := s.Get(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, "cancelled", current.State)
	require.Equal(t, uint64(150), current.NextBlock)
	_, err = s.ChangeState(ctx, o.ID, "resume")
	require.NoError(t, err)
	require.NoError(t, s.Fail(ctx, o.ID, o.UpdatedAt, errors.New("late error from the cancelled attempt")))
	current, err = s.Get(ctx, o.ID)
	require.NoError(t, err)
	require.Equal(t, "accepted", current.State)
	require.Zero(t, current.Errors)
}
