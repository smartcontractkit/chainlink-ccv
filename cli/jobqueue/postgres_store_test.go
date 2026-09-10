package jobqueue_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

func TestArchiveLookupAndAtomicOwnerResolution(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	store := jobqueue.NewPostgresStore(db)
	nextID := int64(0)
	seed := func(queue jobqueue.QueueType, owner string, message []byte, age time.Duration) string {
		t.Helper()
		nextID--
		id := uuid.NewString()
		table := "ccv_task_verifier_jobs_archive"
		if queue == jobqueue.QueueTypeStorageWriter {
			table = "ccv_storage_writer_jobs_archive"
		}
		_, err := db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s
			(id,job_id,owner_id,chain_selector,message_id,task_data,status,created_at,available_at,attempt_count,retry_deadline,completed_at)
			VALUES ($1,$2,$3,18446744073709551615,$4,'{}','failed',$5,NOW(),2,NOW(),NOW())`, table), nextID, id, owner, message, time.Now().Add(-age))
		require.NoError(t, err)
		return id
	}
	id := make([]byte, 32)
	id[0] = 1
	old := seed(jobqueue.QueueTypeTaskVerifier, "owner-a", id, 48*time.Hour)
	for i := range 60 {
		seed(jobqueue.QueueTypeTaskVerifier, "owner-a", []byte{byte(i), 2}, time.Minute)
	}
	rows, err := store.ListFailedFiltered(ctx, nil, "", [][]byte{id}, 1)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, old, rows[0].JobID, "filter must run before limit")
	require.Equal(t, ^uint64(0), rows[0].ChainSelector)
	other := seed(jobqueue.QueueTypeTaskVerifier, "owner-b", id, time.Hour)
	seed(jobqueue.QueueTypeStorageWriter, "owner-c", id, time.Hour)
	rows, err = store.ListFailedFiltered(ctx, nil, "", [][]byte{id}, 0)
	require.NoError(t, err)
	require.Len(t, rows, 3, "all queues and owners are visible")
	_, err = store.Reschedule(ctx, jobqueue.QueueTypeTaskVerifier, "", "", id, time.Hour)
	require.ErrorContains(t, err, "owner-a, owner-b")
	_, err = store.Reschedule(ctx, jobqueue.QueueTypeTaskVerifier, "wrong-owner", other, nil, time.Hour)
	require.ErrorContains(t, err, "no failed job")
	restored, err := store.Reschedule(ctx, jobqueue.QueueTypeTaskVerifier, "", other, nil, time.Hour)
	require.NoError(t, err)
	require.Equal(t, "owner-b", restored.OwnerID)
	duplicate := seed(jobqueue.QueueTypeTaskVerifier, "owner-a", id, time.Hour)
	_, err = store.Reschedule(ctx, jobqueue.QueueTypeTaskVerifier, "owner-a", "", id, time.Hour)
	require.ErrorContains(t, err, "--job-id")
	_, err = store.Reschedule(ctx, jobqueue.QueueTypeTaskVerifier, "owner-a", old, nil, time.Hour)
	require.NoError(t, err)
	_, err = store.Reschedule(ctx, jobqueue.QueueTypeTaskVerifier, "owner-a", duplicate, nil, time.Hour)
	require.ErrorContains(t, err, "active job")
	rows, err = store.ListFailedFiltered(ctx, nil, "owner-a", [][]byte{id}, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1, "failed restoration must preserve the archive")
	require.Equal(t, duplicate, rows[0].JobID)

	uniqueID := seed(jobqueue.QueueTypeStorageWriter, "owner-race", []byte{7}, time.Hour)
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := store.Reschedule(ctx, jobqueue.QueueTypeStorageWriter, "", uniqueID, nil, time.Hour)
			errors <- err
		})
	}
	wg.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes, "a concurrent caller cannot pick a replacement row")
}
