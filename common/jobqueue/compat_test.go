package jobqueue_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/migrations"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// The legacy* statements are copied verbatim from the queue before the dedup key change
// (commit b6f7cd3f). They stand in for an older verifier that shares the table.
const (
	legacyPublish = `INSERT INTO %s
		(job_id, task_data, status, available_at, created_at, attempt_count, retry_deadline, chain_selector, message_id, owner_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (owner_id, chain_selector, message_id) DO NOTHING`

	legacyConsumePending = `
		UPDATE %[1]s
		SET status = $1,
		    started_at = $2,
		    attempt_count = attempt_count + 1
		WHERE id IN (
		    SELECT id FROM %[1]s
		    WHERE owner_id = $3
		      AND status = $4
		      AND available_at <= $5
		    ORDER BY available_at ASC, id ASC
		    LIMIT $6
		    FOR UPDATE SKIP LOCKED
		)
		RETURNING id, job_id, task_data, attempt_count, retry_deadline, created_at, started_at, chain_selector, message_id
	`

	legacyComplete = `
		WITH completed AS (
			DELETE FROM %s
			WHERE job_id = ANY($1)
			  AND owner_id = $2
			RETURNING id, job_id, owner_id, chain_selector, message_id, task_data,
			          created_at, available_at, started_at, attempt_count, retry_deadline, last_error
		)
		INSERT INTO %s (
			id, job_id, owner_id, chain_selector, message_id, task_data,
			status, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
			completed_at
		)
		SELECT id, job_id, owner_id, chain_selector, message_id, task_data,
		       $3, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
		       NOW()
		FROM completed
	`
)

const compatOwner = "test-verifier"

var compatTable = verifier.TaskVerifierJobsTableName

func legacyPublishJob(t *testing.T, ds sqlutil.DataSource, job testJob) int64 {
	t.Helper()
	return legacyPublishTo(t, ds, compatTable, job)
}

func legacyPublishTo(t *testing.T, ds sqlutil.DataSource, table string, job testJob) int64 {
	t.Helper()
	data, err := json.Marshal(job)
	require.NoError(t, err)
	now := time.Now()
	res, err := ds.ExecContext(context.Background(), fmt.Sprintf(legacyPublish, table),
		uuid.NewString(), data, jobqueue.JobStatusPending, now, now, 0, now.Add(time.Hour),
		new(big.Int).SetUint64(job.Chain).String(), job.Message, compatOwner)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	return n
}

type legacyRow struct {
	jobID         string
	chainSelector string
	messageID     []byte
}

func legacyConsume(t *testing.T, ds sqlutil.DataSource) []legacyRow {
	t.Helper()
	return legacyConsumeFrom(t, ds, compatTable)
}

func legacyConsumeFrom(t *testing.T, ds sqlutil.DataSource, table string) []legacyRow {
	t.Helper()
	now := time.Now()
	rows, err := ds.QueryContext(context.Background(), fmt.Sprintf(legacyConsumePending, table),
		jobqueue.JobStatusProcessing, now, compatOwner, jobqueue.JobStatusPending, now, 10)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []legacyRow
	for rows.Next() {
		var (
			id                  int64
			r                   legacyRow
			data                []byte
			attempts            int
			deadline, createdAt time.Time
			startedAt           *time.Time
		)
		require.NoError(t, rows.Scan(&id, &r.jobID, &data, &attempts, &deadline, &createdAt, &startedAt, &r.chainSelector, &r.messageID))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func legacyCompleteJobs(t *testing.T, ds sqlutil.DataSource, jobIDs ...string) {
	t.Helper()
	legacyCompleteIn(t, ds, compatTable, jobIDs...)
}

func legacyCompleteIn(t *testing.T, ds sqlutil.DataSource, table string, jobIDs ...string) {
	t.Helper()
	_, err := ds.ExecContext(context.Background(), fmt.Sprintf(legacyComplete, table, table+"_archive"),
		pq.Array(jobIDs), compatOwner, jobqueue.JobStatusCompleted)
	require.NoError(t, err)
}

var keyModes = map[string]jobqueue.KeyColumns{
	"DedupKeyColumn":    jobqueue.DedupKeyColumn,
	"MessageKeyColumns": jobqueue.MessageKeyColumns,
}

func withKeys(k jobqueue.KeyColumns) func(*jobqueue.QueueConfig) {
	return func(c *jobqueue.QueueConfig) { c.KeyColumns = k }
}

// The cross-version tests run old SQL next to the new code on the migrated schema, which is
// an upgrade or a code rollback on a standalone verifier.
func TestLegacyWriterNewReader(t *testing.T) {
	for name, keys := range keyModes {
		t.Run(name, func(t *testing.T) {
			q, ds := newTestQueue(t, withKeys(keys))
			ctx := context.Background()
			job := testJob{Chain: 1, Message: []byte{0xaa, 0x01}, Data: "legacy"}
			require.EqualValues(t, 1, legacyPublishJob(t, ds, job))

			jobs, err := q.ConsumePending(ctx, 10)
			require.NoError(t, err)
			require.Len(t, jobs, 1)
			assert.Equal(t, job, jobs[0].Payload)
			assert.Equal(t, "aa01:1", jobs[0].DedupKey)

			require.NoError(t, q.Complete(ctx, jobs[0].ID))
			assert.Equal(t, 0, countAllRows(t, ds, compatTable))
			assert.Equal(t, 1, countRows(t, ds, compatTable+"_archive", jobqueue.JobStatusCompleted))
		})
	}
}

func TestNewWriterLegacyReader(t *testing.T) {
	for name, keys := range keyModes {
		t.Run(name, func(t *testing.T) {
			q, ds := newTestQueue(t, withKeys(keys))
			job := testJob{Chain: 2, Message: []byte{0xbb}, Data: "new"}
			require.NoError(t, q.Publish(context.Background(), job))

			rows := legacyConsume(t, ds)
			require.Len(t, rows, 1)
			assert.Equal(t, "2", rows[0].chainSelector)
			assert.Equal(t, job.Message, rows[0].messageID)

			legacyCompleteJobs(t, ds, rows[0].jobID)
			assert.Equal(t, 0, countAllRows(t, ds, compatTable))
			assert.Equal(t, 1, countRows(t, ds, compatTable+"_archive", jobqueue.JobStatusCompleted))
		})
	}
}

func TestDedupAcrossVersions(t *testing.T) {
	ctx := context.Background()
	for name, keys := range keyModes {
		t.Run(name+"/legacy then new", func(t *testing.T) {
			q, ds := newTestQueue(t, withKeys(keys))
			job := testJob{Chain: 3, Message: []byte{0x03}, Data: "x"}
			require.EqualValues(t, 1, legacyPublishJob(t, ds, job))
			inserted, err := q.PublishInTransaction(ctx, ds, job)
			require.NoError(t, err)
			assert.Zero(t, inserted)
			assert.Equal(t, 1, countAllRows(t, ds, compatTable))
		})

		t.Run(name+"/new then legacy", func(t *testing.T) {
			q, ds := newTestQueue(t, withKeys(keys))
			job := testJob{Chain: 4, Message: []byte{0x04}, Data: "x"}
			require.NoError(t, q.Publish(ctx, job))
			assert.Zero(t, legacyPublishJob(t, ds, job))
			assert.Equal(t, 1, countAllRows(t, ds, compatTable))
		})
	}
}

// TestInFlightAcrossVersions covers a job that one version claims and the other finishes.
func TestInFlightAcrossVersions(t *testing.T) {
	for name, keys := range keyModes {
		t.Run(name, func(t *testing.T) {
			q, ds := newTestQueue(t, withKeys(keys), func(c *jobqueue.QueueConfig) { c.LockDuration = time.Millisecond })
			ctx := context.Background()
			require.EqualValues(t, 1, legacyPublishJob(t, ds, testJob{Chain: 5, Message: []byte{0x05}}))
			require.Len(t, legacyConsume(t, ds), 1)

			time.Sleep(10 * time.Millisecond)
			jobs, err := q.ReclaimStale(ctx, 10)
			require.NoError(t, err)
			require.Len(t, jobs, 1)
			require.NoError(t, q.Retry(ctx, 0, nil, jobs[0].ID))

			rows := legacyConsume(t, ds)
			require.Len(t, rows, 1)
			legacyCompleteJobs(t, ds, rows[0].jobID)
			assert.Equal(t, 0, countAllRows(t, ds, compatTable))
		})
	}
}

// TestMigrationDedupKeyFormat checks that the trigger and jobqueue.MessageDedupKey agree.
func TestMigrationDedupKeyFormat(t *testing.T) {
	_, ds := newTestQueue(t)
	job := testJob{Chain: math.MaxUint64, Message: []byte{0x00, 0xab, 0xff}}
	require.EqualValues(t, 1, legacyPublishJob(t, ds, job))

	var key string
	require.NoError(t, ds.GetContext(context.Background(), &key, fmt.Sprintf(`SELECT dedup_key FROM %s`, compatTable)))
	assert.Equal(t, jobqueue.MessageDedupKey(job.Chain, job.Message), key)
	assert.Equal(t, job.DedupKey(), key)
}

// TestMigrationRollback runs the down migration with jobs from the new code in the tables,
// then the up migration with jobs from the old code. The schema after down is also the
// Chainlink-node schema.
func TestMigrationRollback(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	cfg := jobqueue.QueueConfig{Name: compatTable, OwnerID: compatOwner, RetryDuration: time.Hour, LockDuration: time.Minute}
	newQueue := func(keys jobqueue.KeyColumns) *jobqueue.PostgresJobQueue[testJob] {
		c := cfg
		c.KeyColumns = keys
		q, err := jobqueue.NewPostgresJobQueue[testJob](db, c, logger.Test(t))
		require.NoError(t, err)
		return q
	}

	dq := newQueue(jobqueue.DedupKeyColumn)
	require.NoError(t, dq.Publish(ctx, testJob{Chain: 1, Message: []byte{0x01}}, testJob{Chain: 1, Message: []byte{0x02}}))
	jobs, err := dq.ConsumePending(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, dq.Complete(ctx, jobs[0].ID))

	goose.SetBaseFS(migrations.PostgresMigrations)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.DownTo(db.DB, "postgres", dedupKeyMigration-1))

	// The old code and MessageKeyColumns work on the schema without dedup_key.
	assert.Zero(t, legacyPublishJob(t, db, testJob{Chain: 1, Message: []byte{0x02}}))
	rows := legacyConsume(t, db)
	require.Len(t, rows, 1)
	legacyCompleteJobs(t, db, rows[0].jobID)

	mq := newQueue(jobqueue.MessageKeyColumns)
	require.NoError(t, mq.Publish(ctx, testJob{Chain: 1, Message: []byte{0x03}}))
	require.EqualValues(t, 1, legacyPublishJob(t, db, testJob{Chain: 1, Message: []byte{0x04}}))
	_, err = dq.ConsumePending(ctx, 10)
	require.Error(t, err, "DedupKeyColumn needs the migration")

	require.NoError(t, goose.UpTo(db.DB, "postgres", dedupKeyMigration))

	// The backfill gives the old rows the key that the new code computes.
	require.NoError(t, dq.Publish(ctx, testJob{Chain: 1, Message: []byte{0x03}}, testJob{Chain: 1, Message: []byte{0x04}}))
	jobs, err = dq.ConsumePending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, jobs, 2)
	for _, j := range jobs {
		assert.Equal(t, jobqueue.MessageDedupKey(j.Payload.Chain, j.Payload.Message), j.DedupKey)
	}
	require.NoError(t, dq.Complete(ctx, jobs[0].ID, jobs[1].ID))
	assert.Equal(t, 4, countRows(t, db, compatTable+"_archive", jobqueue.JobStatusCompleted))
}

// dedupKeyMigration is the goose version of 00010_job_queue_dedup_key.sql.
const dedupKeyMigration = 10

type keylessJob struct {
	Key string `json:"key"`
}

func (j keylessJob) DedupKey() string { return j.Key }

func TestMessageKeyColumnsRequiresMessageKeyed(t *testing.T) {
	_, ds := newTestQueue(t)
	_, err := jobqueue.NewPostgresJobQueue[keylessJob](ds, jobqueue.QueueConfig{
		Name: compatTable, KeyColumns: jobqueue.MessageKeyColumns,
	}, logger.Test(t))
	require.Error(t, err)
}

func TestDedupKeyColumn(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	const table = "test_dedup_jobs"
	_, err := db.ExecContext(ctx, jobqueue.CreateTablesSQL(table))
	require.NoError(t, err)

	q, err := jobqueue.NewPostgresJobQueue[keylessJob](db, jobqueue.QueueConfig{
		Name: table, OwnerID: "agg", RetryDuration: time.Hour, LockDuration: time.Minute,
		KeyColumns: jobqueue.DedupKeyColumn,
	}, logger.Test(t))
	require.NoError(t, err)

	require.NoError(t, q.Publish(ctx, keylessJob{Key: "a"}, keylessJob{Key: "b"}, keylessJob{Key: "a"}))
	assert.Equal(t, 2, countAllRows(t, db, table))

	jobs, err := q.ConsumePending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, jobs, 2)
	byKey := map[string]jobqueue.Job[keylessJob]{}
	for _, j := range jobs {
		byKey[j.DedupKey] = j
		assert.Equal(t, j.DedupKey, j.Payload.Key)
	}

	require.NoError(t, q.Complete(ctx, byKey["a"].ID))
	require.NoError(t, q.Fail(ctx, nil, byKey["b"].ID))
	assert.Equal(t, 0, countAllRows(t, db, table))

	var archived []string
	require.NoError(t, sqlxSelect(db, &archived, fmt.Sprintf(`SELECT dedup_key FROM %s_archive ORDER BY dedup_key`, table)))
	assert.Equal(t, []string{"a", "b"}, archived)

	// The key is free again once the job has left the active table.
	require.NoError(t, q.Publish(ctx, keylessJob{Key: "a"}))
	jobs, err = q.ConsumePending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.NoError(t, q.Retry(ctx, time.Hour, nil, jobs[0].ID))
	size, err := q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, size)
}

func sqlxSelect(ds sqlutil.DataSource, dest any, query string, args ...any) error {
	return ds.SelectContext(context.Background(), dest, query, args...)
}

// aggJob has a dedup key that is not derived from its message, like an aggregation key.
type aggJob struct {
	Chain   uint64 `json:"chain"`
	Message []byte `json:"message"`
	Key     string `json:"key"`
}

func (j aggJob) DedupKey() string                                 { return j.Key }
func (j aggJob) JobKey() (chainSelector uint64, messageID []byte) { return j.Chain, j.Message }

// aggKeyJob is aggJob without JobKey, as in a new table that has no legacy columns.
type aggKeyJob struct {
	Message []byte `json:"message"`
	Key     string `json:"key"`
}

func (j aggKeyJob) DedupKey() string { return j.Key }

func toAggKeyJobs(jobs []aggJob) []aggKeyJob {
	out := make([]aggKeyJob, len(jobs))
	for i, j := range jobs {
		out[i] = aggKeyJob{Message: j.Message, Key: j.Key}
	}
	return out
}

// TestCustomDedupKey shows which key decides a duplicate in each mode.
func TestCustomDedupKey(t *testing.T) {
	ctx := context.Background()
	sameMsgOtherKey := []aggJob{
		{Chain: 1, Message: []byte{0x01}, Key: "agg-1"},
		{Chain: 1, Message: []byte{0x01}, Key: "agg-2"},
	}
	sameKeyOtherMsg := []aggJob{
		{Chain: 1, Message: []byte{0x02}, Key: "agg-3"},
		{Chain: 1, Message: []byte{0x03}, Key: "agg-3"},
	}

	t.Run("MessageKeyColumns uses the message columns", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		q, err := jobqueue.NewPostgresJobQueue[aggJob](db, jobqueue.QueueConfig{
			Name: compatTable, OwnerID: compatOwner, RetryDuration: time.Hour, LockDuration: time.Minute,
			KeyColumns: jobqueue.MessageKeyColumns,
		}, logger.Test(t))
		require.NoError(t, err)

		require.NoError(t, q.Publish(ctx, sameMsgOtherKey...))
		require.NoError(t, q.Publish(ctx, sameKeyOtherMsg...))
		assert.Equal(t, 3, countAllRows(t, db, compatTable))

		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		keys := map[string]int{}
		for _, j := range jobs {
			assert.Equal(t, j.Payload.Key, j.DedupKey)
			keys[j.DedupKey]++
		}
		assert.Equal(t, map[string]int{"agg-1": 1, "agg-3": 2}, keys)
	})

	t.Run("DedupKeyColumn uses DedupKey", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		const table = "test_agg_jobs"
		_, err := db.ExecContext(ctx, jobqueue.CreateTablesSQL(table))
		require.NoError(t, err)
		q, err := jobqueue.NewPostgresJobQueue[aggKeyJob](db, jobqueue.QueueConfig{
			Name: table, OwnerID: "agg", RetryDuration: time.Hour, LockDuration: time.Minute,
			KeyColumns: jobqueue.DedupKeyColumn,
		}, logger.Test(t))
		require.NoError(t, err)

		require.NoError(t, q.Publish(ctx, toAggKeyJobs(sameMsgOtherKey)...))
		require.NoError(t, q.Publish(ctx, toAggKeyJobs(sameKeyOtherMsg)...))
		assert.Equal(t, 3, countAllRows(t, db, table))

		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		keys := map[string][]byte{}
		for _, j := range jobs {
			assert.Equal(t, j.Payload.Key, j.DedupKey)
			keys[j.DedupKey] = j.Payload.Message
		}
		assert.Equal(t, map[string][]byte{"agg-1": {0x01}, "agg-2": {0x01}, "agg-3": {0x02}}, keys)
	})
}

// TestLegacyColumnsOnlyForMessageKeyed shows that a MessageKeyed payload writes the legacy
// columns, so it cannot use a CreateTablesSQL table that does not have them.
func TestLegacyColumnsOnlyForMessageKeyed(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	const table = "test_new_jobs"
	_, err := db.ExecContext(ctx, jobqueue.CreateTablesSQL(table))
	require.NoError(t, err)

	q, err := jobqueue.NewPostgresJobQueue[aggJob](db, jobqueue.QueueConfig{
		Name: table, OwnerID: "agg", RetryDuration: time.Hour, LockDuration: time.Minute,
	}, logger.Test(t))
	require.NoError(t, err)
	require.ErrorContains(t, q.Publish(ctx, aggJob{Chain: 1, Message: []byte{0x01}, Key: "k"}), "chain_selector")
}

// TestNodeSchema runs MessageKeyColumns on the schema without dedup_key, as on a Chainlink node,
// for both verifier tables and every queue operation.
func TestNodeSchema(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{verifier.TaskVerifierJobsTableName, verifier.StorageWriterJobsTableName} {
		t.Run(table, func(t *testing.T) {
			db := testutil.NewTestDB(t)
			goose.SetBaseFS(migrations.PostgresMigrations)
			require.NoError(t, goose.SetDialect("postgres"))
			require.NoError(t, goose.DownTo(db.DB, "postgres", dedupKeyMigration-1))
			for _, tbl := range []string{table, table + "_archive"} {
				var cols []string
				require.NoError(t, sqlxSelect(db, &cols, `SELECT column_name FROM information_schema.columns WHERE table_name = $1`, tbl))
				require.NotContains(t, cols, "dedup_key", tbl)
			}

			newQueue := func(retry, lock time.Duration) *jobqueue.PostgresJobQueue[testJob] {
				q, err := jobqueue.NewPostgresJobQueue[testJob](db, jobqueue.QueueConfig{
					Name: table, OwnerID: compatOwner, RetryDuration: retry, LockDuration: lock,
					KeyColumns: jobqueue.MessageKeyColumns,
				}, logger.Test(t))
				require.NoError(t, err)
				return q
			}
			q := newQueue(time.Hour, time.Minute)
			archive := table + "_archive"

			t.Run("old publishes, new consumes and completes", func(t *testing.T) {
				job := testJob{Chain: 1, Message: []byte{0x01}, Data: "old"}
				require.EqualValues(t, 1, legacyPublishTo(t, db, table, job))
				jobs, err := q.ConsumePending(ctx, 10)
				require.NoError(t, err)
				require.Len(t, jobs, 1)
				assert.Equal(t, job, jobs[0].Payload)
				assert.Equal(t, job.DedupKey(), jobs[0].DedupKey)
				require.NoError(t, q.Complete(ctx, jobs[0].ID))
				assert.Equal(t, 0, countAllRows(t, db, table))
			})

			t.Run("new publishes, old consumes and completes", func(t *testing.T) {
				job := testJob{Chain: 2, Message: []byte{0x02}, Data: "new"}
				require.NoError(t, q.Publish(ctx, job))
				rows := legacyConsumeFrom(t, db, table)
				require.Len(t, rows, 1)
				assert.Equal(t, "2", rows[0].chainSelector)
				assert.Equal(t, job.Message, rows[0].messageID)
				legacyCompleteIn(t, db, table, rows[0].jobID)
				assert.Equal(t, 0, countAllRows(t, db, table))
			})

			t.Run("dedup in both directions", func(t *testing.T) {
				oldFirst := testJob{Chain: 3, Message: []byte{0x03}}
				require.EqualValues(t, 1, legacyPublishTo(t, db, table, oldFirst))
				inserted, err := q.PublishInTransaction(ctx, db, oldFirst)
				require.NoError(t, err)
				assert.Zero(t, inserted)

				newFirst := testJob{Chain: 4, Message: []byte{0x04}}
				require.NoError(t, q.Publish(ctx, newFirst))
				assert.Zero(t, legacyPublishTo(t, db, table, newFirst))
				assert.Equal(t, 2, countAllRows(t, db, table))

				jobs, err := q.ConsumePending(ctx, 10)
				require.NoError(t, err)
				require.Len(t, jobs, 2)
				require.NoError(t, q.Complete(ctx, jobs[0].ID, jobs[1].ID))
			})

			t.Run("reclaim, retry, deadline archive, fail", func(t *testing.T) {
				short := newQueue(time.Hour, time.Millisecond)
				require.NoError(t, short.Publish(ctx, testJob{Chain: 5, Message: []byte{0x05}}, testJob{Chain: 5, Message: []byte{0x06}}))
				jobs, err := short.ConsumePending(ctx, 10)
				require.NoError(t, err)
				require.Len(t, jobs, 2)

				time.Sleep(10 * time.Millisecond)
				reclaimed, err := short.ReclaimStale(ctx, 10)
				require.NoError(t, err)
				require.Len(t, reclaimed, 2)

				require.NoError(t, short.Retry(ctx, 0, map[string]error{reclaimed[0].ID: errors.New("retry")}, reclaimed[0].ID))
				require.NoError(t, short.Fail(ctx, map[string]error{reclaimed[1].ID: errors.New("fail")}, reclaimed[1].ID))
				assert.Equal(t, 1, countRows(t, db, archive, jobqueue.JobStatusFailed))

				jobs, err = short.ConsumePending(ctx, 10)
				require.NoError(t, err)
				require.Len(t, jobs, 1)
				require.NoError(t, short.Complete(ctx, jobs[0].ID))

				// retry_deadline is set on publish, so this queue publishes already expired jobs.
				expired := newQueue(time.Nanosecond, time.Minute)
				require.NoError(t, expired.Publish(ctx, testJob{Chain: 5, Message: []byte{0x07}}))
				jobs, err = expired.ConsumePending(ctx, 10)
				require.NoError(t, err)
				require.Len(t, jobs, 1)
				require.NoError(t, expired.Retry(ctx, 0, nil, jobs[0].ID))
				assert.Equal(t, 0, countAllRows(t, db, table))
				assert.Equal(t, 2, countRows(t, db, archive, jobqueue.JobStatusFailed))

				var missing int
				require.NoError(t, db.GetContext(ctx, &missing, fmt.Sprintf(
					`SELECT COUNT(*) FROM %s WHERE chain_selector IS NULL OR message_id IS NULL`, archive)))
				assert.Zero(t, missing)
			})
		})
	}
}
