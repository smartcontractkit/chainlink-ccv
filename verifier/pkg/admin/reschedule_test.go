package admin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

func rescheduleMsgID(b byte) []byte {
	id := make([]byte, 32)
	id[31] = b
	return id
}

func rescheduleTargetString(node, jobID string, id []byte, queue jobqueue.QueueType, owner string) string {
	return strings.Join([]string{node, jobID, formatMessageID(id), string(queue), owner}, "|")
}

// rescheduleFakeStore simulates the archive tables: a successful reschedule removes the
// row (moved to active), a failed one leaves it untouched.
type rescheduleFakeStore struct {
	mu            sync.Mutex
	jobs          []jobqueue.ArchivedJob
	rescheduleErr map[string]error // jobID → error
	calls         []rescheduleCall
}

type rescheduleCall struct {
	queue   jobqueue.QueueType
	ownerID string
	jobID   string
	dur     time.Duration
}

func (f *rescheduleFakeStore) ListFailed(context.Context, []jobqueue.QueueType, string, int) ([]jobqueue.ArchivedJob, error) {
	return nil, nil
}

func (f *rescheduleFakeStore) ListFailedFiltered(_ context.Context, queues []jobqueue.QueueType, ownerID string, messageIDs [][]byte, _ int) ([]jobqueue.ArchivedJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []jobqueue.ArchivedJob
	for _, j := range f.jobs {
		if ownerID != "" && j.OwnerID != ownerID {
			continue
		}
		if len(queues) > 0 && !rescheduleQueueIn(queues, j.Queue) {
			continue
		}
		if len(messageIDs) > 0 && !rescheduleMessageIDIn(messageIDs, j.MessageID) {
			continue
		}
		out = append(out, j)
	}
	return out, nil
}

func rescheduleQueueIn(queues []jobqueue.QueueType, q jobqueue.QueueType) bool {
	for _, x := range queues {
		if x == q {
			return true
		}
	}
	return false
}

func rescheduleMessageIDIn(ids [][]byte, id []byte) bool {
	for _, x := range ids {
		if string(x) == string(id) {
			return true
		}
	}
	return false
}

func (f *rescheduleFakeStore) Reschedule(context.Context, jobqueue.QueueType, string, string, []byte, time.Duration) (jobqueue.ArchivedJob, error) {
	return jobqueue.ArchivedJob{}, errors.New("not implemented")
}

func (f *rescheduleFakeStore) RescheduleByJobID(_ context.Context, queue jobqueue.QueueType, ownerID, jobID string, dur time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rescheduleCall{queue: queue, ownerID: ownerID, jobID: jobID, dur: dur})
	if err, ok := f.rescheduleErr[jobID]; ok {
		return err
	}
	for i, j := range f.jobs {
		if j.JobID == jobID {
			f.jobs = append(f.jobs[:i], f.jobs[i+1:]...)
		}
	}
	return nil
}

func (f *rescheduleFakeStore) RescheduleByMessageID(context.Context, jobqueue.QueueType, string, []byte, time.Duration) error {
	return errors.New("not implemented")
}

// fakeSQLDriver backs the concrete ActionLog without a database: ExecContext calls are
// captured so tests can assert the recorded action rows.
type fakeSQLDriver struct {
	mu    sync.Mutex
	execs [][]driver.NamedValue
	err   error
}

func (d *fakeSQLDriver) Open(string) (driver.Conn, error)             { return &fakeSQLConn{d}, nil }
func (d *fakeSQLDriver) Connect(context.Context) (driver.Conn, error) { return &fakeSQLConn{d}, nil }
func (d *fakeSQLDriver) Driver() driver.Driver                        { return d }

type fakeSQLConn struct{ d *fakeSQLDriver }

func (c *fakeSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no statements") }
func (c *fakeSQLConn) Close() error                        { return nil }
func (c *fakeSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (c *fakeSQLConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	if c.d.err != nil {
		return nil, c.d.err
	}
	c.d.execs = append(c.d.execs, args)
	return driver.RowsAffected(1), nil
}

func (d *fakeSQLDriver) recorded() [][]driver.NamedValue {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]driver.NamedValue(nil), d.execs...)
}

var fakeDriverSeq atomic.Int64

func newFakeActionLog(execErr error) (*ActionLog, *fakeSQLDriver) {
	drv := &fakeSQLDriver{err: execErr}
	sql.Register(fmt.Sprintf("ccv-admin-fake-%d", fakeDriverSeq.Add(1)), drv)
	return NewActionLog(sqlx.NewDb(sql.OpenDB(drv), "postgres")), drv
}

func newRescheduleTestHandlers(t *testing.T, store jobqueue.Store, actions *ActionLog, nodeCfgs ...NodeConfig) *handlers {
	t.Helper()
	lggr := logger.Test(t)
	h := &handlers{lggr: lggr, actions: actions}
	for _, nc := range nodeCfgs {
		h.nodes = append(h.nodes, NewNode(nc, lggr))
	}
	if store != nil {
		orig := nodeJobQueue
		nodeJobQueue = func(*Node) (jobqueue.Store, error) { return store, nil }
		t.Cleanup(func() { nodeJobQueue = orig })
	}
	return h
}

func reschedulePostContext(form url.Values) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req
	c.Set("actor", "tester")
	return c, rec
}

func TestParseRescheduleTarget(t *testing.T) {
	valid := rescheduleTargetString("n1", "job-1", rescheduleMsgID(1), jobqueue.QueueTypeTaskVerifier, "owner-1")
	t.Run("valid", func(t *testing.T) {
		target, err := parseRescheduleTarget(valid)
		require.NoError(t, err)
		require.Equal(t, "n1", target.NodeName)
		require.Equal(t, "job-1", target.JobID)
		require.Equal(t, "owner-1", target.OwnerID)
		require.Equal(t, jobqueue.QueueTypeTaskVerifier, target.Queue)
		require.Equal(t, rescheduleMsgID(1), target.MessageID)
		require.Equal(t, formatMessageID(rescheduleMsgID(1)), target.MessageIDHex)
	})
	for name, raw := range map[string]string{
		"too few fields":  "n1|job-1",
		"bad message hex": "n1|job-1|0xzz|task-verifier|owner-1",
		"short message":   "n1|job-1|0x00|task-verifier|owner-1",
		"bad queue":       "n1|job-1|" + formatMessageID(rescheduleMsgID(1)) + "|executor|owner-1",
		"empty owner":     "n1|job-1|" + formatMessageID(rescheduleMsgID(1)) + "|task-verifier|",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseRescheduleTarget(raw)
			require.Error(t, err)
		})
	}
}

func TestParseRetryDuration(t *testing.T) {
	d, err := parseRetryDuration("")
	require.NoError(t, err)
	require.Equal(t, time.Hour, d, "empty defaults to 1h")
	d, err = parseRetryDuration("30m")
	require.NoError(t, err)
	require.Equal(t, 30*time.Minute, d)
	for _, raw := range []string{"abc", "0", "-5m", "0s"} {
		_, err := parseRetryDuration(raw)
		require.Error(t, err, raw)
	}
}

func TestReschedulePreviewExcludesAttested(t *testing.T) {
	id := rescheduleMsgID(1)
	store := &rescheduleFakeStore{jobs: []jobqueue.ArchivedJob{{
		JobID: "job-1", MessageID: id, OwnerID: "owner-1",
		Queue: jobqueue.QueueTypeTaskVerifier, FailureCategory: "policy-timeout",
	}}}
	installFakeVerifier(t, &fakeVerifierServer{results: map[string][]byte{string(id): {0x01}}})
	h := newRescheduleTestHandlers(t, store, nil, NodeConfig{Name: "n1", AggregatorAddress: "bufnet"})

	c, rec := reschedulePostContext(url.Values{"target": {rescheduleTargetString("n1", "job-1", id, jobqueue.QueueTypeTaskVerifier, "owner-1")}})
	h.reschedulePreview(c)

	body := rec.Body.String()
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, body, "already attested — nothing to do")
	require.Contains(t, body, "disabled")
	require.NotContains(t, body, `name="target"`, "attested target must not be executable")
	require.Contains(t, body, "policy-timeout")
}

func TestReschedulePreviewUnknownDisablesTarget(t *testing.T) {
	id := rescheduleMsgID(2)
	store := &rescheduleFakeStore{jobs: []jobqueue.ArchivedJob{{
		JobID: "job-2", MessageID: id, OwnerID: "owner-1", Queue: jobqueue.QueueTypeStorageWriter,
	}}}
	orig := dialVerifierClient
	dialVerifierClient = func(string) (verifierpb.VerifierClient, io.Closer, error) {
		return nil, nil, errors.New("connection refused")
	}
	t.Cleanup(func() { dialVerifierClient = orig })
	h := newRescheduleTestHandlers(t, store, nil, NodeConfig{Name: "n1", AggregatorAddress: "down:443"})

	c, rec := reschedulePostContext(url.Values{"target": {rescheduleTargetString("n1", "job-2", id, jobqueue.QueueTypeStorageWriter, "owner-1")}})
	h.reschedulePreview(c)

	body := rec.Body.String()
	require.Contains(t, body, "attestation state unknown")
	require.Contains(t, body, "connection refused")
	require.NotContains(t, body, `name="target"`, "unknown is never proof a replay is needed")
}

func TestReschedulePreviewExecutableTarget(t *testing.T) {
	id := rescheduleMsgID(3)
	store := &rescheduleFakeStore{jobs: []jobqueue.ArchivedJob{{
		JobID: "job-3", MessageID: id, OwnerID: "owner-1",
		Queue: jobqueue.QueueTypeTaskVerifier, FailureCategory: "source-rpc",
	}}}
	installFakeVerifier(t, &fakeVerifierServer{}) // every ID: NotFound
	h := newRescheduleTestHandlers(t, store, nil, NodeConfig{Name: "n1", AggregatorAddress: "bufnet"})

	c, rec := reschedulePostContext(url.Values{"target": {rescheduleTargetString("n1", "job-3", id, jobqueue.QueueTypeTaskVerifier, "owner-1")}})
	h.reschedulePreview(c)

	body := rec.Body.String()
	require.Contains(t, body, `name="target"`)
	require.Contains(t, body, "checked")
	require.Contains(t, body, "re-verifies the message")
	require.Contains(t, body, "retries delivering the saved verification result")
	require.Contains(t, body, "Neither re-checks source-chain finality")
	require.Contains(t, body, "archive → active; attempts reset; new retry deadline")
}

func TestReschedulePreviewSkipsMissingArchiveRowAndUnknownNode(t *testing.T) {
	id := rescheduleMsgID(4)
	store := &rescheduleFakeStore{} // archive empty
	installFakeVerifier(t, &fakeVerifierServer{})
	h := newRescheduleTestHandlers(t, store, nil, NodeConfig{Name: "n1", AggregatorAddress: "bufnet"})

	form := url.Values{"target": {
		rescheduleTargetString("n1", "job-gone", id, jobqueue.QueueTypeTaskVerifier, "owner-1"),
		rescheduleTargetString("ghost", "job-x", id, jobqueue.QueueTypeTaskVerifier, "owner-1"),
	}}
	c, rec := reschedulePostContext(form)
	h.reschedulePreview(c)

	body := rec.Body.String()
	require.Contains(t, body, "no matching failed archive row")
	require.Contains(t, body, "unknown node")
	require.NotContains(t, body, `name="target"`)
}

func TestRescheduleExecuteActiveConflictPreservesArchive(t *testing.T) {
	id := rescheduleMsgID(10)
	conflict := errors.New("restore failed (an active job may already exist): duplicate key value")
	store := &rescheduleFakeStore{
		jobs:          []jobqueue.ArchivedJob{{JobID: "job-x", MessageID: id, OwnerID: "owner-1", Queue: jobqueue.QueueTypeTaskVerifier}},
		rescheduleErr: map[string]error{"job-x": conflict},
	}
	actions, drv := newFakeActionLog(nil)
	h := newRescheduleTestHandlers(t, store, actions, NodeConfig{Name: "n1"})

	c, rec := reschedulePostContext(url.Values{"target": {rescheduleTargetString("n1", "job-x", id, jobqueue.QueueTypeTaskVerifier, "owner-1")}})
	h.rescheduleExecute(c)

	body := rec.Body.String()
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, body, "failed")
	require.Contains(t, body, "active job may already exist")
	require.Len(t, store.jobs, 1, "archive row preserved on conflict")
	require.Len(t, store.calls, 1)
	require.Equal(t, time.Hour, store.calls[0].dur, "default retry duration")
	require.Equal(t, jobqueue.QueueTypeTaskVerifier, store.calls[0].queue)
	require.Equal(t, "owner-1", store.calls[0].ownerID)

	execs := drv.recorded()
	require.Len(t, execs, 1)
	require.Equal(t, "failed", execs[0][5].Value)
	require.Equal(t, conflict.Error(), execs[0][6].Value)
}

func TestRescheduleExecutePartialSuccess(t *testing.T) {
	idA, idB := rescheduleMsgID(11), rescheduleMsgID(12)
	store := &rescheduleFakeStore{
		jobs: []jobqueue.ArchivedJob{
			{JobID: "job-a", MessageID: idA, OwnerID: "owner-1", Queue: jobqueue.QueueTypeTaskVerifier},
			{JobID: "job-b", MessageID: idB, OwnerID: "owner-1", Queue: jobqueue.QueueTypeStorageWriter},
		},
		rescheduleErr: map[string]error{"job-b": errors.New("boom")},
	}
	actions, drv := newFakeActionLog(nil)
	h := newRescheduleTestHandlers(t, store, actions, NodeConfig{Name: "n1"})

	tA := rescheduleTargetString("n1", "job-a", idA, jobqueue.QueueTypeTaskVerifier, "owner-1")
	tB := rescheduleTargetString("n1", "job-b", idB, jobqueue.QueueTypeStorageWriter, "owner-1")
	c, rec := reschedulePostContext(url.Values{"target": {tA, tB}, "retry_duration": {"30m"}})
	h.rescheduleExecute(c)

	body := rec.Body.String()
	require.Contains(t, body, "success")
	require.Contains(t, body, "boom")
	require.Len(t, store.calls, 2, "both targets attempted independently")
	require.Equal(t, 30*time.Minute, store.calls[0].dur)
	require.Len(t, store.jobs, 1, "only the failed job stays archived")
	require.Equal(t, "job-b", store.jobs[0].JobID)

	// The retry form carries only the non-success target, marked as a retry.
	require.Contains(t, body, `name="retry" value="failed"`)
	require.Equal(t, 1, strings.Count(body, `name="target"`))

	execs := drv.recorded()
	require.Len(t, execs, 2)
	require.Equal(t, "success", execs[0][5].Value)
	require.Equal(t, "failed", execs[1][5].Value)
}

func TestRescheduleExecuteRetryFailedSkipsSuccesses(t *testing.T) {
	idA, idB := rescheduleMsgID(13), rescheduleMsgID(14)
	store := &rescheduleFakeStore{
		jobs: []jobqueue.ArchivedJob{
			{JobID: "job-a", MessageID: idA, OwnerID: "owner-1", Queue: jobqueue.QueueTypeStorageWriter},
			{JobID: "job-b", MessageID: idB, OwnerID: "owner-1", Queue: jobqueue.QueueTypeStorageWriter},
		},
		rescheduleErr: map[string]error{"job-b": errors.New("boom")},
	}
	installFakeVerifier(t, &fakeVerifierServer{}) // NotFound: replays remain needed
	actions, _ := newFakeActionLog(nil)
	h := newRescheduleTestHandlers(t, store, actions, NodeConfig{Name: "n1", AggregatorAddress: "bufnet"})

	tA := rescheduleTargetString("n1", "job-a", idA, jobqueue.QueueTypeStorageWriter, "owner-1")
	tB := rescheduleTargetString("n1", "job-b", idB, jobqueue.QueueTypeStorageWriter, "owner-1")
	c, _ := reschedulePostContext(url.Values{"target": {tA, tB}})
	h.rescheduleExecute(c)
	require.Len(t, store.calls, 2)

	// Retry resubmits both targets; the previous success must not be re-executed.
	c2, rec2 := reschedulePostContext(url.Values{"target": {tA, tB}, "retry": {"failed"}})
	h.rescheduleExecute(c2)

	require.Len(t, store.calls, 3, "only the still-failed target is re-attempted")
	require.Equal(t, "job-b", store.calls[2].jobID)
	body := rec2.Body.String()
	require.Contains(t, body, "skipped")
	require.Contains(t, body, "no matching failed archive row")
	require.Contains(t, body, "boom")
}

func TestRescheduleExecuteRecordsActionLogPerTarget(t *testing.T) {
	idA, idB := rescheduleMsgID(15), rescheduleMsgID(16)
	store := &rescheduleFakeStore{jobs: []jobqueue.ArchivedJob{
		{JobID: "job-a", MessageID: idA, OwnerID: "owner-1", Queue: jobqueue.QueueTypeTaskVerifier},
		{JobID: "job-b", MessageID: idB, OwnerID: "owner-2", Queue: jobqueue.QueueTypeTaskVerifier},
	}}
	actions, drv := newFakeActionLog(nil)
	h := newRescheduleTestHandlers(t, store, actions, NodeConfig{Name: "n1"})

	form := url.Values{"target": {
		rescheduleTargetString("n1", "job-a", idA, jobqueue.QueueTypeTaskVerifier, "owner-1"),
		rescheduleTargetString("n1", "job-b", idB, jobqueue.QueueTypeTaskVerifier, "owner-2"),
	}}
	c, _ := reschedulePostContext(form)
	h.rescheduleExecute(c)

	// Column order of ActionLog.Record's INSERT: actor, action, node, target, op, outcome, detail.
	execs := drv.recorded()
	require.Len(t, execs, 2)
	for i, id := range [][]byte{idA, idB} {
		args := execs[i]
		require.Equal(t, "tester", args[0].Value)
		require.Equal(t, "reschedule", args[1].Value)
		require.Equal(t, "n1", args[2].Value)
		require.Equal(t, formatMessageID(id), args[3].Value)
		require.Equal(t, "", args[4].Value)
		require.Equal(t, "success", args[5].Value)
		require.Contains(t, args[6].Value, "restored archive")
	}
}

func TestRescheduleExecuteSurfacesAuditError(t *testing.T) {
	id := rescheduleMsgID(17)
	store := &rescheduleFakeStore{jobs: []jobqueue.ArchivedJob{{
		JobID: "job-a", MessageID: id, OwnerID: "owner-1", Queue: jobqueue.QueueTypeTaskVerifier,
	}}}
	actions, _ := newFakeActionLog(errors.New("disk full"))
	h := newRescheduleTestHandlers(t, store, actions, NodeConfig{Name: "n1"})

	c, rec := reschedulePostContext(url.Values{"target": {rescheduleTargetString("n1", "job-a", id, jobqueue.QueueTypeTaskVerifier, "owner-1")}})
	h.rescheduleExecute(c)

	body := rec.Body.String()
	require.Len(t, store.calls, 1, "mutation still happened")
	require.Contains(t, body, "Action log write failed")
	require.Contains(t, body, "disk full", "unaudited mutations must not pass silently")
}

func TestRescheduleExecuteReadOnlyMode(t *testing.T) {
	h := newRescheduleTestHandlers(t, &rescheduleFakeStore{}, nil, NodeConfig{Name: "n1"})
	c, rec := reschedulePostContext(url.Values{"target": {rescheduleTargetString("n1", "job-a", rescheduleMsgID(18), jobqueue.QueueTypeTaskVerifier, "owner-1")}})
	h.rescheduleExecute(c)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "Read-only mode")
}

func TestRescheduleExecuteBadInput(t *testing.T) {
	actions, _ := newFakeActionLog(nil)
	h := newRescheduleTestHandlers(t, &rescheduleFakeStore{}, actions, NodeConfig{Name: "n1"})

	c, rec := reschedulePostContext(url.Values{"target": {"x"}, "retry_duration": {"abc"}})
	h.rescheduleExecute(c)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid retry_duration")

	c, rec = reschedulePostContext(url.Values{"retry_duration": {"1h"}})
	h.rescheduleExecute(c)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "No targets selected")

	c, rec = reschedulePostContext(url.Values{"target": {"not-a-target"}})
	h.rescheduleExecute(c)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "invalid target")
}
