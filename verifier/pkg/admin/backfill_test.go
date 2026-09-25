package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/replay"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const testMessageID = "0x00000000000000000000000000000000000000000000000000000000000000aa"

type fakeReplayRunner struct {
	startFn func(context.Context, replay.Request) (string, error)
}

func (f *fakeReplayRunner) Start(ctx context.Context, req replay.Request) (string, error) {
	if f.startFn == nil {
		return "", errors.New("unexpected Start call")
	}
	return f.startFn(ctx, req)
}

type fakeReplayLister struct {
	mu   sync.Mutex
	jobs []replay.Job
	err  error
}

func (f *fakeReplayLister) ListJobs(context.Context) ([]replay.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]replay.Job(nil), f.jobs...), f.err
}

func (f *fakeReplayLister) add(j replay.Job) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, j)
}

// registerJobOnStart mirrors the real engine: the durable job row exists as soon as
// Start runs, so the handler's job correlation finds it. Each request is forwarded
// on reqs for assertions (Start runs on a detached goroutine in production code).
func registerJobOnStart(lister *fakeReplayLister, reqs chan replay.Request) func(context.Context, replay.Request) (string, error) {
	var seq atomic.Int64
	return func(_ context.Context, req replay.Request) (string, error) {
		id := fmt.Sprintf("job-%d", seq.Add(1))
		lister.add(replay.Job{
			ID: id, Type: req.Type, Status: replay.StatusRunning, RequestHash: req.Hash(),
			CreatedAt: time.Now(), LastHeartbeat: time.Now(),
		})
		if reqs != nil {
			reqs <- req
		}
		return id, nil
	}
}

func newBackfillTestRouter(t *testing.T, runner replayRunner, lister replayJobLister, actions *ActionLog, indexerPath string) *gin.Engine {
	t.Helper()
	oldEngine, oldJobs := backfillEngineFor, backfillJobsFor
	backfillEngineFor = func(context.Context, logger.Logger, *Node) (replayRunner, func(), error) {
		return runner, func() {}, nil
	}
	backfillJobsFor = func(context.Context, logger.Logger, *Node) (replayJobLister, error) { return lister, nil }
	t.Cleanup(func() { backfillEngineFor, backfillJobsFor = oldEngine, oldJobs })

	gin.SetMode(gin.TestMode)
	n := NewNode(NodeConfig{Name: "node-a", SecretsPath: "/nonexistent/secrets.toml", IndexerConfigPath: indexerPath}, logger.Test(t))
	h := &handlers{cfg: &Config{}, lggr: logger.Test(t), nodes: []*Node{n}, actions: actions}
	r := gin.New()
	h.registerBackfillRoutes(r)
	return r
}

func recvRequest(t *testing.T, reqs chan replay.Request) replay.Request {
	t.Helper()
	select {
	case req := <-reqs:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("engine Start was not called")
		return replay.Request{}
	}
}

func TestBackfillRejectsMixedInputs(t *testing.T) {
	actions, _ := newCaptureActionLog(t)
	runner := &fakeReplayRunner{startFn: func(context.Context, replay.Request) (string, error) {
		t.Fatal("engine must not run when the form mixes discovery and targeted inputs")
		return "", nil
	}}
	r := newBackfillTestRouter(t, runner, &fakeReplayLister{}, actions, "/idx/config.toml")

	rec := postForm(r, "/backfill/submit", url.Values{
		"node": {"node-a"}, "since": {"42"}, "message_ids": {testMessageID},
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "not both")
}

func TestBackfillSubmitDiscoveryRecordsJob(t *testing.T) {
	actions, captured := newCaptureActionLog(t)
	wantHash := (replay.Request{Type: replay.TypeDiscovery, Since: 42}).Hash()
	reqs := make(chan replay.Request, 1)
	lister := &fakeReplayLister{}
	runner := &fakeReplayRunner{startFn: registerJobOnStart(lister, reqs)}
	r := newBackfillTestRouter(t, runner, lister, actions, "/idx/config.toml")

	rec := postForm(r, "/backfill/submit", url.Values{"node": {"node-a"}, "since": {"42"}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "job-1")

	gotReq := recvRequest(t, reqs)
	require.Equal(t, replay.TypeDiscovery, gotReq.Type)
	require.Equal(t, int64(42), gotReq.Since)
	require.False(t, gotReq.Force, "force defaults to off")

	vals := captured.execValues(t, 0)
	require.Equal(t, "backfill-submit", vals[1])
	require.Equal(t, "node-a", vals[2])
	require.Equal(t, "job-1", vals[4])
	require.Equal(t, "success", vals[5])
	require.Contains(t, vals[6], "request_hash="+wantHash)
}

func TestBackfillForceIsExplicitOptIn(t *testing.T) {
	actions, _ := newCaptureActionLog(t)
	reqs := make(chan replay.Request, 2)
	lister := &fakeReplayLister{}
	runner := &fakeReplayRunner{startFn: registerJobOnStart(lister, reqs)}
	r := newBackfillTestRouter(t, runner, lister, actions, "/idx/config.toml")

	rec := postForm(r, "/backfill/submit", url.Values{"node": {"node-a"}, "since": {"1"}, "force": {"on"}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, recvRequest(t, reqs).Force)

	rec = postForm(r, "/backfill/submit", url.Values{"node": {"node-a"}, "message_ids": {testMessageID}})
	require.Equal(t, http.StatusOK, rec.Code)
	req := recvRequest(t, reqs)
	require.False(t, req.Force, "absent checkbox means backfill-only")
	require.Equal(t, replay.TypeMessages, req.Type)
	require.Equal(t, []string{testMessageID}, req.MessageIDs)
}

func TestBackfillRejectsInvalidMessageIDs(t *testing.T) {
	actions, _ := newCaptureActionLog(t)
	runner := &fakeReplayRunner{startFn: func(context.Context, replay.Request) (string, error) {
		t.Fatal("engine must not run for malformed message IDs")
		return "", nil
	}}
	r := newBackfillTestRouter(t, runner, &fakeReplayLister{}, actions, "/idx/config.toml")

	rec := postForm(r, "/backfill/submit", url.Values{"node": {"node-a"}, "message_ids": {"0xdeadbeef"}})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "message-id")
}

func TestBackfillHiddenWithoutOwnedIndexer(t *testing.T) {
	actions, _ := newCaptureActionLog(t)
	r := newBackfillTestRouter(t, &fakeReplayRunner{}, &fakeReplayLister{}, actions, "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/backfill", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "not available")
	require.NotContains(t, rec.Body.String(), `hx-post="/backfill/submit"`, "no submit form without an owned indexer")

	rec = postForm(r, "/backfill/submit", url.Values{"node": {"node-a"}, "since": {"42"}})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "indexer_config_path")
}

func TestBackfillJobsListRendersStateProgressAndStale(t *testing.T) {
	since := int64(42)
	lister := &fakeReplayLister{jobs: []replay.Job{
		{
			ID: "job-running", Type: replay.TypeDiscovery, Status: replay.StatusRunning,
			SinceSequenceNumber: &since, ProcessedItems: 3, TotalItems: 10, ProgressCursor: 9,
			LastHeartbeat: time.Now().Add(-10 * time.Minute), CreatedAt: time.Now(),
		},
		{
			ID: "job-done", Type: replay.TypeMessages, Status: replay.StatusCompleted, ForceOverwrite: true,
			MessageIDs: []string{testMessageID}, ProcessedItems: 1, TotalItems: 1,
			LastHeartbeat: time.Now(), CreatedAt: time.Now(),
		},
	}}
	r := newBackfillTestRouter(t, &fakeReplayRunner{}, lister, nil, "/idx/config.toml")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/backfill/jobs", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "job-running")
	require.Contains(t, body, "since aggregator sequence 42")
	require.Contains(t, body, "3/10")
	require.Contains(t, body, "stale")
	require.Contains(t, body, "force")
	require.Contains(t, body, "1 message ID(s)")
	// In-flight job present: the fragment self-polls.
	require.Contains(t, body, "every 5s")
}

func TestBackfillDoubleSubmitConflict(t *testing.T) {
	actions, _ := newCaptureActionLog(t)
	// The job row pre-exists so the first handler returns without waiting on the
	// still-blocked engine goroutine; the in-flight claim is what rejects the duplicate.
	lister := &fakeReplayLister{jobs: []replay.Job{{
		ID: "job-1", Type: replay.TypeDiscovery, Status: replay.StatusRunning,
		RequestHash: (replay.Request{Type: replay.TypeDiscovery, Since: 42}).Hash(),
		CreatedAt:   time.Now(), LastHeartbeat: time.Now(),
	}}}
	entered := make(chan struct{})
	release := make(chan struct{})
	runner := &fakeReplayRunner{startFn: func(context.Context, replay.Request) (string, error) {
		close(entered)
		<-release
		return "job-1", nil
	}}
	r := newBackfillTestRouter(t, runner, lister, actions, "/idx/config.toml")
	form := url.Values{"node": {"node-a"}, "since": {"42"}}

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- postForm(r, "/backfill/submit", form) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first submission never reached the engine")
	}

	rec := postForm(r, "/backfill/submit", form)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "already running")

	close(release)
	select {
	case firstRec := <-first:
		require.Equal(t, http.StatusOK, firstRec.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("first submission never returned")
	}
}
