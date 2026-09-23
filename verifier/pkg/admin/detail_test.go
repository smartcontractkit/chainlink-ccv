package admin

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	recoverystore "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type fakeJobQueueStore struct {
	jobs []jobqueue.ArchivedJob
	err  error
}

func (f *fakeJobQueueStore) ListFailed(context.Context, []jobqueue.QueueType, string, int) ([]jobqueue.ArchivedJob, error) {
	return f.jobs, f.err
}

func (f *fakeJobQueueStore) ListFailedFiltered(context.Context, []jobqueue.QueueType, string, [][]byte, int) ([]jobqueue.ArchivedJob, error) {
	return f.jobs, f.err
}

func (f *fakeJobQueueStore) Reschedule(context.Context, jobqueue.QueueType, string, string, []byte, time.Duration) (jobqueue.ArchivedJob, error) {
	return jobqueue.ArchivedJob{}, errors.New("not implemented")
}

func (f *fakeJobQueueStore) RescheduleByJobID(context.Context, jobqueue.QueueType, string, string, time.Duration) error {
	return errors.New("not implemented")
}

func (f *fakeJobQueueStore) RescheduleByMessageID(context.Context, jobqueue.QueueType, string, []byte, time.Duration) error {
	return errors.New("not implemented")
}

type fakeRecoveryStore struct {
	page recoverystore.EventPage
	err  error
}

func (f *fakeRecoveryStore) Submit(context.Context, recoverystore.SubmitRequest) (recoverystore.Operation, error) {
	return recoverystore.Operation{}, errors.New("not implemented")
}

func (f *fakeRecoveryStore) Get(context.Context, string) (recoverystore.Operation, error) {
	return recoverystore.Operation{}, errors.New("not implemented")
}

func (f *fakeRecoveryStore) List(context.Context, string, string, int) ([]recoverystore.Operation, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeRecoveryStore) ChangeState(context.Context, string, string) (recoverystore.Operation, error) {
	return recoverystore.Operation{}, errors.New("not implemented")
}

func (f *fakeRecoveryStore) ListEvents(context.Context, recoverystore.EventFilter) (recoverystore.EventPage, error) {
	return f.page, f.err
}

type fakeChainStatusLister struct {
	rows []chainstatus.Row
	err  error
}

func (f *fakeChainStatusLister) List(context.Context) ([]chainstatus.Row, error) {
	return f.rows, f.err
}

func detailTestMessageID(t *testing.T) []byte {
	t.Helper()
	id, err := jobqueue.ParseMessageID(strings.Repeat("ab", 32))
	require.NoError(t, err)
	return id
}

func detailStrPtr(s string) *string { return &s }

// serveDetail renders the page through renderDetail with fake stores; the node's own
// (lazy) connection is never touched.
func serveDetail(t *testing.T, src detailSources, msgID []byte) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	node := NewNode(NodeConfig{
		Name: "verifier-1", SecretsPath: "unused-in-tests",
		TraceURL: "https://traces.example.com", IndexerURL: "https://indexer.example.com",
	}, logger.Test(t))
	h := &handlers{cfg: &Config{}, lggr: logger.Test(t), nodes: []*Node{node}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/nodes/verifier-1/messages/"+formatMessageID(msgID), nil)
	h.renderDetail(c, node, src, msgID)
	return rec
}

func TestDetailPreAdmissionDrop(t *testing.T) {
	msgID := detailTestMessageID(t)
	since := time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Second)
	src := detailSources{
		jq: &fakeJobQueueStore{},
		rec: &fakeRecoveryStore{page: recoverystore.EventPage{
			Events: []recoverystore.Event{{
				OwnerID: "verifier-1a", SourceChain: "1", Kind: "drop", Stage: "pre_admission",
				Reason: "remote_chain_cursed", SourceBlock: detailStrPtr("12345"), TxHash: detailStrPtr("0xdeadbeef"),
				FirstObservedAt: since, LastObservedAt: since.Add(time.Hour),
				Observations: "2", ExpiresAt: since.Add(30 * 24 * time.Hour),
			}},
			RetainedSince: since,
			Coverage:      "Observed events only. Empty results do not prove no affected traffic.",
		}},
		chain: &fakeChainStatusLister{rows: []chainstatus.Row{{
			ChainSelector: 1, VerifierID: "verifier-1a", FinalizedBlockHeight: big.NewInt(12340),
		}}},
	}
	rec := serveDetail(t, src, msgID)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "dropped before queue admission")
	require.Contains(t, body, "nothing to reschedule")
	require.Contains(t, body, "/recovery")
	require.Contains(t, body, "remote_chain_cursed")
	require.Contains(t, body, "0xdeadbeef")
	require.NotContains(t, body, `name="target"`)
	require.Contains(t, body, "12340") // finalized height from the chain-status row
	require.Contains(t, body, "https://traces.example.com")
	require.Contains(t, body, "https://indexer.example.com")
}

func TestDetailNotFound(t *testing.T) {
	msgID := detailTestMessageID(t)
	since := time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Second)
	src := detailSources{
		jq: &fakeJobQueueStore{},
		rec: &fakeRecoveryStore{page: recoverystore.EventPage{
			RetainedSince: since,
			Coverage:      "Observed events only. Empty results do not prove no affected traffic.",
		}},
		chain: &fakeChainStatusLister{},
	}
	rec := serveDetail(t, src, msgID)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "not found on this node")
	require.Contains(t, body, "No archived failed jobs")
	require.Contains(t, body, "No drop or incident events")
	require.Contains(t, body, "Empty results do not prove no affected traffic")
	require.Contains(t, body, "Event history retained since "+since.Format(time.RFC3339))
	require.Contains(t, body, "Source chain unknown")
}

func TestDetailArchivedRows(t *testing.T) {
	msgID := detailTestMessageID(t)
	created := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	archived := time.Now().Add(-26 * time.Hour).UTC().Truncate(time.Second)
	deadline := created.Add(time.Hour)
	src := detailSources{
		jq: &fakeJobQueueStore{jobs: []jobqueue.ArchivedJob{
			{
				JobID: "job-1111", MessageID: msgID, OwnerID: "verifier-1a", ChainSelector: 1,
				AttemptCount: 7, LastError: "policy hook rejected: FAIL", FailureCategory: "policy_rejected",
				CreatedAt: created, ArchivedAt: &archived, RetryDeadline: deadline,
				Queue: jobqueue.QueueTypeTaskVerifier,
			},
			{
				JobID: "job-2222", MessageID: msgID, OwnerID: "verifier-1a", ChainSelector: 1,
				AttemptCount: 3, LastError: "connection refused", FailureCategory: "storage_failure",
				CreatedAt: created, ArchivedAt: &archived, RetryDeadline: deadline,
				Queue: jobqueue.QueueTypeStorageWriter,
			},
		}},
		rec: &fakeRecoveryStore{page: recoverystore.EventPage{
			RetainedSince: time.Now().Add(-30 * 24 * time.Hour).UTC(), Coverage: "coverage-note",
		}},
		chain: &fakeChainStatusLister{rows: []chainstatus.Row{{
			ChainSelector: 1, VerifierID: "verifier-1a", FinalizedBlockHeight: big.NewInt(99),
		}}},
	}
	rec := serveDetail(t, src, msgID)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "2 archived failed job(s)")
	require.Contains(t, body, "policy_rejected")
	require.Contains(t, body, "storage_failure")
	require.Contains(t, body, "policy hook rejected: FAIL")
	require.Contains(t, body, "connection refused")
	require.Contains(t, body, archived.Add(30*24*time.Hour).Format(time.RFC3339)) // archive expiry
	require.Contains(t, body, archived.Format(time.RFC3339))
	require.Contains(t, body, deadline.Format(time.RFC3339))
	require.Contains(t, body, "26h") // archive age
	require.Contains(t, body, "Ask the policy endpoint again (re-verify)")
	require.Contains(t, body, "Retry delivering the saved result")
	require.Contains(t, body, "neither action re-checks")
	require.Contains(t, body, `action="/reschedule/preview"`)
	require.NotContains(t, body, "dropped before queue admission")
}

func TestDetailRescheduleTargetContract(t *testing.T) {
	msgID := detailTestMessageID(t)
	archived := time.Now().UTC().Truncate(time.Second)
	src := detailSources{
		jq: &fakeJobQueueStore{jobs: []jobqueue.ArchivedJob{{
			JobID: "job-abc", MessageID: msgID, OwnerID: "verifier-1a", ChainSelector: 1,
			ArchivedAt: &archived, Queue: jobqueue.QueueTypeTaskVerifier,
		}}},
		rec:   &fakeRecoveryStore{page: recoverystore.EventPage{RetainedSince: time.Now().UTC()}},
		chain: &fakeChainStatusLister{},
	}
	rec := serveDetail(t, src, msgID)
	require.Equal(t, http.StatusOK, rec.Code)
	want := "verifier-1|job-abc|" + formatMessageID(msgID) + "|task-verifier|verifier-1a"
	require.Contains(t, rec.Body.String(), `name="target" value="`+want+`"`)
}

func TestDetailUnreachableNode(t *testing.T) {
	node := NewNode(NodeConfig{
		Name: "verifier-1", SecretsPath: filepath.Join(t.TempDir(), "missing.toml"),
	}, logger.Test(t))
	h := &handlers{cfg: &Config{}, lggr: logger.Test(t), nodes: []*Node{node}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h.registerDetailRoutes(r)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes/verifier-1/messages/"+formatMessageID(detailTestMessageID(t)), nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "Node unreachable")
	require.Contains(t, body, "unknown, not absent")
}

func TestDetailUnknownNode(t *testing.T) {
	node := NewNode(NodeConfig{Name: "verifier-1", SecretsPath: "unused"}, logger.Test(t))
	h := &handlers{cfg: &Config{}, lggr: logger.Test(t), nodes: []*Node{node}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h.registerDetailRoutes(r)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes/nope/messages/"+formatMessageID(detailTestMessageID(t)), nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDetailInvalidMessageID(t *testing.T) {
	node := NewNode(NodeConfig{Name: "verifier-1", SecretsPath: "unused"}, logger.Test(t))
	h := &handlers{cfg: &Config{}, lggr: logger.Test(t), nodes: []*Node{node}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h.registerDetailRoutes(r)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes/verifier-1/messages/0xzz", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDetailDisabledReader(t *testing.T) {
	msgID := detailTestMessageID(t)
	archived := time.Now().UTC().Truncate(time.Second)
	src := detailSources{
		jq: &fakeJobQueueStore{jobs: []jobqueue.ArchivedJob{{
			JobID: "job-1", MessageID: msgID, OwnerID: "verifier-1a", ChainSelector: 1,
			ArchivedAt: &archived, Queue: jobqueue.QueueTypeTaskVerifier,
		}}},
		rec: &fakeRecoveryStore{page: recoverystore.EventPage{RetainedSince: time.Now().UTC()}},
		chain: &fakeChainStatusLister{rows: []chainstatus.Row{{
			ChainSelector: 1, VerifierID: "verifier-1a", FinalizedBlockHeight: big.NewInt(42), Disabled: true,
		}}},
	}
	rec := serveDetail(t, src, msgID)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "disabled")
	require.Contains(t, body, "investigated reset-reader")
	require.Contains(t, body, "/recovery")
}
