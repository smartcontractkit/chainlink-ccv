package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	recoverystore "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type fakeJobQueueBrowseStore struct {
	fakeJobQueueStore
	jobs []jobqueue.ArchivedJob
}

func (f *fakeJobQueueBrowseStore) ListFailedFiltered(_ context.Context, _ []jobqueue.QueueType, _ string, _ [][]byte, _ int) ([]jobqueue.ArchivedJob, error) {
	if len(f.jobs) > 0 {
		out := make([]jobqueue.ArchivedJob, len(f.jobs))
		copy(out, f.jobs)
		return out, nil
	}
	id := make([]byte, 32)
	id[0] = 0xab
	return []jobqueue.ArchivedJob{
		{
			JobID:           "job-browse-1",
			MessageID:       id,
			Queue:           jobqueue.QueueTypeTaskVerifier,
			OwnerID:         "owner-1",
			FailureCategory: "policy_rejected",
		},
	}, nil
}

func TestSearchRecentBrowse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	allJobs := make([]jobqueue.ArchivedJob, 0, 80)
	// Simulate 40 rows from task-verifier followed by 40 newer rows from storage-writer (80 total).
	for i := range 40 {
		id := make([]byte, 32)
		id[0] = byte(i + 1)
		allJobs = append(allJobs, jobqueue.ArchivedJob{
			JobID:           fmt.Sprintf("job-tv-%02d", i),
			MessageID:       id,
			Queue:           jobqueue.QueueTypeTaskVerifier,
			OwnerID:         "owner-1",
			FailureCategory: "policy_rejected",
			CreatedAt:       base.Add(time.Duration(i) * time.Minute),
		})
	}
	for i := range 40 {
		id := make([]byte, 32)
		id[1] = byte(i + 1)
		allJobs = append(allJobs, jobqueue.ArchivedJob{
			JobID:           fmt.Sprintf("job-sw-%02d", i),
			MessageID:       id,
			Queue:           jobqueue.QueueTypeStorageWriter,
			OwnerID:         "owner-2",
			FailureCategory: "storage_failure",
			CreatedAt:       base.Add(time.Duration(40+i) * time.Minute),
		})
	}
	jq := &fakeJobQueueBrowseStore{jobs: allJobs}
	h := &handlers{
		cfg:  &Config{},
		lggr: logger.Test(t),
		stores: stores{
			jqOverride: jq,
		},
	}

	// Test GET ?browse=recent caps globally at 50 and orders newest first across queues.
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/search?browse=recent", nil)
	h.searchPage(c)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "Recent failed jobs")
	require.Equal(t, 50, strings.Count(body, "detail →"))
	require.Less(t, strings.Index(body, "owner-2"), strings.Index(body, "owner-1"), "newer storage-writer rows must appear before older task-verifier rows")

	// Test POST with empty message_ids also caps globally at 50.
	rec = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/search", strings.NewReader("message_ids="))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.searchResults(c)

	require.Equal(t, http.StatusOK, rec.Code)
	body = rec.Body.String()
	require.Contains(t, body, "Recent failed jobs")
	require.Equal(t, 50, strings.Count(body, "detail →"))
}

type paginatedFakeRecoveryStore struct {
	fakeRecoveryStore
	pages map[string]recoverystore.EventPage
	err   error
}

func (f *paginatedFakeRecoveryStore) ListEvents(_ context.Context, filter recoverystore.EventFilter) (recoverystore.EventPage, error) {
	if f.err != nil {
		return recoverystore.EventPage{}, f.err
	}
	return f.pages[filter.BeforeID], nil
}

func TestSearchDropEventsPaginatedAndErrorHandling(t *testing.T) {
	id1, id2 := rescheduleMsgID(1), rescheduleMsgID(2)
	hex1, hex2 := formatMessageID(id1), formatMessageID(id2)

	recStore := &paginatedFakeRecoveryStore{
		pages: map[string]recoverystore.EventPage{
			"": {
				Events: []recoverystore.Event{{
					ID:          "200",
					MessageID:   &hex1,
					Reason:      "remote_chain_cursed",
					Stage:       "pre_admission",
					OwnerID:     "owner-curse-1",
					SourceChain: "1",
					SourceBlock: new("99999"),
				}},
				NextCursor: "200",
			},
			"200": {
				Events: []recoverystore.Event{{
					ID:          "100",
					MessageID:   &hex2,
					Reason:      "reader_disabled",
					Stage:       "pre_admission",
					OwnerID:     "owner-curse-2",
					SourceChain: "1",
					SourceBlock: new("99998"),
				}},
			},
		},
	}

	gin.SetMode(gin.TestMode)
	h := &handlers{
		cfg:  &Config{},
		lggr: logger.Test(t),
		stores: stores{
			jqOverride:  &fakeJobQueueStore{},
			recOverride: recStore,
		},
	}

	form := url.Values{"message_ids": {hex1 + " " + hex2}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(form.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.searchResults(c)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "Observed pre-admission drops")
	require.Contains(t, body, "owner-curse-1")
	require.Contains(t, body, "owner-curse-2")
	require.NotContains(t, body, "Messages not found", "IDs found on subsequent event pages must not be marked not found")

	// When the recovery store errors, surface the error and suppress NotFoundIDs.
	recStore.err = errors.New("events table unreachable")
	rec = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(form.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.searchResults(c)

	require.Equal(t, http.StatusOK, rec.Code)
	body = rec.Body.String()
	require.Contains(t, body, "Lookup unavailable")
	require.Contains(t, body, "recovery event lookup failed: events table unreachable")
	require.NotContains(t, body, "Messages not found")
}

func TestReschedulePreviewSelectionCountsAndCSP(t *testing.T) {
	idA, idB := rescheduleMsgID(21), rescheduleMsgID(22)
	store := &rescheduleFakeStore{jobs: []jobqueue.ArchivedJob{
		{
			JobID: "job-a", MessageID: idA, OwnerID: "owner-1",
			Queue: jobqueue.QueueTypeTaskVerifier, FailureCategory: "source-rpc",
		},
	}}
	installFakeResultsClient(t, notFoundResultsClient())
	h, _ := newRescheduleTestHandlers(t, store)

	// Submit 1 executable target and 1 missing/excluded target.
	c, rec := reschedulePostContext(url.Values{"target": {
		rescheduleTargetString("job-a", idA, jobqueue.QueueTypeTaskVerifier, "owner-1"),
		rescheduleTargetString("job-missing", idB, jobqueue.QueueTypeTaskVerifier, "owner-1"),
	}})
	h.reschedulePreview(c)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `data-select-all="target"`)
	require.NotContains(t, body, "onclick=")
	require.Contains(t, body, `<strong id="reschedule-selected-count">1</strong> of 1 executable target(s) selected (2 total in preview).`)
	require.Contains(t, body, `Reschedule selected (1)`)
}
