package admin

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
)

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
