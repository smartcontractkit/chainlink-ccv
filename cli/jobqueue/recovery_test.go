package jobqueue_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestListFilteredJSON(t *testing.T) {
	store := mocks.NewMockStore(t)
	id := strings.Repeat("ab", 32)
	decoded, err := hex.DecodeString(id)
	require.NoError(t, err)
	fullError := strings.Repeat("diagnostic detail ", 20)
	now := time.Now().UTC()
	store.EXPECT().ListFailedFiltered(mock.Anything, []jobqueue.QueueType(nil), "", [][]byte{decoded}, 50).
		Return([]jobqueue.ArchivedJob{{
			Queue: jobqueue.QueueTypeTaskVerifier, JobID: "job", OwnerID: "owner", MessageID: decoded,
			ChainSelector: ^uint64(0), LastError: fullError, ArchivedAt: &now, RetryDeadline: now,
		}}, nil).Once()
	app := newApp(jobqueue.InitJobQueueCommands(jobqueue.Deps{Store: store, Logger: logger.Test(t)}))
	out := captureStdout(t, func() {
		require.NoError(t, app.Run([]string{"ccv", "list", "--message-id", "0X" + strings.ToUpper(id) + ",0x" + id, "--message-id", id, "--output", "json"}))
	})
	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rows), "stdout must contain only JSON")
	require.Len(t, rows, 1)
	require.Equal(t, "18446744073709551615", rows[0]["source_chain_selector"])
	require.Equal(t, "0x"+id, rows[0]["message_id"])
	require.Equal(t, fullError, rows[0]["last_error"])
	require.NotNil(t, rows[0]["archived_at"])
	require.NotNil(t, rows[0]["retry_deadline"])
}

func TestListJSONEmptyArray(t *testing.T) {
	store := mocks.NewMockStore(t)
	store.EXPECT().ListFailed(mock.Anything, []jobqueue.QueueType(nil), "", 50).Return(nil, nil)
	app := newApp(jobqueue.InitJobQueueCommands(jobqueue.Deps{Store: store, Logger: logger.Test(t)}))
	out := captureStdout(t, func() { require.NoError(t, app.Run([]string{"ccv", "list", "--output", "json"})) })
	require.JSONEq(t, `[]`, out)
}

func TestListRejectsInvalidFilters(t *testing.T) {
	for _, input := range []string{"", "0x", "abcd", strings.Repeat("zz", 32), strings.Repeat("aa", 32) + ","} {
		t.Run(input, func(t *testing.T) {
			store := mocks.NewMockStore(t)
			app := newApp(jobqueue.InitJobQueueCommands(jobqueue.Deps{Store: store, Logger: logger.Test(t)}))
			require.ErrorContains(t, app.Run([]string{"ccv", "list", "--message-id", input}), "message-id")
		})
	}
}

func TestRescheduleInfersAndReportsOwner(t *testing.T) {
	store := mocks.NewMockStore(t)
	store.EXPECT().Reschedule(mock.Anything, jobqueue.QueueTypeTaskVerifier, "", "job", []byte(nil), time.Hour).
		Return(jobqueue.ArchivedJob{JobID: "job", OwnerID: "resolved-owner"}, nil).Once()
	app := newApp(jobqueue.InitJobQueueCommands(jobqueue.Deps{Store: store, Logger: logger.Test(t)}))
	out := captureStdout(t, func() {
		require.NoError(t, app.Run([]string{"ccv", "reschedule", "--queue", "task-verifier", "--job-id", "job"}))
	})
	require.Contains(t, out, "owner: resolved-owner")
}
