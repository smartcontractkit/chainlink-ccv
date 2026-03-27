package jobqueue_test

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func newApp(cmds []cli.Command) *cli.App {
	app := cli.NewApp()
	app.Commands = cmds
	return app
}

// captureStdout runs f and returns everything written to os.Stdout during the call.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	_ = w.Close()
	return <-done
}

// --- list command ---

func TestInitJobQueueCommands_returns_two_commands(t *testing.T) {
	store := mocks.NewMockStore(t)
	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	require.Len(t, cmds, 2)
	assert.Equal(t, "list", cmds[0].Name)
	assert.Equal(t, "reschedule", cmds[1].Name)
}

func TestListAction_empty_result_prints_no_jobs_message(t *testing.T) {
	store := mocks.NewMockStore(t)
	store.EXPECT().ListFailed(mock.Anything, []jobqueue.QueueType(nil), "", 50).Return(nil, nil).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	out := captureStdout(t, func() {
		err := app.Run([]string{"ccv", "list"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No failed jobs found.")
}

func TestListAction_with_jobs_renders_table(t *testing.T) {
	now := time.Now().UTC()
	archivedAt := now.Add(-time.Hour)
	jobs := []jobqueue.ArchivedJob{
		{
			JobID:         "job-uuid-1",
			MessageID:     []byte{0xde, 0xad, 0xbe, 0xef},
			OwnerID:       "CCTPVerifier",
			ChainSelector: 1234,
			Status:        "failed",
			AttemptCount:  5,
			LastError:     "connection refused",
			CreatedAt:     now.Add(-2 * time.Hour),
			ArchivedAt:    &archivedAt,
			RetryDeadline: now.Add(-30 * time.Minute),
			Queue:         jobqueue.QueueTypeTaskVerifier,
		},
	}

	store := mocks.NewMockStore(t)
	store.EXPECT().
		ListFailed(mock.Anything, []jobqueue.QueueType{jobqueue.QueueTypeTaskVerifier}, "CCTPVerifier", 10).
		Return(jobs, nil).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	out := captureStdout(t, func() {
		err := app.Run([]string{
			"ccv", "list",
			"--queue", "task-verifier",
			"--verifier-id", "CCTPVerifier",
			"--limit", "10",
		})
		require.NoError(t, err)
	})

	assert.Contains(t, out, "job-uuid-1")
	assert.Contains(t, out, "deadbeef")
	assert.Contains(t, out, "CCTPVerifier")
	assert.Contains(t, out, "1234")
	assert.Contains(t, out, "5")
	assert.Contains(t, out, "connection refused")
}

func TestListAction_store_error_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	store.EXPECT().ListFailed(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, assert.AnError).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{"ccv", "list"})
	require.Error(t, err)
}

func TestListAction_invalid_queue_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{"ccv", "list", "--queue", "unknown-queue"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid queue")
}

// --- reschedule by job-id ---

func TestRescheduleAction_by_job_id_succeeds(t *testing.T) {
	store := mocks.NewMockStore(t)
	store.EXPECT().
		RescheduleByJobID(mock.Anything, jobqueue.QueueTypeTaskVerifier, "v1", "job-uuid-1", time.Hour).
		Return(nil).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	out := captureStdout(t, func() {
		err := app.Run([]string{
			"ccv", "reschedule",
			"--queue", "task-verifier",
			"--verifier-id", "v1",
			"--job-id", "job-uuid-1",
			"--retry-duration", "1h",
		})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "job-uuid-1")
}

func TestRescheduleAction_by_job_id_store_error_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	store.EXPECT().
		RescheduleByJobID(mock.Anything, jobqueue.QueueTypeStorageWriter, "v1", "missing-job", time.Hour).
		Return(assert.AnError).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{
		"ccv", "reschedule",
		"--queue", "storage-writer",
		"--verifier-id", "v1",
		"--job-id", "missing-job",
	})
	require.Error(t, err)
}

// --- reschedule by message-id ---

func TestRescheduleAction_by_message_id_with_0x_prefix_succeeds(t *testing.T) {
	msgIDBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	store := mocks.NewMockStore(t)
	store.EXPECT().
		RescheduleByMessageID(mock.Anything, jobqueue.QueueTypeTaskVerifier, "v1", msgIDBytes, time.Hour).
		Return(nil).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	out := captureStdout(t, func() {
		err := app.Run([]string{
			"ccv", "reschedule",
			"--queue", "task-verifier",
			"--verifier-id", "v1",
			"--message-id", "0xdeadbeef",
		})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "0xdeadbeef")
}

func TestRescheduleAction_by_message_id_without_0x_prefix_succeeds(t *testing.T) {
	msgIDBytes := []byte{0xca, 0xfe}
	store := mocks.NewMockStore(t)
	store.EXPECT().
		RescheduleByMessageID(mock.Anything, jobqueue.QueueTypeStorageWriter, "v2", msgIDBytes, 30*time.Minute).
		Return(nil).Once()

	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{
		"ccv", "reschedule",
		"--queue", "storage-writer",
		"--verifier-id", "v2",
		"--message-id", "cafe",
		"--retry-duration", "30m",
	})
	require.NoError(t, err)
}

func TestRescheduleAction_invalid_message_id_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{
		"ccv", "reschedule",
		"--queue", "task-verifier",
		"--verifier-id", "v1",
		"--message-id", "not-hex!",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message-id")
}

func TestRescheduleAction_missing_job_id_and_message_id_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{
		"ccv", "reschedule",
		"--queue", "task-verifier",
		"--verifier-id", "v1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--job-id or --message-id is required")
}

func TestRescheduleAction_both_job_id_and_message_id_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{
		"ccv", "reschedule",
		"--queue", "task-verifier",
		"--verifier-id", "v1",
		"--job-id", "some-id",
		"--message-id", "0xdeadbeef",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestRescheduleAction_invalid_queue_returns_error(t *testing.T) {
	store := mocks.NewMockStore(t)
	deps := jobqueue.Deps{Logger: logger.Test(t), Store: store}
	cmds := jobqueue.InitJobQueueCommands(deps)
	app := newApp(cmds)

	err := app.Run([]string{
		"ccv", "reschedule",
		"--queue", "bad-queue",
		"--verifier-id", "v1",
		"--job-id", "some-id",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid queue")
}

// --- ParseMessageID ---

func TestParseMessageID_with_0x_prefix(t *testing.T) {
	b, err := jobqueue.ParseMessageID("0xdeadbeef")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)
}

func TestParseMessageID_without_prefix(t *testing.T) {
	b, err := jobqueue.ParseMessageID("deadbeef")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)
}

func TestParseMessageID_invalid_hex_returns_error(t *testing.T) {
	_, err := jobqueue.ParseMessageID("zzzz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message-id")
}

// --- ParseRequiredQueue ---

func TestParseRequiredQueue_valid_values(t *testing.T) {
	q, err := jobqueue.ParseRequiredQueue("task-verifier")
	require.NoError(t, err)
	assert.Equal(t, jobqueue.QueueTypeTaskVerifier, q)

	q, err = jobqueue.ParseRequiredQueue("storage-writer")
	require.NoError(t, err)
	assert.Equal(t, jobqueue.QueueTypeStorageWriter, q)
}

func TestParseRequiredQueue_invalid_returns_error(t *testing.T) {
	_, err := jobqueue.ParseRequiredQueue("unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid queue")
}
