package verifiercli

import "context"

// JobQueueSubcommand is the CLI path to the job-queue commands:
// `ccv job-queue ...`.
var JobQueueSubcommand = []string{"ccv", "job-queue"}

// QueueName is the --queue flag value. Kept as a named type so tests
// can't mix it up with verifier IDs or chain selectors.
type QueueName string

const (
	// QueueTaskVerifier is the task-verifier queue.
	QueueTaskVerifier QueueName = "task-verifier"
)

// RetryDuration is the --retry-duration flag value, parsed by the CLI
// with time.ParseDuration. Common values: "1h", "30m".
type RetryDuration string

// JobQueueClient is the wrapper around the ccv job-queue CLI group.
// Obtain via (*Client).JobQueue().
type JobQueueClient struct {
	client *Client
}

// JobQueue returns a sub-client for the job-queue CLI.
func (c *Client) JobQueue() JobQueueClient {
	return JobQueueClient{client: c}
}

// List runs `job-queue list` against the given queue and returns the
// raw table output. Tests typically match against a known job ID.
func (j JobQueueClient) List(ctx context.Context, queue QueueName, verifierID string) (string, error) {
	return j.client.CLI(ctx, JobQueueSubcommand,
		"list",
		"--queue", string(queue),
		"--verifier-id", verifierID)
}

// Reschedule runs `job-queue reschedule` to move a failed job from the
// archive table back to the active queue. retry must be a valid
// time.ParseDuration string.
func (j JobQueueClient) Reschedule(ctx context.Context, queue QueueName, verifierID, jobID string, retry RetryDuration) (string, error) {
	return j.client.CLI(ctx, JobQueueSubcommand,
		"reschedule",
		"--queue", string(queue),
		"--verifier-id", verifierID,
		"--job-id", jobID,
		"--retry-duration", string(retry))
}
