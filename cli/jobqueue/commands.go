package jobqueue

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/internal/tablefmt"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	defaultLimit         = 50
	defaultRetryDuration = time.Hour
)

// Deps holds dependencies for the jobqueue CLI commands.
type Deps struct {
	Logger logger.Logger
	Store  Store
}

// InitJobQueueCommands returns CLI commands for listing and rescheduling failed jobs.
// Attach these under a parent command (e.g. `node ccv job-queue`).
func InitJobQueueCommands(deps Deps) []cli.Command {
	return buildJobQueueCommands(func() Deps { return deps })
}

// InitJobQueueCommandsWithFactory returns the same commands but resolves Deps lazily.
// Use when Deps can only be constructed after a Before hook runs (e.g. DB connection).
func InitJobQueueCommandsWithFactory(getDeps func() Deps) []cli.Command {
	return buildJobQueueCommands(getDeps)
}

func buildJobQueueCommands(getDeps func() Deps) []cli.Command {
	return []cli.Command{
		{
			Name:   "list",
			Usage:  "List failed jobs in the archive tables",
			Action: listActionWithFactory(getDeps),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "queue",
					Usage: fmt.Sprintf("Filter by queue: %q, %q, or omit for both", QueueTypeTaskVerifier, QueueTypeStorageWriter),
				},
				cli.StringFlag{
					Name:  "verifier-id",
					Usage: "Filter by verifier ID (owner). Omit to list all verifiers.",
				},
				cli.StringSliceFlag{Name: "message-id", Usage: "Full message IDs, comma-separated or repeated"},
				cli.StringFlag{Name: "output", Value: "table", Usage: "Output format: table or json"},
				cli.IntFlag{
					Name:  "limit",
					Usage: "Maximum number of jobs to show per queue (0 = unlimited)",
					Value: defaultLimit,
				},
			},
		},
		{
			Name:   "reschedule",
			Usage:  "Move a failed job from the archive back to the active queue",
			Action: rescheduleActionWithFactory(getDeps),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "queue",
					Usage:    fmt.Sprintf("Queue to reschedule from: %q or %q", QueueTypeTaskVerifier, QueueTypeStorageWriter),
					Required: true,
				},
				cli.StringFlag{
					Name:     "verifier-id",
					Usage: "Verifier owner; inferred only when one owner matches",
				},
				cli.StringFlag{
					Name:  "job-id",
					Usage: "UUID of the job to reschedule (mutually exclusive with --message-id)",
				},
				cli.StringFlag{
					Name:  "message-id",
					Usage: "Hex-encoded message ID (e.g. 0xabc123...) of the job to reschedule (mutually exclusive with --job-id)",
				},
				cli.DurationFlag{
					Name:  "retry-duration",
					Usage: "How long from now the job is eligible for retry (e.g. 1h, 30m)",
					Value: defaultRetryDuration,
				},
			},
		},
	}
}

func listActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ctx := context.Background()

		queues, err := parseOptionalQueue(c.String("queue"))
		if err != nil {
			return err
		}

		ownerID := c.String("verifier-id")
		limit := c.Int("limit")

		if limit < 0 {
			return fmt.Errorf("--limit must be non-negative")
		}
		if c.String("output") != "table" && c.String("output") != "json" {
			return fmt.Errorf("--output must be table or json")
		}
		var jobs []ArchivedJob
		if c.IsSet("message-id") {
			ids, parseErr := ParseMessageIDs(c.StringSlice("message-id"))
			if parseErr != nil {
				return parseErr
			}
			jobs, err = deps.Store.ListFailedFiltered(ctx, queues, ownerID, ids, limit)
		} else {
			jobs, err = deps.Store.ListFailed(ctx, queues, ownerID, limit)
		}
		if err != nil {
			deps.Logger.Errorw("list failed jobs failed", "error", err)
			return err
		}

		if c.String("output") == "json" {
			return renderJobsJSON(jobs)
		}

		return renderJobs(jobs)
	}
}

func rescheduleActionWithFactory(getDeps func() Deps) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ctx := context.Background()

		queue, err := ParseRequiredQueue(c.String("queue"))
		if err != nil {
			return err
		}

		ownerID := c.String("verifier-id")
		jobID := c.String("job-id")
		messageIDHex := c.String("message-id")
		retryDuration := c.Duration("retry-duration")

		if jobID == "" && messageIDHex == "" {
			return fmt.Errorf("one of --job-id or --message-id is required")
		}
		if jobID != "" && messageIDHex != "" {
			return fmt.Errorf("--job-id and --message-id are mutually exclusive")
		}

		if retryDuration <= 0 {
			return fmt.Errorf("--retry-duration must be positive")
		}
		if ownerID == "" {
			var messageID []byte
			if messageIDHex != "" {
				messageID, err = ParseMessageID(messageIDHex)
				if err != nil {
					return err
				}
			}
			job, err := deps.Store.Reschedule(ctx, queue, "", jobID, messageID, retryDuration)
			if err != nil {
				return err
			}
			fmt.Printf("Job %s rescheduled in queue %s (owner: %s). Retry window: %s.\n", job.JobID, queue, job.OwnerID, retryDuration) //nolint:forbidigo // CLI output
			return nil
		}

		if jobID != "" {
			if err := deps.Store.RescheduleByJobID(ctx, queue, ownerID, jobID, retryDuration); err != nil {
				deps.Logger.Errorw("reschedule by job-id failed", "jobID", jobID, "error", err)
				return err
			}
			fmt.Printf("Job %s rescheduled in queue %s (owner: %s). Retry window: %s.\n", //nolint:forbidigo // CLI user output
				jobID, queue, ownerID, retryDuration)
			return nil
		}

		messageID, err := ParseMessageID(messageIDHex)
		if err != nil {
			return err
		}

		if err := deps.Store.RescheduleByMessageID(ctx, queue, ownerID, messageID, retryDuration); err != nil {
			deps.Logger.Errorw("reschedule by message-id failed", "messageID", messageIDHex, "error", err)
			return err
		}
		fmt.Printf("Job with message_id %s rescheduled in queue %s (owner: %s). Retry window: %s.\n", //nolint:forbidigo // CLI user output
			messageIDHex, queue, ownerID, retryDuration)
		return nil
	}
}

// parseOptionalQueue parses the --queue flag value, returning nil slice for "all" / empty.
func parseOptionalQueue(s string) ([]QueueType, error) {
	if s == "" {
		return nil, nil
	}
	q, err := ParseRequiredQueue(s)
	if err != nil {
		return nil, err
	}
	return []QueueType{q}, nil
}

// ParseRequiredQueue parses and validates a queue type string.
func ParseRequiredQueue(s string) (QueueType, error) {
	switch QueueType(s) {
	case QueueTypeTaskVerifier, QueueTypeStorageWriter:
		return QueueType(s), nil
	default:
		return "", fmt.Errorf("invalid queue %q: must be %q or %q", s, QueueTypeTaskVerifier, QueueTypeStorageWriter)
	}
}

// ParseMessageID decodes a hex string (with or without 0x prefix) into bytes.
func ParseMessageID(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid message-id %q: must be a hex string: %w", s, err)
	}
	return b, nil
}

// ParseMessageIDs validates full protocol IDs and normalizes repeated/comma flags.
func ParseMessageIDs(values []string) ([][]byte, error) {
	ids := make([][]byte, 0)
	seen := make(map[string]bool)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			id, err := ParseMessageID(strings.TrimSpace(part))
			if err != nil || len(id) != 32 {
				return nil, fmt.Errorf("invalid message-id %q: expected a full 32-byte hex ID", part)
			}
			if !seen[string(id)] {
				ids = append(ids, id)
				seen[string(id)] = true
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("--message-id requires at least one full ID")
	}
	return ids, nil
}

func renderJobsJSON(jobs []ArchivedJob) error {
	type row struct {
		Queue           QueueType  `json:"queue"`
		JobID           string     `json:"job_id"`
		MessageID       string     `json:"message_id"`
		OwnerID         string     `json:"owner_id"`
		ChainSelector   string     `json:"source_chain_selector"`
		Attempts        int        `json:"attempts"`
		LastError       string     `json:"last_error"`
		FailureCategory string     `json:"failure_category"`
		CreatedAt       time.Time  `json:"created_at"`
		ArchivedAt      *time.Time `json:"archived_at"`
		RetryDeadline   time.Time  `json:"retry_deadline"`
	}
	result := make([]row, 0, len(jobs))
	for _, j := range jobs {
		result = append(result, row{
			Queue: j.Queue, JobID: j.JobID, MessageID: "0x" + hex.EncodeToString(j.MessageID),
			OwnerID: j.OwnerID, ChainSelector: fmt.Sprintf("%d", j.ChainSelector),
			Attempts: j.AttemptCount, LastError: j.LastError, FailureCategory: j.FailureCategory,
			CreatedAt: j.CreatedAt, ArchivedAt: j.ArchivedAt, RetryDeadline: j.RetryDeadline,
		})
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func renderJobs(jobs []ArchivedJob) error {
	if len(jobs) == 0 {
		fmt.Println("No failed jobs found.") //nolint:forbidigo // CLI user output
		return nil
	}

	table := tablefmt.NewPlain(os.Stdout)
	tablefmt.Header(table, []string{
		"Queue", "Job ID", "Message ID", "Owner ID",
		"Chain Selector", "Attempts", "Last Error", "Created At", "Archived At",
	})

	for _, j := range jobs {
		archivedAt := "-"
		if j.ArchivedAt != nil {
			archivedAt = j.ArchivedAt.Format("2006-01-02T15:04:05Z")
		}

		lastError := j.LastError
		if len(lastError) > 80 {
			lastError = lastError[:77] + "..."
		}

		if err := table.Append([]string{
			string(j.Queue),
			j.JobID,
			"0x" + hex.EncodeToString(j.MessageID),
			j.OwnerID,
			fmt.Sprintf("%d", j.ChainSelector),
			fmt.Sprintf("%d", j.AttemptCount),
			lastError,
			j.CreatedAt.Format("2006-01-02T15:04:05Z"),
			archivedAt,
		}); err != nil {
			return err
		}
	}

	return table.Render()
}
