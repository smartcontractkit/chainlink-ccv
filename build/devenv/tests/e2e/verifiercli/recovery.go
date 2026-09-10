package verifiercli

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
)

var RecoverySubcommand = []string{"ccv", "recovery"}

type RecoveryClient struct { client *Client }
func (c *Client) Recovery() RecoveryClient { return RecoveryClient{client: c} }

func (r RecoveryClient) Submit(ctx context.Context, mode, owner, chain string, from uint64, to *uint64, id string) (recovery.Operation, error) {
	args := []string{mode, "--verifier-id", owner, "--chain-selector", chain, "--from-block", strconv.FormatUint(from, 10), "--actor", "devenv-test", "--note", "devenv investigated source range"}
	if to != nil {
		args = append(args, "--to-block", strconv.FormatUint(*to, 10))
	}
	if id != "" {
		args = append(args, "--request-id", id)
	}
	var result recovery.Operation
	out, err := r.client.CLIJSON(ctx, RecoverySubcommand, args...)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(out, &result)
	return result, err
}

func (r RecoveryClient) Action(ctx context.Context, action, id string) (recovery.Operation, error) {
	var result recovery.Operation
	out, err := r.client.CLIJSON(ctx, RecoverySubcommand, action, "--operation-id", id)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(out, &result)
	return result, err
}

func (r RecoveryClient) Wait(ctx context.Context, id string) (recovery.Operation, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	for {
		o, err := r.Action(ctx, "status", id)
		if err != nil {
			return o, err
		}
		switch o.State {
		case "completed": return o, nil
		case "failed", "blocked", "cancelled": return o, fmt.Errorf("recovery %s: %s", o.State, o.LastError)
		}
		select {
		case <-ctx.Done():
			return o, fmt.Errorf("recovery wait: %w (state %s, next %d, error %s)", ctx.Err(), o.State, o.NextBlock, o.LastError)
		case <-time.After(time.Second):
		}
	}
}

func (r RecoveryClient) Events(ctx context.Context, owner, chain, reason string, ids ...string) (recovery.EventPage, error) {
	args := []string{"events", "--verifier-id", owner, "--chain-selector", chain}
	if reason != "" {
		args = append(args, "--reason", reason)
	}
	if len(ids) > 0 {
		args = append(args, "--message-id", strings.Join(ids, ","))
	}
	var page recovery.EventPage
	out, err := r.client.CLIJSON(ctx, RecoverySubcommand, args...)
	if err != nil {
		return page, err
	}
	err = json.Unmarshal(out, &page)
	return page, err
}

type ArchivedJobJSON struct {
	Queue           string     `json:"queue"`
	JobID           string     `json:"job_id"`
	MessageID       string     `json:"message_id"`
	OwnerID         string     `json:"owner_id"`
	SourceChain     string     `json:"source_chain_selector"`
	LastError       string     `json:"last_error"`
	FailureCategory string     `json:"failure_category"`
	ArchivedAt      *time.Time `json:"archived_at"`
}

func (j JobQueueClient) ListJSON(ctx context.Context, queue QueueName, owner string, ids ...string) ([]ArchivedJobJSON, error) {
	args := []string{"list", "--output", "json", "--limit", "0"}
	if queue != "" {
		args = append(args, "--queue", string(queue))
	}
	if owner != "" {
		args = append(args, "--verifier-id", owner)
	}
	if len(ids) > 0 {
		args = append(args, "--message-id", strings.Join(ids, ","))
	}
	out, err := j.client.CLIJSON(ctx, JobQueueSubcommand, args...)
	if err != nil {
		return nil, err
	}
	var rows []ArchivedJobJSON
	err = json.Unmarshal(out, &rows)
	return rows, err
}
