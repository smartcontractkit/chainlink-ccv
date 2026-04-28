// Package indexercli is a test-only client for the indexer replay CLI
// inside a running indexer container.
package indexercli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const DefaultReplayBinary = "/bin/indexer-replay"

// Client talks to the indexer replay CLI inside one container.
type Client struct {
	containerName string
	replayBinary  string
}

// Option configures a Client.
type Option func(*Client)

// WithReplayBinary overrides the in-container replay binary path.
func WithReplayBinary(path string) Option {
	return func(c *Client) { c.replayBinary = path }
}

// NewClient returns a Client bound to containerName. A leading slash from
// Docker inspect output is stripped so callers can pass container names through.
func NewClient(containerName string, opts ...Option) *Client {
	c := &Client{
		containerName: strings.TrimPrefix(containerName, "/"),
		replayBinary:  DefaultReplayBinary,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Container returns the normalized container name.
func (c *Client) Container() string {
	return c.containerName
}

// Exec runs docker exec against the bound indexer container.
func (c *Client) Exec(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", c.containerName}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker exec %s %v: %w (output: %s)", c.containerName, args, err, string(out))
	}
	return string(out), nil
}

// Replay runs an indexer-replay subcommand.
func (c *Client) Replay(ctx context.Context, subcommand string, args ...string) (string, error) {
	full := append([]string{c.replayBinary, subcommand}, args...)
	return c.Exec(ctx, full...)
}

// List runs indexer-replay list.
func (c *Client) List(ctx context.Context) (string, error) {
	return c.Replay(ctx, "list")
}

// Status runs indexer-replay status.
func (c *Client) Status(ctx context.Context, id string) (string, error) {
	return c.Replay(ctx, "status", "--id", id)
}

// DiscoverySince runs indexer-replay discovery --since, optionally with --force.
func (c *Client) DiscoverySince(ctx context.Context, since string, force bool) (string, error) {
	args := []string{"--since", since}
	if force {
		args = append(args, "--force")
	}
	return c.Replay(ctx, "discovery", args...)
}

// MessagesByID runs indexer-replay messages --ids for one message, optionally with --force.
func (c *Client) MessagesByID(ctx context.Context, msgIDHex string, force bool) (string, error) {
	args := []string{"--ids", msgIDHex}
	if force {
		args = append(args, "--force")
	}
	return c.Replay(ctx, "messages", args...)
}
