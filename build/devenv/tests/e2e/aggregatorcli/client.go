// Package aggregatorcli is a test-only client for the aggregator CLI exposed
// by the aggregator binary inside a running container. It wraps raw `docker
// exec` invocations and splits the CLI surface into sub-clients (chains) so
// individual tests can ask for just the capability they need.
//
// All methods are synchronous and return the raw stdout + stderr as a single
// string. The aggregator CLI writes directly to the database and the
// in-memory registry refreshes periodically, so Pause/Resume/Restart are not
// needed — just call the CLI and wait for the next refresh.
package aggregatorcli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const (
	// DefaultBinaryPath is the in-container path of the aggregator binary.
	// In devenv the binary is built by air into /tmp/aggregator (see aggregator/air.toml).
	DefaultBinaryPath = "/tmp/aggregator"
)

// Client talks to a single aggregator container. It is cheap to construct
// and safe to share across subtests that target the same container.
type Client struct {
	containerName string
	binaryPath    string
}

// Option configures a Client.
type Option func(*Client)

// WithBinaryPath overrides the in-container path of the aggregator binary.
func WithBinaryPath(path string) Option {
	return func(c *Client) { c.binaryPath = path }
}

// NewClient returns a Client bound to containerName. Any leading slash is
// stripped so callers can pass the name through unchanged.
func NewClient(containerName string, opts ...Option) *Client {
	c := &Client{
		containerName: strings.TrimPrefix(containerName, "/"),
		binaryPath:    DefaultBinaryPath,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Container returns the container name this client is bound to.
func (c *Client) Container() string { return c.containerName }

// Exec runs `docker exec <container> <args...>` and returns combined output.
func (c *Client) Exec(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", c.containerName}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker exec %s %v: %w (output: %s)", c.containerName, args, err, string(out))
	}
	return string(out), nil
}

// CLI runs the aggregator CLI subcommand tree. Prefer the sub-clients, which
// compose these calls for you.
func (c *Client) CLI(ctx context.Context, subcommand []string, args ...string) (string, error) {
	full := append([]string{c.binaryPath}, subcommand...)
	full = append(full, args...)
	return c.Exec(ctx, full...)
}
