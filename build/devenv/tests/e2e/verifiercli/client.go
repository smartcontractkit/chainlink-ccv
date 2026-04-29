// Package verifiercli is a test-only client for the verifier CLI exposed
// by the committee binary inside a running verifier container. It wraps
// the raw `docker exec` invocations and splits the CLI surface into
// sub-clients (chain-statuses, job-queue) so individual tests can ask
// for just the capability they need.
//
// All methods are synchronous and return the raw stdout + stderr as a
// single string. Tests that need structured output parse the string -
// see ParseFirstListRow in chain_statuses.go for an example.
package verifiercli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// DefaultBinaryPath is the in-container path of the committee binary
	// in the standard devenv image. Override with WithBinaryPath for
	// alternate layouts.
	DefaultBinaryPath = "/app/cmd/verifier/committee/tmp/committee"

	// DefaultProcessMatch is the pgrep/pkill pattern that matches the
	// running committee process inside the container.
	DefaultProcessMatch = "tmp/committee"

	// defaultRestartReadyTimeout bounds how long RestartAndWaitReady
	// will poll the CLI before giving up.
	defaultRestartReadyTimeout = 60 * time.Second
	// defaultRestartReadyInterval is the poll interval during a
	// RestartAndWaitReady wait.
	defaultRestartReadyInterval = 2 * time.Second
)

// Client talks to a single verifier container. It is cheap to construct
// and safe to share across subtests that target the same container.
type Client struct {
	containerName string
	binaryPath    string
	processMatch  string
}

// Option configures a Client.
type Option func(*Client)

// WithBinaryPath overrides the in-container path of the committee CLI.
func WithBinaryPath(path string) Option {
	return func(c *Client) { c.binaryPath = path }
}

// WithProcessMatch overrides the pgrep/pkill pattern used to target the
// committee process for Pause/Resume.
func WithProcessMatch(match string) Option {
	return func(c *Client) { c.processMatch = match }
}

// NewClient returns a Client bound to containerName. Any leading slash
// (as returned by Docker's container inspect output) is stripped so
// callers can pass the name through unchanged.
func NewClient(containerName string, opts ...Option) *Client {
	c := &Client{
		containerName: strings.TrimPrefix(containerName, "/"),
		binaryPath:    DefaultBinaryPath,
		processMatch:  DefaultProcessMatch,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Container returns the container name this client is bound to. Useful
// for log messages and test assertions.
func (c *Client) Container() string { return c.containerName }

// Exec runs `docker exec <container> <args...>` and returns combined
// output. Errors include both the Docker error and the output so tests
// can include it in require.NoError messages.
func (c *Client) Exec(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", c.containerName}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker exec %s %v: %w (output: %s)", c.containerName, args, err, string(out))
	}
	return string(out), nil
}

// CLI runs the committee CLI against one of its subcommand trees
// (e.g. "ccv", "chain-statuses", "list"). Prefer the sub-clients -
// ChainStatuses, JobQueue - which compose these for you.
func (c *Client) CLI(ctx context.Context, subcommand []string, args ...string) (string, error) {
	full := append([]string{c.binaryPath}, subcommand...)
	full = append(full, args...)
	return c.Exec(ctx, full...)
}

// Pause sends pkill -STOP to the committee process. Tests use this
// before CLI mutations so the running verifier does not race the
// mutation (e.g. overwrite a freshly disabled chain status).
// Pause is safe to call multiple times; a STOP on an already-stopped
// process is a no-op.
func (c *Client) Pause(ctx context.Context) error {
	_, err := c.Exec(ctx, "pkill", "-STOP", "-f", c.processMatch)
	return err
}

// Resume sends pkill -CONT. Callers should defer Resume (or call it in
// t.Cleanup) to guarantee the environment is left healthy even when the
// test fails between Pause and the logical resume.
// A best-effort helper for cleanup paths is ResumeBestEffort.
func (c *Client) Resume(ctx context.Context) error {
	_, err := c.Exec(ctx, "pkill", "-CONT", "-f", c.processMatch)
	return err
}

// ResumeBestEffort is Resume without error propagation. Intended for
// t.Cleanup hooks where the test has already recorded its failure and
// we just want the container back to a usable state.
func (c *Client) ResumeBestEffort(ctx context.Context) {
	_, _ = c.Exec(ctx, "pkill", "-CONT", "-f", c.processMatch)
}

// RestartAndWaitReady restarts the verifier container via `docker
// restart` and then polls the CLI's list subcommand until it succeeds
// (the CLI fails while the embedded server is still booting). Returns
// an error if readiness is not reached before the timeout or ctx is
// canceled.
func (c *Client) RestartAndWaitReady(ctx context.Context) error {
	restartCmd := exec.CommandContext(ctx, "docker", "restart", c.containerName)
	if out, err := restartCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker restart %s: %w (output: %s)", c.containerName, err, string(out))
	}

	deadline := time.Now().Add(defaultRestartReadyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultRestartReadyInterval):
		}
		if _, err := c.ChainStatuses().List(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no probe error recorded")
	}
	return fmt.Errorf("verifier %s not ready within %s: %w", c.containerName, defaultRestartReadyTimeout, lastErr)
}
