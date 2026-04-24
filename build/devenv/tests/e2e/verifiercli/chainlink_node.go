package verifiercli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	DefaultCLNodeBinaryPath  = "chainlink"
	DefaultCLNodeProcessName = "chainlink"
	DefaultCLNodePassword    = "/config/node_password"
	DefaultCLNodeHealthURL   = "http://localhost:6688/health"
)

var DefaultCLNodeConfigArgs = []string{
	"-c", "/config/config",
	"-c", "/config/overrides",
	"-c", "/config/user-overrides",
	"-s", "/config/secrets",
	"-s", "/config/secrets-overrides",
	"-s", "/config/user-secrets-overrides",
}

var CLNodeChainStatusesSubcommand = []string{"local", "ccv", "chain-statuses"}

// CLNodeClient talks to the verifier CLI exposed through a full Chainlink node.
type CLNodeClient struct {
	containerName string
	binaryPath    string
	processMatch  string
	configArgs    []string
	passwordFile  string
	healthURL     string
}

// CLNodeOption configures a CLNodeClient.
type CLNodeOption func(*CLNodeClient)

// WithCLNodeBinaryPath overrides the in-container chainlink binary path.
func WithCLNodeBinaryPath(path string) CLNodeOption {
	return func(c *CLNodeClient) { c.binaryPath = path }
}

// WithCLNodeProcessMatch overrides the process match used for Pause and Resume.
func WithCLNodeProcessMatch(match string) CLNodeOption {
	return func(c *CLNodeClient) { c.processMatch = match }
}

// WithCLNodeConfigArgs overrides the chainlink -c/-s config flags.
func WithCLNodeConfigArgs(args ...string) CLNodeOption {
	return func(c *CLNodeClient) { c.configArgs = append([]string(nil), args...) }
}

// WithCLNodePasswordFile overrides the --password file path. Empty disables the flag.
func WithCLNodePasswordFile(path string) CLNodeOption {
	return func(c *CLNodeClient) { c.passwordFile = path }
}

// WithCLNodeHealthURL overrides the local health endpoint probed after restart.
func WithCLNodeHealthURL(url string) CLNodeOption {
	return func(c *CLNodeClient) { c.healthURL = url }
}

// NewCLNodeClient returns a Client bound to a Chainlink node container.
func NewCLNodeClient(containerName string, opts ...CLNodeOption) *CLNodeClient {
	c := &CLNodeClient{
		containerName: strings.TrimPrefix(containerName, "/"),
		binaryPath:    DefaultCLNodeBinaryPath,
		processMatch:  DefaultCLNodeProcessName,
		configArgs:    append([]string(nil), DefaultCLNodeConfigArgs...),
		passwordFile:  DefaultCLNodePassword,
		healthURL:     DefaultCLNodeHealthURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Container returns the normalized container name.
func (c *CLNodeClient) Container() string {
	return c.containerName
}

// Exec runs docker exec against the bound Chainlink node container.
func (c *CLNodeClient) Exec(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", c.containerName}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker exec %s %v: %w (output: %s)", c.containerName, args, err, string(out))
	}
	return string(out), nil
}

// CLI runs the chainlink local ccv subcommand tree.
func (c *CLNodeClient) CLI(ctx context.Context, subcommand []string, args ...string) (string, error) {
	full := append([]string{c.binaryPath}, c.configArgs...)
	full = append(full, subcommand...)
	if c.passwordFile != "" {
		full = append(full, "--password", c.passwordFile)
	}
	full = append(full, args...)
	return c.Exec(ctx, full...)
}

// Pause stops the Chainlink process while tests mutate local CLI state.
func (c *CLNodeClient) Pause(ctx context.Context) error {
	_, err := c.Exec(ctx, "pkill", "-STOP", "-f", c.processMatch)
	return err
}

// Resume continues a process stopped by Pause.
func (c *CLNodeClient) Resume(ctx context.Context) error {
	_, err := c.Exec(ctx, "pkill", "-CONT", "-f", c.processMatch)
	return err
}

// ResumeBestEffort resumes without propagating errors for cleanup paths.
func (c *CLNodeClient) ResumeBestEffort(ctx context.Context) {
	_, _ = c.Exec(ctx, "pkill", "-CONT", "-f", c.processMatch)
}

// RestartAndWaitReady restarts the node container and polls its local health endpoint.
func (c *CLNodeClient) RestartAndWaitReady(ctx context.Context) error {
	restartCmd := exec.CommandContext(ctx, "docker", "restart", c.containerName)
	if out, err := restartCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker restart %s: %w (output: %s)", c.containerName, err, string(out))
	}

	deadline := time.Now().Add(defaultRestartReadyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := c.Exec(ctx, "curl", "-sf", c.healthURL); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultRestartReadyInterval):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no health probe error recorded")
	}
	return fmt.Errorf("CL node %s not healthy within %s: %w", c.containerName, defaultRestartReadyTimeout, lastErr)
}

// CLNodeChainStatusesClient wraps the chainlink local ccv chain-statuses commands.
type CLNodeChainStatusesClient struct {
	client *CLNodeClient
}

// ChainStatuses returns a sub-client for chain-statuses operations.
func (c *CLNodeClient) ChainStatuses() CLNodeChainStatusesClient {
	return CLNodeChainStatusesClient{client: c}
}

// SetFinalizedHeight rewinds or advances a verifier's finalized source height.
func (s CLNodeChainStatusesClient) SetFinalizedHeight(ctx context.Context, sel ChainSelector, verifierID string, height BlockHeight) (string, error) {
	return s.client.CLI(ctx, CLNodeChainStatusesSubcommand,
		"set-finalized-height",
		"--chain-selector", string(sel),
		"--verifier-id", verifierID,
		"--block-height", string(height))
}
