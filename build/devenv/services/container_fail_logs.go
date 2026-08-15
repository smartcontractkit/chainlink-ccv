package services

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/testcontainers/testcontainers-go"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// SaveFailingTestcontainerLogs copies the container log stream to
// {DefaultCTFLogsDir}/{name}-attempt-{N}.log. It is best-effort: errors
// are logged and returned so callers can ignore them before Terminate.
func SaveFailingTestcontainerLogs(ctx context.Context, c testcontainers.Container, containerName string, attempt int) error {
	if c == nil {
		return nil
	}
	reader, err := c.Logs(ctx)
	if err != nil {
		framework.L.Warn().Err(err).Int("attempt", attempt).Str("name", containerName).Msg("failed to read testcontainer logs before terminate")
		return err
	}
	defer reader.Close()

	dir := framework.DefaultCTFLogsDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		framework.L.Warn().Err(err).Str("path", dir).Msg("failed to create failed-start log dir")
		return err
	}

	name := strings.TrimSpace(containerName)
	if name == "" {
		name = "container"
	}
	name = strings.ReplaceAll(name, string(filepath.Separator), "_")

	outPath := filepath.Join(dir, fmt.Sprintf("%s-attempt-%d.log", name, attempt))
	out, err := os.Create(outPath)
	if err != nil {
		framework.L.Warn().Err(err).Str("path", outPath).Msg("failed to create failed-start log file")
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, reader); err != nil {
		framework.L.Warn().Err(err).Str("path", outPath).Msg("failed to write failed-start log file")
		return err
	}
	framework.L.Info().Str("path", outPath).Int("attempt", attempt).Str("name", name).Msg("saved testcontainer logs before terminate")
	return nil
}

// ContainerLogTail returns the last maxBytes of the container's combined log stream, for
// inclusion in error messages. Readiness failures otherwise surface only as a timeout in the
// test output, leaving the application's own startup error invisible without CI artifacts.
// Best-effort: a read failure yields a placeholder rather than an error.
func ContainerLogTail(ctx context.Context, c testcontainers.Container, maxBytes int) string {
	if c == nil {
		return "<no container handle>"
	}
	reader, err := c.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("<failed to open container logs: %v>", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Sprintf("<failed to read container logs: %v>", err)
	}
	if len(data) > maxBytes {
		data = data[len(data)-maxBytes:]
	}
	return string(data)
}
