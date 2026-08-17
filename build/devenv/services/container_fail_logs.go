package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// containerLogTailTimeout bounds the log fetch in ContainerLogTail.
const containerLogTailTimeout = 15 * time.Second

// ContainerLogTail returns the last maxBytes of the container's combined log stream, for
// inclusion in error messages. Readiness failures otherwise surface only as a timeout in the
// test output, leaving the application's own startup error invisible without CI artifacts.
// Best-effort: a read failure yields a placeholder rather than an error.
//
// ctx contributes its values but not its cancellation. This runs on the failure path, where the
// caller's ctx has often already hit the deadline that caused the failure, and a diagnostic that
// disappears exactly when it is needed is worse than no diagnostic at all. The fetch gets its own
// timeout instead.
func ContainerLogTail(ctx context.Context, c testcontainers.Container, maxBytes int) string {
	if maxBytes <= 0 {
		return "<no log tail requested>"
	}
	if c == nil {
		return "<no container handle>"
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), containerLogTailTimeout)
	defer cancel()

	reader, err := c.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("<failed to open container logs: %v>", err)
	}
	defer reader.Close()

	tail, err := readTail(reader, maxBytes)
	switch {
	case err != nil && len(tail) == 0:
		return fmt.Sprintf("<failed to read container logs: %v>", err)
	case err != nil:
		// Partial output still tends to hold the startup error we are after.
		return fmt.Sprintf("%s\n<log read ended early: %v>", tail, err)
	default:
		return string(tail)
	}
}

// readTail returns the last maxBytes read from r, holding no more than that many bytes at a time
// so a noisy container cannot pull its entire log stream into memory.
func readTail(r io.Reader, maxBytes int) ([]byte, error) {
	tail := make([]byte, 0, maxBytes)
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			tail = appendTail(tail, chunk[:n], maxBytes)
		}
		if errors.Is(err, io.EOF) {
			return tail, nil
		}
		if err != nil {
			return tail, err
		}
	}
}

// appendTail appends src to dst, dropping the oldest bytes so the result never exceeds maxBytes.
func appendTail(dst, src []byte, maxBytes int) []byte {
	if len(src) >= maxBytes {
		return append(dst[:0], src[len(src)-maxBytes:]...)
	}
	if overflow := len(dst) + len(src) - maxBytes; overflow > 0 {
		dst = append(dst[:0], dst[overflow:]...)
	}
	return append(dst, src...)
}
