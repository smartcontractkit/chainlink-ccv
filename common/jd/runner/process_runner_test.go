package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	testConfigPathEnvVar = "TEST_CONFIG_PATH"
	testOutputPathEnvVar = "TEST_OUTPUT_PATH"
	testBlockEnvVar      = "TEST_BLOCK"
)

var helperBinaryPath string

func TestMain(m *testing.M) {
	modRoot, err := findModuleRoot()
	if err != nil {
		panic("find module root: " + err.Error())
	}
	helperBinaryPath = filepath.Join(os.TempDir(), "jd-runner-helper-test")
	build := exec.Command("go", "build", "-o", helperBinaryPath, "./common/jd/runner/testdata/helper")
	build.Dir = modRoot
	if err := build.Run(); err != nil {
		panic("build helper binary: " + err.Error())
	}

	code := m.Run()
	_ = os.Remove(helperBinaryPath)

	os.Exit(code)
}

func findModuleRoot() (string, error) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	// go list -m runs from cwd; when tests run from package dir, we may get a relative path
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func TestProcessRunner_SpecPassedCorrectly(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	outputFile, err := os.CreateTemp("", "runner-spec-output-*")
	require.NoError(t, err)
	outputPath := outputFile.Name()
	require.NoError(t, outputFile.Close())
	t.Cleanup(func() { require.NoError(t, os.Remove(outputPath)) })

	os.Setenv(testOutputPathEnvVar, outputPath)
	t.Cleanup(func() { require.NoError(t, os.Unsetenv(testOutputPathEnvVar)) })

	r := NewProcessRunner(lggr, helperBinaryPath, testConfigPathEnvVar)
	spec := "verifier_id = \"test\"\n\n[section]\nkey = \"value with\nnewline\""
	err = r.StartJob(ctx, spec)
	require.NoError(t, err)

	// Helper exits after writing; wait for process to exit and output file to appear
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(outputPath)
		return err == nil && len(data) > 0
	}, 2*time.Second, 50*time.Millisecond)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, spec, string(data))

	require.NoError(t, r.StopJob(ctx))
}

func TestProcessRunner_StopJobIdempotent(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	r := NewProcessRunner(lggr, helperBinaryPath, testConfigPathEnvVar)
	err = r.StopJob(ctx)
	require.NoError(t, err)
	err = r.StopJob(ctx)
	require.NoError(t, err)
}

func TestProcessRunner_NoProcessBehavior(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	r := NewProcessRunner(lggr, helperBinaryPath, testConfigPathEnvVar)
	err = r.StopJob(ctx)
	require.NoError(t, err)
}

func TestProcessRunner_DoubleStartErrors(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	outputFile, err := os.CreateTemp("", "runner-double-start-*")
	require.NoError(t, err)
	outputPath := outputFile.Name()
	require.NoError(t, outputFile.Close())
	t.Cleanup(func() { require.NoError(t, os.Remove(outputPath)) })

	setTestOutputEnv(outputPath)
	t.Cleanup(restoreTestOutputEnv)

	r := NewProcessRunner(lggr, helperBinaryPath, testConfigPathEnvVar)
	spec := "key = \"value\""
	err = r.StartJob(ctx, spec)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.StopJob(ctx)) })

	err = r.StartJob(ctx, "other = \"spec\"")
	assert.ErrorIs(t, err, ErrJobAlreadyRunning)
}

func TestProcessRunner_StartStopLifecycle(t *testing.T) {
	ctx := context.Background()
	lggr, err := logger.New()
	require.NoError(t, err)

	outputFile, err := os.CreateTemp("", "runner-lifecycle-*")
	require.NoError(t, err)
	outputPath := outputFile.Name()
	require.NoError(t, outputFile.Close())
	t.Cleanup(func() { require.NoError(t, os.Remove(outputPath)) })

	setTestOutputEnv(outputPath)
	require.NoError(t, os.Setenv(testBlockEnvVar, "1")) // helper will block
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv(testBlockEnvVar))
		restoreTestOutputEnv()
	})

	r := NewProcessRunner(lggr, helperBinaryPath, testConfigPathEnvVar)
	spec := "blocking = true"
	err = r.StartJob(ctx, spec)
	require.NoError(t, err)

	// Process is running (blocking). Stop it.
	err = r.StopJob(ctx)
	require.NoError(t, err)

	// Process should be gone; second StopJob is no-op
	err = r.StopJob(ctx)
	require.NoError(t, err)
}

func setTestOutputEnv(path string) {
	os.Setenv(testOutputPathEnvVar, path)
}

func restoreTestOutputEnv() {
	// Restore is no-op if we didn't save; tests that need full restore use defer with origEnv
	os.Unsetenv(testOutputPathEnvVar)
}
