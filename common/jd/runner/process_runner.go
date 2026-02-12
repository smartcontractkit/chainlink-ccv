package runner

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	jdlifecycle "github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const shutdownTimeout = 5 * time.Second

func NewProcessRunner(lggr logger.Logger, processBinaryPath, configPathEnvVar string) jdlifecycle.JobRunner {
	return &processRunner{
		lggr:               logger.Sugared(logger.Named(lggr, "ProcessRunner")),
		processBinaryPath:  processBinaryPath,
		configPathEnvVar:   configPathEnvVar,
	}
}

// processRunner is a JobRunner implementation that starts and stops processes.
// The job spec (e.g. TOML) is written to a temp file; the process is started with
// an environment variable (configPathEnvVar) set to that file path. The child binary
// reads config from that path (e.g. VERIFIER_CONFIG_PATH for the verifier).
type processRunner struct {
	lggr              logger.Logger
	processBinaryPath  string
	configPathEnvVar   string

	mu         sync.Mutex
	cmd        *exec.Cmd
	tempPath   string
}

// StartJob implements lifecycle.JobRunner.
func (p *processRunner) StartJob(ctx context.Context, spec string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil {
		return ErrJobAlreadyRunning
	}

	f, err := os.CreateTemp("", "jd-job-spec-*.toml")
	if err != nil {
		return err
	}
	tempPath := f.Name()
	if _, err := f.WriteString(spec); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	env := append(os.Environ(), p.configPathEnvVar+"="+tempPath)
	cmd := exec.Command(p.processBinaryPath)
	cmd.Env = env
	// Process runs with background context so it outlives StartJob.
	// Stdout/Stderr left unset so subprocess inherits parent's streams.

	if err := cmd.Start(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	p.cmd = cmd
	p.tempPath = tempPath
	p.lggr.Infow("Started job process", "pid", cmd.Process.Pid, "tempPath", tempPath)
	return nil
}

// StopJob implements lifecycle.JobRunner.
func (p *processRunner) StopJob(ctx context.Context) error {
	p.mu.Lock()
	cmd := p.cmd
	tempPath := p.tempPath
	if cmd == nil {
		p.mu.Unlock()
		p.lggr.Infow("StopJob: no job running")
		return nil
	}
	p.cmd = nil
	p.tempPath = ""
	p.mu.Unlock()

	p.lggr.Infow("Stopping job process", "pid", cmd.Process.Pid)
	_ = cmd.Process.Signal(syscall.SIGTERM)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Process exited
	case <-time.After(shutdownTimeout):
		p.lggr.Warnw("Process did not exit after SIGTERM, sending SIGKILL", "pid", cmd.Process.Pid)
		_ = cmd.Process.Kill()
		<-done
	}

	_ = os.Remove(tempPath)
	return nil
}

var _ jdlifecycle.JobRunner = &processRunner{}
