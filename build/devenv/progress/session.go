package progress

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/term"
)

// Options configures a progress Session.
type Options struct {
	// Title is shown in the header line above the checklist.
	Title string
	// LogPath overrides where the captured firehose is written. When empty it
	// defaults to $CCV_UP_LOG, then <cwd>/uplog.txt.
	LogPath string
}

// Session owns the terminal capture and renderer for one bringup.
type Session struct {
	mu      sync.Mutex
	active  bool
	ended   bool
	logPath string
	r       *mpbReporter
	cap     *capture
	sigCh   chan os.Signal
}

func defaultLogPath(override string) string {
	if override != "" {
		return override
	}
	if p := os.Getenv("CCV_UP_LOG"); p != "" {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	return filepath.Join(wd, "uplog.txt")
}

// Begin installs the progress UI when stderr is a terminal. On a TTY it
// redirects stdout/stderr to a log file, starts the renderer, and returns a
// context carrying a live Reporter. Off a TTY it is a no-op: the returned
// context is unchanged and every downstream Stage call resolves to a no-op, so
// logs flow exactly as before. End must always be called (typically deferred).
func Begin(ctx context.Context, opts Options) (context.Context, *Session) {
	logPath := defaultLogPath(opts.LogPath)
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return ctx, &Session{active: false, logPath: logPath}
	}
	c, err := newCapture(logPath)
	if err != nil {
		// Capture failed; fall back to plain logging rather than breaking bringup.
		return ctx, &Session{active: false, logPath: logPath}
	}
	r := newMpbReporter(c.term, opts.Title)
	s := &Session{active: true, logPath: logPath, r: r, cap: c}
	s.installSignalHandler()
	return WithReporter(ctx, r), s
}

// Active reports whether the progress UI is engaged (i.e. we were on a TTY).
func (s *Session) Active() bool { return s != nil && s.active }

// LogPath returns the path the firehose is (or would be) written to.
func (s *Session) LogPath() string {
	if s == nil {
		return ""
	}
	return s.logPath
}

// End tears down the UI: it finalizes the current row, stops the renderer, and
// restores stdout/stderr. On failure it prints the log path to the (restored)
// terminal. It is idempotent; the returned bool reports whether this call was
// the one that performed the teardown.
func (s *Session) End(runErr error) bool {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return false
	}
	s.ended = true
	active := s.active
	s.mu.Unlock()

	if !active {
		return true
	}

	failedLabel := ""
	if runErr != nil {
		failedLabel = s.r.failCurrent()
	} else {
		s.r.completeCurrent()
	}
	s.r.stop()
	s.cap.restore()
	s.stopSignalHandler()

	if runErr != nil {
		fmt.Fprint(os.Stderr, "\n✗ devenv startup failed")
		if failedLabel != "" {
			fmt.Fprintf(os.Stderr, " during %q", failedLabel)
		}
		fmt.Fprintf(os.Stderr, "\n  logs: %s\n", s.logPath)
	}
	return true
}

func (s *Session) installSignalHandler() {
	s.sigCh = make(chan os.Signal, 1)
	signal.Notify(s.sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if _, ok := <-s.sigCh; !ok {
			return
		}
		// If this call actually performed the teardown, the process was
		// interrupted mid-bringup — exit with the conventional 128+SIGINT code.
		if s.End(fmt.Errorf("interrupted")) {
			os.Exit(130)
		}
	}()
}

func (s *Session) stopSignalHandler() {
	if s.sigCh != nil {
		signal.Stop(s.sigCh)
		close(s.sigCh)
	}
}

// capture redirects the process stdout/stderr fds to a log file while keeping a
// duplicate of the real terminal for the renderer to draw on. This is the same
// fd-level (dup2) mechanism already used by `ccv test --log`, so subprocess and
// testcontainers output is captured too — not just in-process zerolog.
type capture struct {
	logFile     *os.File
	term        *os.File
	savedStdout int
	savedStderr int
}

func newCapture(logPath string) (*capture, error) {
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	savedStdout, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		_ = lf.Close()
		return nil, err
	}
	savedStderr, err := syscall.Dup(int(os.Stderr.Fd()))
	if err != nil {
		_ = syscall.Close(savedStdout)
		_ = lf.Close()
		return nil, err
	}
	realTerm := os.NewFile(uintptr(savedStderr), "devenv_term")
	_ = syscall.Dup2(int(lf.Fd()), int(os.Stdout.Fd()))
	_ = syscall.Dup2(int(lf.Fd()), int(os.Stderr.Fd()))
	return &capture{logFile: lf, term: realTerm, savedStdout: savedStdout, savedStderr: savedStderr}, nil
}

func (c *capture) restore() {
	_ = syscall.Dup2(c.savedStdout, int(os.Stdout.Fd()))
	_ = syscall.Dup2(c.savedStderr, int(os.Stderr.Fd()))
	_ = syscall.Close(c.savedStdout)
	_ = c.term.Close() // owns savedStderr
	_ = c.logFile.Close()
}
