// Package quiesce provides `ccv quiesce pause|resume`, which SIGSTOP/SIGCONT the
// verifier service process in this container. The production image is distroless
// and has no pkill, so quiescing for curse-replay or CLI mutations goes through here.
package quiesce

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/urfave/cli"
)

// kill is a seam for tests, which must not stop their own process.
var kill = syscall.Kill

// InitQuiesceCommands returns the pause/resume subcommands for `ccv quiesce`.
func InitQuiesceCommands() []cli.Command {
	return []cli.Command{
		{
			Name:  "pause",
			Usage: "Pause (SIGSTOP) the verifier service process in this container, so CLI mutations do not race it",
			Action: func(*cli.Context) error {
				return signalService("/proc", syscall.SIGSTOP)
			},
		},
		{
			Name:  "resume",
			Usage: "Resume (SIGCONT) the verifier service process in this container after a pause",
			Action: func(*cli.Context) error {
				return signalService("/proc", syscall.SIGCONT)
			},
		},
	}
}

func signalService(procRoot string, sig syscall.Signal) error {
	pid, err := findServicePID(procRoot, os.Getpid(), ownName())
	if err != nil {
		return err
	}
	if err := kill(pid, sig); err != nil {
		return fmt.Errorf("cannot signal verifier service (pid %d): %w", pid, err)
	}
	fmt.Printf("sent %s to verifier service (pid %d)\n", sig, pid) //nolint:forbidigo // CLI user output
	return nil
}

func ownName() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Base(exe)
}

// findServicePID returns the lowest PID under procRoot whose comm equals name,
// excluding self. tini starts the service at container boot, so it holds the
// lowest PID; later matches are transient CLI invocations such as this one.
func findServicePID(procRoot string, self int, name string) (int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return -1, fmt.Errorf("cannot list %s: %w", procRoot, err)
	}
	best := -1
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		// #nosec G304 -- the path is enumerated from procRoot, which is the point of the scan
		comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name && (best == -1 || pid < best) {
			best = pid
		}
	}
	if best == -1 {
		return -1, fmt.Errorf("no running verifier service found (looked for comm %q under %s)", name, procRoot)
	}
	return best, nil
}
