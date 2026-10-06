package verifier

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
)

// adminSiblingRestartDelay caps how fast a crashed console sibling is respawned.
const adminSiblingRestartDelay = 5 * time.Second

// StartAdminConsoleSibling starts the admin console (`ccv admin serve`) as a
// supervised sibling process when a console config file is present: the
// verifier's container serves the admin UI on its dedicated port with an
// independent lifecycle — a crashed console is restarted without touching the
// verifier. An absent config means the console is disabled. The returned stop
// function terminates the sibling; nil means nothing was started.
func StartAdminConsoleSibling() (stop func()) {
	path := os.Getenv(admin.ConfigPathEnv)
	if path == "" {
		path = admin.DefaultConfigPath
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "admin console sibling: cannot resolve own executable: %v\n", err)
		return nil
	}

	var mu sync.Mutex
	var current *exec.Cmd
	setCurrent := func(c *exec.Cmd) {
		mu.Lock()
		defer mu.Unlock()
		current = c
	}
	killCurrent := func() {
		mu.Lock()
		defer mu.Unlock()
		if current != nil && current.Process != nil {
			_ = current.Process.Kill()
		}
	}

	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		for {
			child := exec.Command(exe, "ccv", "admin", "serve", "--config", path)
			// Container logs carry both processes; the console's own gin logger
			// distinguishes its lines.
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			setCurrent(child)
			startErr := child.Start()
			if startErr == nil {
				waitErr := child.Wait()
				if waitErr == nil {
					_, _ = fmt.Fprintf(os.Stderr, "admin console sibling: stopped\n")
					return
				}
				startErr = waitErr
			}
			_, _ = fmt.Fprintf(os.Stderr, "admin console sibling: exited (%v); restarting in %s\n",
				startErr, adminSiblingRestartDelay)
			select {
			case <-done:
				return
			case <-time.After(adminSiblingRestartDelay):
			}
		}
	}()

	return func() {
		close(done)
		killCurrent()
		<-exited
	}
}
