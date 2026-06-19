package reporter

import (
	"fmt"
	"io"
	"sync"
	"time"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
)

type componentStart struct {
	phase int
	name  string
	start time.Time
}

// simpleReporter writes one line per component completion to out.
// No cursor movement — safe for pipes, CI, and log capture.
type simpleReporter struct {
	mu      sync.Mutex
	out     io.Writer
	starts  map[string]componentStart // key: "phase:name"
	elapsed time.Duration
}

func newSimpleReporter(out io.Writer) *simpleReporter {
	return &simpleReporter{
		out:    out,
		starts: make(map[string]componentStart),
	}
}

func (r *simpleReporter) key(phase int, name string) string {
	return fmt.Sprintf("%d:%s", phase, name)
}

func (r *simpleReporter) OnStart(phase int, name string, _ devenvruntime.Component) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts[r.key(phase, name)] = componentStart{phase: phase, name: name, start: time.Now()}
}

func (r *simpleReporter) OnFinish(phase int, name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := r.key(phase, name)
	cs, ok := r.starts[k]
	if !ok {
		cs = componentStart{phase: phase, name: name, start: time.Now()}
	}
	delete(r.starts, k)

	dur := time.Since(cs.start).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(r.out, "✗ [%d] %-28s %6s  error: %v\n", phase, name, dur, err)
	} else {
		fmt.Fprintf(r.out, "✓ [%d] %-28s %6s\n", phase, name, dur)
	}
}

func (r *simpleReporter) OnStageStart(name string) {
	fmt.Fprintf(r.out, "── %s\n", name)
}

func (r *simpleReporter) OnStageFinish(name string, err error) {
	if err != nil {
		fmt.Fprintf(r.out, "✗ %s failed: %v\n", name, err)
	}
}

func (r *simpleReporter) Run(fn func() error) error {
	start := time.Now()
	err := fn()
	r.elapsed = time.Since(start)
	return err
}

func (r *simpleReporter) PrintSummary(outTomlPath string) {
	printSummary(r.out, outTomlPath, r.elapsed)
}
