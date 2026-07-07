package progress

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const spinnerTick = 120 * time.Millisecond

// mpbReporter renders checklist rows with github.com/vbauerster/mpb. It uses the
// sequential auto-advance model: starting a new stage finalizes the previous
// one (the monolith bringup is a single sequential function, so a new stage
// starting means the prior stage succeeded). End finalizes the last stage.
type mpbReporter struct {
	mu  sync.Mutex
	p   *mpb.Progress
	cur *mpbStep
}

func newMpbReporter(out *os.File, title string) *mpbReporter {
	if title != "" {
		fmt.Fprintf(out, "Bringing up %s\n", title)
	} else {
		fmt.Fprintln(out, "Bringing up devenv")
	}
	p := mpb.New(
		mpb.WithOutput(out),
		mpb.WithRefreshRate(spinnerTick),
	)
	return &mpbReporter{p: p}
}

// newStep creates a checklist row (bar) at the given depth, optionally
// registering it as a child of parent.
func (r *mpbReporter) newStep(label string, depth int, parent *mpbStep) *mpbStep {
	st := &mpbStep{label: label, start: time.Now(), r: r, depth: depth}
	st.bar = r.p.New(1, mpb.NopStyle(),
		mpb.BarWidth(0),
		mpb.PrependDecorators(decor.Any(func(decor.Statistics) string { return st.prefix() })),
		mpb.AppendDecorators(decor.Any(func(decor.Statistics) string { return st.suffix() })),
	)
	if parent != nil {
		parent.mu.Lock()
		parent.children = append(parent.children, st)
		parent.mu.Unlock()
	}
	return st
}

// Stage starts a top-level row, auto-advancing (finalizing) the previous one.
func (r *mpbReporter) Stage(label string) Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil {
		r.cur.finish(false)
	}
	st := r.newStep(label, 0, nil)
	r.cur = st
	return st
}

func (r *mpbReporter) completeCurrent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil {
		r.cur.finish(false)
	}
}

// failCurrent marks the in-flight stage failed and returns its label.
func (r *mpbReporter) failCurrent() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil {
		return ""
	}
	label := r.cur.label
	r.cur.finish(true)
	return label
}

func (r *mpbReporter) stop() { r.p.Wait() }

type mpbStep struct {
	mu       sync.Mutex
	r        *mpbReporter
	bar      *mpb.Bar
	label    string
	depth    int
	children []*mpbStep
	start    time.Time
	end      time.Time
	total    int
	cur      int
	msg      string
	done     bool
	failed   bool
}

// child adds an indented sub-row nested under s. It does not participate in the
// reporter's top-level auto-advance; finishing s cascades to its children.
func (s *mpbStep) child(label string) Step {
	return s.r.newStep(label, s.depth+1, s)
}

func (s *mpbStep) SetTotal(n int) {
	s.mu.Lock()
	s.total = n
	s.mu.Unlock()
}

func (s *mpbStep) Inc() {
	s.mu.Lock()
	s.cur++
	s.mu.Unlock()
}

func (s *mpbStep) Msg(format string, args ...any) {
	s.mu.Lock()
	s.msg = fmt.Sprintf(format, args...)
	s.mu.Unlock()
}

func (s *mpbStep) Done() { s.finish(false) }
func (s *mpbStep) Fail() { s.finish(true) }

func (s *mpbStep) finish(failed bool) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.done = true
	s.failed = failed
	s.end = time.Now()
	bar := s.bar
	children := append([]*mpbStep(nil), s.children...)
	s.mu.Unlock()

	// Cascade to any children the caller didn't finish explicitly, so no
	// sub-row is left spinning when its parent is done.
	for _, c := range children {
		c.finish(failed)
	}

	// Release the step lock before touching the bar: mpb may synchronously
	// re-render, which calls prefix()/suffix() and re-takes s.mu.
	if failed {
		bar.Abort(false) // keep the final render (a ✗ row) instead of dropping it
	} else {
		bar.SetCurrent(1) // total is 1, so this completes the bar
	}
}

func (s *mpbStep) prefix() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var glyph string
	switch {
	case s.failed:
		glyph = "✗"
	case s.done:
		glyph = "✔"
	default:
		idx := int(time.Since(s.start)/spinnerTick) % len(spinnerFrames)
		glyph = spinnerFrames[idx]
	}
	// Indent nested rows and mark them with a tree connector; pad the whole
	// field so the elapsed/counter column stays roughly aligned across depths.
	tree := ""
	if s.depth > 0 {
		tree = strings.Repeat("  ", s.depth) + "↳ "
	}
	return fmt.Sprintf("  %-28s", tree+glyph+" "+s.label)
}

func (s *mpbStep) suffix() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.end
	if end.IsZero() {
		end = time.Now()
	}
	elapsed := end.Sub(s.start).Truncate(100 * time.Millisecond)
	detail := ""
	switch {
	case s.total > 0:
		detail = fmt.Sprintf("%d/%d  ", s.cur, s.total)
	case s.msg != "" && !s.done:
		detail = s.msg + "  "
	}
	return fmt.Sprintf("  %s%s", detail, elapsed)
}
