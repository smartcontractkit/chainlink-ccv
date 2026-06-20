package reporter

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
)

// ── messages ────────────────────────────────────────────────────────────────

type tickMsg time.Time

type componentStartedMsg struct {
	phase int
	name  string
}

type componentFinishedMsg struct {
	phase int
	name  string
	err   error
}

type statusUpdateMsg struct {
	phase  int
	name   string
	status string
}

type (
	stageStartedMsg  struct{ name string }
	stageFinishedMsg struct {
		name string
		err  error
	}
)
type doneMsg struct{ err error }

// ── styles ───────────────────────────────────────────────────────────────────

type tuiStyles struct {
	ok     lipgloss.Style
	fail   lipgloss.Style
	stage  lipgloss.Style
	sep    lipgloss.Style
	dim    lipgloss.Style
	active lipgloss.Style
}

func newSepStyle(out io.Writer) lipgloss.Style {
	return lipgloss.NewRenderer(out).NewStyle().Foreground(lipgloss.Color("8"))
}

func newStyles(out io.Writer) tuiStyles {
	r := lipgloss.NewRenderer(out)
	return tuiStyles{
		ok:     r.NewStyle().Foreground(lipgloss.Color("2")),            // green
		fail:   r.NewStyle().Foreground(lipgloss.Color("1")),            // red
		stage:  r.NewStyle().Foreground(lipgloss.Color("4")),            // blue
		sep:    newSepStyle(out),                                        // dark gray
		dim:    r.NewStyle().Foreground(lipgloss.Color("8")),            // dark gray
		active: r.NewStyle().Foreground(lipgloss.Color("2")).Bold(true), // bold green — in-progress
	}
}

var spinnerFrames = []string{"|", "/", "-", "\\"}

// fmtDur formats a duration for stable fixed-width display: always in seconds
// (never ms), one decimal place, seconds zero-padded within minutes so the
// string length is stable (e.g. "1m09.3s" not "1m9.3s").
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(100 * time.Millisecond)
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := d.Seconds() - float64(mins)*60
	return fmt.Sprintf("%dm%04.1fs", mins, secs)
}

// ── model ────────────────────────────────────────────────────────────────────

type statusEntry struct {
	text string
	at   time.Time
}

type activeComp struct {
	phase    int
	name     string
	start    time.Time
	statuses []statusEntry
}

type tuiModel struct {
	styles      tuiStyles
	log         []string // completed / stage lines
	active      map[string]*activeComp
	activeOrder []string // insertion-ordered keys for stable display
	runStart    time.Time
	frame       int
	done        bool
	cancelled   bool
	finalErr    error
	width       int
}

func newModel(out io.Writer) tuiModel {
	return tuiModel{
		styles:   newStyles(out),
		active:   make(map[string]*activeComp),
		runStart: time.Now(),
		width:    80,
	}
}

func compKey(phase int, name string) string {
	return fmt.Sprintf("%d:%s", phase, name)
}

func (m tuiModel) Init() tea.Cmd {
	return tickEvery(100 * time.Millisecond)
}

func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.cancelled = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width

	case tickMsg:
		m.frame++
		if m.done && len(m.active) == 0 {
			return m, tea.Quit
		}
		return m, tickEvery(100 * time.Millisecond)

	case stageStartedMsg:
		m.log = append(m.log, m.styles.stage.Render("── "+msg.name))

	case stageFinishedMsg:
		if msg.err != nil {
			m.log = append(m.log, m.styles.fail.Render(fmt.Sprintf("✗ %s failed: %v", msg.name, msg.err)))
		}

	case componentStartedMsg:
		key := compKey(msg.phase, msg.name)
		m.active[key] = &activeComp{phase: msg.phase, name: msg.name, start: time.Now()}
		m.activeOrder = append(m.activeOrder, key)

	case componentFinishedMsg:
		key := compKey(msg.phase, msg.name)
		cs, ok := m.active[key]
		finishedAt := time.Now()
		start := finishedAt
		if ok {
			start = cs.start
		}
		dur := fmtDur(finishedAt.Sub(start))
		delete(m.active, key)
		// Remove from ordered list.
		for i, k := range m.activeOrder {
			if k == key {
				m.activeOrder = append(m.activeOrder[:i], m.activeOrder[i+1:]...)
				break
			}
		}
		if msg.err != nil {
			m.log = append(m.log, m.styles.fail.Render(
				fmt.Sprintf("✗ [%d] %-28s %7s  error: %v", msg.phase, msg.name, dur, msg.err)))
		} else {
			// Green checkmark and name; phase and duration in default color.
			m.log = append(m.log, m.styles.ok.Render("✓")+
				fmt.Sprintf(" [%d] ", msg.phase)+
				m.styles.ok.Render(fmt.Sprintf("%-28s", msg.name))+
				fmt.Sprintf(" %7s", dur))
		}
		// Append accumulated status lines with per-entry durations.
		if ok {
			n := len(cs.statuses)
			for i, entry := range cs.statuses {
				var entryDur time.Duration
				if i < n-1 {
					entryDur = cs.statuses[i+1].at.Sub(entry.at)
				} else {
					entryDur = finishedAt.Sub(entry.at)
				}
				prefix := "      ├── "
				if i == n-1 {
					prefix = "      └── "
				}
				m.log = append(m.log, m.styles.dim.Render(fmt.Sprintf("%s%7s  %s", prefix, fmtDur(entryDur), entry.text)))
			}
		}
		if m.done && len(m.active) == 0 {
			return m, tea.Quit
		}

	case statusUpdateMsg:
		key := compKey(msg.phase, msg.name)
		if cs, ok := m.active[key]; ok && msg.status != "" {
			if n := len(cs.statuses); n == 0 || cs.statuses[n-1].text != msg.status {
				cs.statuses = append(cs.statuses, statusEntry{text: msg.status, at: time.Now()})
			}
		}

	case doneMsg:
		m.done = true
		m.finalErr = msg.err
		if len(m.active) == 0 {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m tuiModel) View() string {
	var sb strings.Builder

	for _, line := range m.log {
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	if len(m.active) == 0 {
		return sb.String()
	}

	sep := strings.Repeat("─", min(m.width, 60))
	sb.WriteString(m.styles.sep.Render(sep))
	sb.WriteString("\n")

	spin := spinnerFrames[m.frame%len(spinnerFrames)]
	for _, key := range m.activeOrder {
		cs, ok := m.active[key]
		if !ok {
			continue
		}
		elapsed := time.Since(cs.start)
		cumulative := time.Since(m.runStart)
		// Line 1: spinner+phase in default, name in bold green, duration in default.
		fmt.Fprintf(&sb, "%s [%d] ", spin, cs.phase)
		sb.WriteString(m.styles.active.Render(fmt.Sprintf("%-28s", cs.name)))
		fmt.Fprintf(&sb, " %7s", fmtDur(elapsed))
		sb.WriteString("  " + m.styles.dim.Render(fmt.Sprintf("(%s)", fmtDur(cumulative))))
		sb.WriteString("\n")
		// Status lines use tree connectors: ├── for middle entries, └── for last.
		for i, entry := range cs.statuses {
			var entryDur time.Duration
			if i < len(cs.statuses)-1 {
				entryDur = cs.statuses[i+1].at.Sub(entry.at)
			} else {
				entryDur = time.Since(entry.at)
			}
			prefix := "      ├── "
			if i == len(cs.statuses)-1 {
				prefix = "      └── "
			}
			line := fmt.Sprintf("%s%7s  %s", prefix, fmtDur(entryDur), entry.text)
			sb.WriteString(m.styles.dim.Render(line))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// ── reporter ─────────────────────────────────────────────────────────────────

type bubbletearReporter struct {
	mu          sync.Mutex
	program     *tea.Program
	finalErr    error
	elapsed     time.Duration
	out         io.Writer
	stopPollers map[string]func()
}

func newBubbletearReporter(out io.Writer) *bubbletearReporter {
	return &bubbletearReporter{
		out:         out,
		stopPollers: make(map[string]func()),
	}
}

func (r *bubbletearReporter) OnStart(phase int, name string, comp devenvruntime.Component) {
	r.program.Send(componentStartedMsg{phase: phase, name: name})

	s, ok := comp.(devenvruntime.StatusGetter)
	if !ok {
		return
	}

	stop := make(chan struct{})
	key := compKey(phase, name)
	r.mu.Lock()
	r.stopPollers[key] = sync.OnceFunc(func() { close(stop) })
	r.mu.Unlock()

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				r.program.Send(statusUpdateMsg{phase: phase, name: name, status: s.Status()})
			}
		}
	}()
}

func (r *bubbletearReporter) OnFinish(phase int, name string, err error) {
	key := compKey(phase, name)
	r.mu.Lock()
	if stop, ok := r.stopPollers[key]; ok {
		stop()
		delete(r.stopPollers, key)
	}
	r.mu.Unlock()
	r.program.Send(componentFinishedMsg{phase: phase, name: name, err: err})
}

func (r *bubbletearReporter) OnStageStart(name string) {
	r.program.Send(stageStartedMsg{name: name})
}

func (r *bubbletearReporter) OnStageFinish(name string, err error) {
	r.program.Send(stageFinishedMsg{name: name, err: err})
}

func (r *bubbletearReporter) Run(fn func() error) error {
	prog := tea.NewProgram(newModel(r.out), tea.WithOutput(r.out))
	r.program = prog

	start := time.Now()
	go func() {
		err := fn()
		prog.Send(doneMsg{err: err})
	}()

	m, err := prog.Run()
	r.elapsed = time.Since(start)
	if err != nil {
		return err
	}
	if tm, ok := m.(tuiModel); ok {
		if tm.cancelled {
			os.Exit(130)
		}
		r.finalErr = tm.finalErr
	}
	return r.finalErr
}

func (r *bubbletearReporter) PrintSummary(outTomlPath, logFilePath string) {
	printSummary(r.out, outTomlPath, logFilePath, r.elapsed)
}
