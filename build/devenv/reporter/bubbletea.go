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

type stageStartedMsg struct{ name string }
type stageFinishedMsg struct {
	name string
	err  error
}
type doneMsg struct{ err error }

// ── styles ───────────────────────────────────────────────────────────────────

var (
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))   // green
	styleFail   = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))   // red
	styleStage  = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))   // blue
	styleSep    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))   // dark gray
	styleFooter = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))  // yellow
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))   // dark gray
)

var spinnerFrames = []string{"|", "/", "-", "\\"}

// ── model ────────────────────────────────────────────────────────────────────

type activeComp struct {
	phase  int
	name   string
	start  time.Time
	status string
}

type tuiModel struct {
	log         []string // completed / stage lines
	active      map[string]*activeComp
	activeOrder []string // insertion-ordered keys for stable display
	frame       int
	done        bool
	cancelled   bool
	finalErr    error
	width       int
}

func newModel() tuiModel {
	return tuiModel{
		active: make(map[string]*activeComp),
		width:  80,
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
		m.log = append(m.log, styleStage.Render("── "+msg.name))

	case stageFinishedMsg:
		if msg.err != nil {
			m.log = append(m.log, styleFail.Render(fmt.Sprintf("✗ %s failed: %v", msg.name, msg.err)))
		}

	case componentStartedMsg:
		key := compKey(msg.phase, msg.name)
		m.active[key] = &activeComp{phase: msg.phase, name: msg.name, start: time.Now()}
		m.activeOrder = append(m.activeOrder, key)

	case componentFinishedMsg:
		key := compKey(msg.phase, msg.name)
		cs, ok := m.active[key]
		start := time.Now()
		if ok {
			start = cs.start
		}
		dur := time.Since(start).Round(time.Millisecond)
		delete(m.active, key)
		// Remove from ordered list.
		for i, k := range m.activeOrder {
			if k == key {
				m.activeOrder = append(m.activeOrder[:i], m.activeOrder[i+1:]...)
				break
			}
		}
		if msg.err != nil {
			m.log = append(m.log, styleFail.Render(
				fmt.Sprintf("✗ [%d] %-28s %6s  error: %v", msg.phase, msg.name, dur, msg.err)))
		} else {
			m.log = append(m.log, styleOK.Render(
				fmt.Sprintf("✓ [%d] %-28s %6s", msg.phase, msg.name, dur)))
		}
		if m.done && len(m.active) == 0 {
			return m, tea.Quit
		}

	case statusUpdateMsg:
		key := compKey(msg.phase, msg.name)
		if cs, ok := m.active[key]; ok {
			cs.status = msg.status
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
	sb.WriteString(styleSep.Render(sep))
	sb.WriteString("\n")

	spin := spinnerFrames[m.frame%len(spinnerFrames)]
	for _, key := range m.activeOrder {
		cs, ok := m.active[key]
		if !ok {
			continue
		}
		elapsed := time.Since(cs.start).Round(time.Second)
		line := fmt.Sprintf("%s %-28s %4s", spin, cs.name, elapsed)
		if cs.status != "" {
			line += styleFooter.Render(" | "+cs.status)
		}
		sb.WriteString(styleDim.Render(line))
		sb.WriteString("\n")
	}

	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── reporter ─────────────────────────────────────────────────────────────────

type bubbletearReporter struct {
	mu          sync.Mutex
	program     *tea.Program
	finalErr    error
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

	s, ok := comp.(devenvruntime.Statuser)
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
	prog := tea.NewProgram(newModel(), tea.WithOutput(r.out))
	r.program = prog

	go func() {
		err := fn()
		prog.Send(doneMsg{err: err})
	}()

	m, err := prog.Run()
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

func (r *bubbletearReporter) PrintSummary(outTomlPath string) {
	printSummary(r.out, outTomlPath)
}
