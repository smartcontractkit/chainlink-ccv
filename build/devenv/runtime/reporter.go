package devenvruntime

// Reporter receives lifecycle events from the runtime and CLI stages.
// Implementations handle rendering; the runtime and CLI stay display-unaware.
type Reporter interface {
	// Component lifecycle — called by the phased runtime for each component.
	OnStart(phase int, name string, component Component)
	OnFinish(phase int, name string, err error)

	// Stage lifecycle — called by the CLI for build / env / test stages.
	OnStageStart(name string)
	OnStageFinish(name string, err error)

	// Run hands control to the reporter so it can set up its display before
	// invoking fn. Simple reporters call fn() directly on the same goroutine.
	// The Bubbletea reporter starts the TUI on the main goroutine and runs fn
	// in a background goroutine, bridging events via program.Send() internally.
	Run(fn func() error) error

	// PrintSummary renders the post-run summary. outTomlPath may be empty if
	// the environment was never started (e.g. test against a running env).
	// logFilePath is the path to the verbose log file, or empty in verbose mode.
	PrintSummary(outTomlPath, logFilePath string)
}

// NoopReporter is a Reporter that does nothing. Used in verbose mode and
// in legacy/monolith mode where component-level events are unavailable.
type NoopReporter struct{}

func (NoopReporter) OnStart(int, string, Component)    {}
func (NoopReporter) OnFinish(int, string, error)       {}
func (NoopReporter) OnStageStart(string)               {}
func (NoopReporter) OnStageFinish(string, error)       {}
func (NoopReporter) Run(fn func() error) error         { return fn() }
func (NoopReporter) PrintSummary(string, string)       {}
