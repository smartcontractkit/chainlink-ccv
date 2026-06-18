package reporter

import (
	"io"
	"os"

	"github.com/charmbracelet/x/term"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
)

// New returns the appropriate Reporter for the current output context.
//
//   - verbose=true  → NoopReporter (caller keeps raw zerolog output)
//   - TTY detected  → BubbletearReporter (animated TUI)
//   - otherwise     → SimpleFancyReporter (line-based progress)
//
// out is the writer that the reporter should render to (typically the real
// terminal fd after stdout/stderr have been redirected to a log file).
func New(verbose bool, out io.Writer) devenvruntime.Reporter {
	if verbose {
		return devenvruntime.NoopReporter{}
	}
	if f, ok := out.(*os.File); ok && term.IsTerminal(f.Fd()) {
		return newBubbletearReporter(out)
	}
	return newSimpleReporter(out)
}
