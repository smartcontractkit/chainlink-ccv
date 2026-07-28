// Package progress renders the devenv startup as a live checklist on a TTY,
// while capturing the usual log firehose to a file. It is deliberately
// self-contained and gated on the presence of a terminal: off a TTY every hook
// resolves to a no-op and logs flow exactly as before.
//
// The reporter is carried in the context.Context, so any
// code reachable from a bringup can emit progress via
// ReporterOrNoOp(ctx) without threading a new parameter through every layer.
package progress

import "context"

type ctxKey struct{}

// scopeKey carries the current parent step, so Stage nests new rows under it.
type scopeKey struct{}

// Step is a single checklist row. All methods must be safe for concurrent use.
type Step interface {
	// SetTotal declares a countable sub-total (e.g. number of chains), turning
	// the row's suffix into an "n/total" counter.
	SetTotal(n int)
	// Inc advances the countable sub-progress by one.
	Inc()
	// Msg sets a transient detail shown while the step is running.
	Msg(format string, args ...any)
	// Finish marks the step failed when err is non-nil, complete otherwise.
	// Pair with defer so a step is finalized from a function's named return
	// value, keeping the outcome correct as error paths are added:
	//
	//	step := progress.Stage(ctx, label)
	//	defer func() { step.Finish(err) }()
	Finish(err error)
}

// Reporter creates checklist rows. All methods must be safe for concurrent use.
type Reporter interface {
	Stage(label string) Step
}

// WithReporter returns a context carrying r.
func WithReporter(ctx context.Context, r Reporter) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// ReporterOrNoOp returns the reporter carried in ctx, or a no-op reporter when
// none is present.
func ReporterOrNoOp(ctx context.Context) Reporter {
	if r, ok := ctx.Value(ctxKey{}).(Reporter); ok && r != nil {
		return r
	}
	return noopReporter{}
}

// Stage adds a checklist row and returns it. When ctx carries a parent scope
// (set via Scope), the row nests as an indented child of that parent; otherwise
// it is a top-level row. The deep code calling Stage need not know its depth —
// nesting is decided entirely by whichever scope the caller threaded into ctx.
func Stage(ctx context.Context, label string) Step {
	if p, ok := ctx.Value(scopeKey{}).(*mpbStep); ok && p != nil {
		return p.child(label)
	}
	return ReporterOrNoOp(ctx).Stage(label)
}

// Scope returns a context whose subsequent Stage calls nest under parent. Pass
// it to a function whose internal Stage calls should render as children:
//
//	step := progress.Stage(ctx, "Launch verifiers (early)")
//	launchStandaloneVerifiers(progress.Scope(ctx, step), ...)
//
// Off a TTY (parent is a no-op) this is inert and Stage stays a no-op.
func Scope(ctx context.Context, parent Step) context.Context {
	return context.WithValue(ctx, scopeKey{}, parent)
}

type noopReporter struct{}

func (noopReporter) Stage(string) Step { return noopStep{} }

type noopStep struct{}

func (noopStep) SetTotal(int)       {}
func (noopStep) Inc()               {}
func (noopStep) Msg(string, ...any) {}
func (noopStep) Finish(error)       {}
