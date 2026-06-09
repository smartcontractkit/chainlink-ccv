// Package timing provides wall-clock trackers used to profile devenv startup.
// It is isolated from the root ccv package so that components can import it
// without pulling in the full devenv dependency graph.
package timing

import (
	"time"

	"github.com/rs/zerolog"
)

// TimeTracker records named wall-clock intervals and prints a summary.
type TimeTracker struct {
	logger    zerolog.Logger
	start     time.Time
	last      time.Time
	intervals []interval
}

type interval struct {
	tag   string
	delta time.Duration
}

// New creates a new TimeTracker anchored to the current wall-clock time.
func New(l zerolog.Logger) *TimeTracker { //nolint:gocritic
	now := time.Now()
	return &TimeTracker{
		start:     now,
		last:      now,
		logger:    l,
		intervals: nil,
	}
}

func (t *TimeTracker) Record(tag string) {
	now := time.Now()
	delta := now.Sub(t.last)
	t.intervals = append(t.intervals, interval{
		tag:   tag,
		delta: delta,
	})
	t.last = now
}

func (t *TimeTracker) Print() {
	total := time.Since(t.start)
	t.logger.Debug().Msg("Time tracking results:")
	for _, i := range t.intervals {
		t.logger.Debug().
			Str("tag", i.tag).
			Str("duration", i.delta.String()).
			Send()
	}

	t.logger.Debug().
		Str("duration", total.String()).
		Msg("Total environment boot up time")
}

func (t *TimeTracker) SinceStart() time.Duration {
	return time.Since(t.start)
}

// ComponentTiming records the wall-clock span of a single component's phase run.
type ComponentTiming struct {
	Phase int
	Key   string
	Start time.Time
	End   time.Time
}

// ComponentTimeTracker collects per-component timing entries for the phased runtime.
//
// TODO: consider merging ComponentTimeTracker with TimeTracker.
type ComponentTimeTracker struct {
	entries []ComponentTiming
}

// NewComponentTimeTracker creates an empty ComponentTimeTracker.
func NewComponentTimeTracker() *ComponentTimeTracker {
	return &ComponentTimeTracker{}
}

// Record appends a timing entry for the given phase and component key.
func (t *ComponentTimeTracker) Record(phase int, key string, start, end time.Time) {
	t.entries = append(t.entries, ComponentTiming{
		Phase: phase,
		Key:   key,
		Start: start,
		End:   end,
	})
}

// Print logs one Info line per recorded component showing phase, key, and duration.
func (t *ComponentTimeTracker) Print(logger zerolog.Logger) {
	for _, e := range t.entries {
		logger.Info().
			Int("phase", e.Phase).
			Str("component", e.Key).
			Str("duration", e.End.Sub(e.Start).String()).
			Msg("component timing")
	}
}
