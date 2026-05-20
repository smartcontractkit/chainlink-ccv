// Package timing provides a simple wall-clock interval tracker used to
// profile devenv startup phases. It is isolated from the root ccv package
// so that components can import it without pulling in the full devenv
// dependency graph.
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
