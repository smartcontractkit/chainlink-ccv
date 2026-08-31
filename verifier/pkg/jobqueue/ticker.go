package jobqueue

import (
	"math/rand/v2"
	"time"
)

// DefaultTickerJitter is the fraction by which JitteredTicker varies its period.
const DefaultTickerJitter = 0.1

// JitteredTicker fires at interval, varied by +/- a jitter fraction on every period.
//
// A fleet restarts in a rolling deploy, and many verifier processes share one database.
// Identical fixed periods let those processes phase-align into a single synchronized
// burst of queries. Jitter spreads them out.
//
// Reset must be called after each fire, so it is used from a select loop that already
// handles every arm explicitly.
type JitteredTicker struct {
	timer    *time.Timer
	interval time.Duration
	jitter   float64
}

// NewJitteredTicker starts a ticker. A jitter fraction outside (0, 1) is replaced by
// DefaultTickerJitter.
func NewJitteredTicker(interval time.Duration, jitter float64) *JitteredTicker {
	if jitter <= 0 || jitter >= 1 {
		jitter = DefaultTickerJitter
	}
	t := &JitteredTicker{interval: interval, jitter: jitter}
	t.timer = time.NewTimer(t.next())
	return t
}

// C returns the channel that reports each fire.
func (t *JitteredTicker) C() <-chan time.Time { return t.timer.C }

// Reset schedules the next fire. Call it once per receive from C.
func (t *JitteredTicker) Reset() { t.timer.Reset(t.next()) }

// Stop releases the underlying timer.
func (t *JitteredTicker) Stop() { t.timer.Stop() }

// next returns the interval scaled by a random factor in [1-jitter, 1+jitter].
func (t *JitteredTicker) next() time.Duration {
	factor := 1 + t.jitter*(2*rand.Float64()-1) //nolint:gosec // jitter, not security
	d := time.Duration(float64(t.interval) * factor)
	if d <= 0 {
		d = t.interval
	}
	return d
}
