package storagewriter

import "time"

const (
	// DefaultBackoffFactor is the multiplier applied to the base storage-write retry
	// delay on each successive failed attempt. A factor of 2 doubles the wait each time.
	DefaultBackoffFactor = 2

	// DefaultBackoffMax caps the truncated exponential backoff so consecutive retries
	// never space out unbounded. Without a cap, a down aggregator would hold a message's
	// finality open for as long as its retry window allows while retries grow exponentially.
	DefaultBackoffMax = 1 * time.Minute
)

// backoffDelay returns a truncated exponential backoff delay for the given attempt.
//
// attempt is the 1-based number of the attempt that just failed, matching the job
// queue's attempt_count column (incremented once per consume). An attempt of 1 returns
// base; each subsequent attempt multiplies the delay by factor, capped at maxDelay.
//
// The result is clamped to maxDelay, so retries converge on a steady cadence instead of
// growing without bound. A non-positive attempt, an attempt of 1, or a factor below 2
// all reduce to base. Duration math is overflow-safe: the multiplication only happens
// while delay is below maxDelay.
func backoffDelay(attempt int, base time.Duration, factor int, maxDelay time.Duration) time.Duration {
	if maxDelay > 0 && base > maxDelay {
		base = maxDelay
	}
	if attempt <= 1 || factor < 2 || maxDelay <= 0 {
		return base
	}

	delay := base
	for i := 1; i < attempt; i++ {
		// next would exceed the cap (or the int64 range); bail early rather than
		// risking overflow of the duration.
		if delay > maxDelay/time.Duration(factor) {
			return maxDelay
		}
		delay *= time.Duration(factor)
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}
