package common

import (
	mrand "math/rand/v2"
	"time"
)

// WithJitter spreads a scheduling delay across [delay/2, delay*3/2].
//
// An outage stalls everything being retried at once, and applying the same fixed delay to all
// of it would reschedule the whole backlog onto a single tick — the worst shaping to hand an
// endpoint that is already failing or rate-limiting. Jitter spreads those retries: it does not
// reduce total call volume, only its burstiness, and should be paired with backoff that grows
// with the attempt count.
//
// A delay of zero or sub-half-nanosecond values is returned unchanged.
func WithJitter(delay time.Duration) time.Duration {
	half := int64(delay / 2)
	if half <= 0 {
		return delay
	}
	//nolint:gosec // G404: jitter spreads retry load, it is not a security decision.
	return delay - time.Duration(half) + time.Duration(mrand.Int64N(2*half+1))
}
