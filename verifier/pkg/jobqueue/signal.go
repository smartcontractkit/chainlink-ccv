package jobqueue

import "time"

// DefaultPendingFallbackInterval is how often a consumer polls for pending work while
// it waits for a signal. It is the liveness net for rows that become available without
// an in-process signal:
//   - a republish that ON CONFLICT DO NOTHING drops after a restart, which inserts
//     nothing and therefore has nothing to signal about,
//   - rows that the out-of-process job queue CLI moves back to 'pending'.
const DefaultPendingFallbackInterval = 30 * time.Second

// workSignal is a lossy, coalescing wakeup channel.
//
// The channel has capacity 1 and the send is non-blocking, so a burst of N notify calls
// collapses to at most one pending token and a producer never waits for a consumer. The
// buffer is what removes the lost-wakeup window: a token that arrives while the consumer
// is busy stays in the buffer, and the consumer takes it on its next pass. A broadcast
// through a closed channel would be missed instead.
//
// The channel is created once and is NEVER closed. notifyAfter can fire after the
// consumer stops. A send into a buffered channel that nobody reads is a no-op, but a
// send on a closed channel panics.
type workSignal struct {
	ch chan struct{}
	// maxDelay bounds the delay that notifyAfter is willing to schedule a timer for.
	// Past this point the fallback poll is at least as timely, so a timer adds nothing.
	maxDelay time.Duration
}

func newWorkSignal() *workSignal {
	return &workSignal{
		ch:       make(chan struct{}, 1),
		maxDelay: DefaultPendingFallbackInterval,
	}
}

// C returns the channel a consumer waits on.
func (s *workSignal) C() <-chan struct{} { return s.ch }

// notify wakes the consumer. It never blocks and it never fails.
func (s *workSignal) notify() {
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

// notifyAfter wakes the consumer once the given delay has passed.
//
// Work that becomes available in the future must not wake the consumer now: the consumer
// would query for rows with available_at <= now, find none, and spend a statement for
// nothing. The row would then wait for the fallback poll anyway.
func (s *workSignal) notifyAfter(d time.Duration) {
	if d <= 0 {
		s.notify()
		return
	}
	if d > s.maxDelay {
		return
	}
	// The closure captures only s, so a pending timer holds nothing but a channel.
	time.AfterFunc(d, s.notify)
}
