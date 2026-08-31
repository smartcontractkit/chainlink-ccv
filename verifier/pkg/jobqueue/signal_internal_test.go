package jobqueue

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// drained reports whether the signal currently holds a token, and removes it if so.
func drained(s *workSignal) bool {
	select {
	case <-s.C():
		return true
	default:
		return false
	}
}

func Test_WorkSignal(t *testing.T) {
	t.Parallel()

	t.Run("notify makes one token available", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		require.False(t, drained(s), "a fresh signal must not report work")

		s.notify()
		require.True(t, drained(s), "notify must make a token available")
		require.False(t, drained(s), "a token must be consumed only once")
	})

	t.Run("notify coalesces a burst into a single token", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		// A publisher that sends one job at a time must not turn into one wakeup per job.
		// Without coalescing a busy producer would issue more queries than the fixed poll
		// it replaced.
		for range 1000 {
			s.notify()
		}

		require.True(t, drained(s), "the burst must leave one token")
		require.False(t, drained(s), "the burst must leave no more than one token")
	})

	t.Run("notify never blocks, even with no consumer", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		done := make(chan struct{})
		go func() {
			defer close(done)
			var wg sync.WaitGroup
			// Many producers, no consumer at all: the source readers publish from one
			// goroutine per chain, so a blocking notify would stall chain polling.
			for range 50 {
				wg.Go(func() {
					for range 100 {
						s.notify()
					}
				})
			}
			wg.Wait()
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("notify blocked a producer")
		}
	})

	t.Run("notifyAfter with no delay signals immediately", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		s.notifyAfter(0)
		require.True(t, drained(s))

		s.notifyAfter(-time.Second)
		require.True(t, drained(s))
	})

	t.Run("notifyAfter waits for the delay", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		// A retried job is not due until available_at, so waking now would only make the
		// consumer run a query that matches nothing.
		s.notifyAfter(300 * time.Millisecond)
		require.False(t, drained(s), "the signal must not fire before the delay")

		select {
		case <-s.C():
		case <-time.After(3 * time.Second):
			t.Fatal("the signal never fired after the delay")
		}
	})

	t.Run("notifyAfter beyond the fallback interval schedules nothing", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		// Past this point the fallback poll reaches the row at least as soon, so a timer
		// would only hold a reference for no benefit.
		s.notifyAfter(s.maxDelay + time.Second)

		time.Sleep(200 * time.Millisecond)
		require.False(t, drained(s))
	})

	t.Run("a late signal after shutdown is harmless", func(t *testing.T) {
		t.Parallel()
		s := newWorkSignal()

		// notifyAfter can fire once the consumer has stopped reading. The channel is never
		// closed precisely so that this stays a no-op instead of a panic.
		s.notifyAfter(50 * time.Millisecond)
		time.Sleep(200 * time.Millisecond)

		require.NotPanics(t, func() {
			s.notify()
			s.notifyAfter(10 * time.Millisecond)
			time.Sleep(100 * time.Millisecond)
		})
	})
}

func Test_JitteredTicker(t *testing.T) {
	t.Parallel()

	t.Run("fires repeatedly within the jitter bounds", func(t *testing.T) {
		t.Parallel()

		const (
			interval = 100 * time.Millisecond
			jitter   = 0.1
		)
		ticker := NewJitteredTicker(interval, jitter)
		defer ticker.Stop()

		for i := range 5 {
			start := time.Now()
			select {
			case <-ticker.C():
				ticker.Reset()
			case <-time.After(5 * time.Second):
				t.Fatalf("ticker stopped firing at iteration %d", i)
			}
			elapsed := time.Since(start)

			// Lower bound is exact; the upper bound is loose because a contended machine
			// delays delivery but never speeds it up.
			require.GreaterOrEqual(t, elapsed, time.Duration(float64(interval)*(1-jitter))-2*time.Millisecond,
				"fired earlier than the jitter allows")
			require.Less(t, elapsed, 2*time.Second, "fired far later than the interval")
		}
	})

	t.Run("periods vary so restarted processes do not align", func(t *testing.T) {
		t.Parallel()

		ticker := NewJitteredTicker(time.Hour, 0.5)
		defer ticker.Stop()

		seen := make(map[time.Duration]struct{})
		for range 50 {
			seen[ticker.next()] = struct{}{}
		}
		require.Greater(t, len(seen), 1, "every period was identical, so jitter is not applied")
	})

	t.Run("an out-of-range jitter falls back to the default", func(t *testing.T) {
		t.Parallel()

		for _, jitter := range []float64{0, -1, 1, 5} {
			ticker := NewJitteredTicker(time.Hour, jitter)
			require.InDelta(t, DefaultTickerJitter, ticker.jitter, 1e-9)
			ticker.Stop()
		}
	})
}
