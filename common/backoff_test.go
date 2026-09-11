package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackoffDelay(t *testing.T) {
	const (
		base = 2 * time.Second
		max  = 1 * time.Minute
	)

	tests := []struct {
		name    string
		attempt int
		factor  int
		max     time.Duration
		want    time.Duration
	}{
		{"first attempt returns base", 1, 2, max, base},
		{"second attempt doubles", 2, 2, max, 4 * time.Second},
		{"third attempt quadruples", 3, 2, max, 8 * time.Second},
		{"converges on max", 4, 2, max, 16 * time.Second},
		{"caps at max (attempt 6)", 6, 2, max, 60 * time.Second},
		{"never exceeds max", 20, 2, max, 60 * time.Second},
		{"large attempt stays bounded", 1000, 2, max, 60 * time.Second},
		{"factor 1 does not grow", 5, 1, max, base},
		{"factor 0 does not grow", 5, 0, max, base},
		{"negative factor does not grow", 5, -2, max, base},
		{"non-positive attempt returns base", 0, 2, max, base},
		{"negative attempt returns base", -3, 2, max, base},
		{"base above cap clamps to cap", 1, 2, 1 * time.Second, 1 * time.Second},
		{"zero max disables growth", 5, 2, 0, base},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, BackoffDelay(tt.attempt, base, tt.factor, tt.max))
		})
	}
}

func TestBackoffDelayDoesNotGrowUnbounded(t *testing.T) {
	prev := time.Duration(0)
	for attempt := 1; attempt < 100; attempt++ {
		got := BackoffDelay(attempt, 2*time.Second, 2, time.Minute)
		require.True(t, got >= prev, "backoff must never decrease: attempt %d", attempt)
		require.LessOrEqual(t, got, time.Minute, "backoff must never exceed cap: attempt %d", attempt)
		prev = got
	}
	// The tail of a large attempt must sit at the cap, not drift or overflow.
	require.Equal(t, time.Minute, BackoffDelay(10_000, 2*time.Second, 2, time.Minute))
}
