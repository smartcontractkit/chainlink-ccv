package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithJitterStaysWithinBounds(t *testing.T) {
	expected := 1 * time.Second
	seen := make(map[time.Duration]struct{})
	for range 500 {
		got := WithJitter(expected)
		require.GreaterOrEqual(t, got, 500*time.Millisecond)
		require.LessOrEqual(t, got, 1500*time.Millisecond)
		seen[got] = struct{}{}
	}
	assert.Greater(t, len(seen), 1, "a fixed delay would synchronize every held message onto one tick")
}

func TestWithJitterDegenerateValues(t *testing.T) {
	assert.Equal(t, time.Duration(0), WithJitter(0))
	assert.Equal(t, time.Duration(1), WithJitter(1), "sub-half-nanosecond delays are returned unchanged")
	assert.Equal(t, -time.Second, WithJitter(-time.Second), "negative delays pass through")
}
