package storageaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAckCache_BoundedEviction(t *testing.T) {
	c, err := newAckCache(3)
	require.NoError(t, err)
	c.add("a", "m1")
	c.add("a", "m2")
	c.add("a", "m3")

	// At capacity; the next add evicts the least-recently-acked entry (m1).
	c.add("a", "m4")

	require.False(t, c.has("a", "m1"), "oldest ack evicted")
	require.True(t, c.has("a", "m2"))
	require.True(t, c.has("a", "m3"))
	require.True(t, c.has("a", "m4"))
	require.Equal(t, 3, c.len(), "cache never exceeds its capacity")
}

func TestAckCache_RecencyOnReAck(t *testing.T) {
	c, err := newAckCache(3)
	require.NoError(t, err)
	c.add("a", "m1")
	c.add("a", "m2")
	c.add("a", "m3")
	// Re-acking m1 refreshes its recency, so it is no longer the eviction candidate.
	c.add("a", "m1")
	c.add("a", "m4")

	require.True(t, c.has("a", "m1"), "re-acked entry kept")
	require.False(t, c.has("a", "m2"), "now-least-recent entry evicted instead")
	require.Equal(t, 3, c.len())
}

func TestAckCache_KeysArePerAggregator(t *testing.T) {
	// Same message acked by different aggregators counts as distinct entries.
	c, err := newAckCache(2)
	require.NoError(t, err)
	c.add("a", "m1")
	c.add("b", "m1")
	c.add("c", "m1") // evicts the oldest of the two existing entries

	require.False(t, c.has("a", "m1"))
	require.True(t, c.has("b", "m1"))
	require.True(t, c.has("c", "m1"))
	require.Equal(t, 2, c.len())
}

func TestAckCache_Remove(t *testing.T) {
	c, err := newAckCache(2)
	require.NoError(t, err)
	c.add("a", "m1")
	require.True(t, c.has("a", "m1"))

	c.remove("a", "m1")
	require.False(t, c.has("a", "m1"))
	require.Equal(t, 0, c.len())

	// Removing an absent key is a no-op.
	c.remove("a", "nope")
	require.Equal(t, 0, c.len())
}

func TestAckCache_NilSafety(t *testing.T) {
	var c *ackCache
	require.False(t, c.has("a", "m1"))
	assert.NotPanics(t, func() { c.add("a", "m1") })
	assert.NotPanics(t, func() { c.remove("a", "m1") })
}

func TestAckCache_NegativeCapacityFallsBackToDefault(t *testing.T) {
	c, err := newAckCache(-1)
	require.NoError(t, err)
	require.NotPanics(t, func() { c.add("a", "m1") })
	require.True(t, c.has("a", "m1"))
}
