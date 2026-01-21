package verifier

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestPendingWritingTracker_AddRemove(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// Add a message
	tracker.Add(chain, "msg1", 100)

	// Checkpoint should be 99 (100 - 1)
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Adding same message again should be idempotent
	tracker.Add(chain, "msg1", 100)

	// Remove the message
	tracker.Remove(chain, "msg1")

	// No more pending messages, no checkpoint
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)
	require.Equal(t, uint64(0), checkpoint)
}

func TestPendingWritingTracker_MultipleMessages(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// Add messages at different finalized levels
	tracker.Add(chain, "msg1", 100)
	tracker.Add(chain, "msg2", 102)
	tracker.Add(chain, "msg3", 105)

	// Checkpoint should be 99 (min=100 - 1)
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Remove msg2 (102)
	tracker.Remove(chain, "msg2")

	// Checkpoint should still be 99 (min still=100)
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced) // Not advanced from last checkpoint

	// Remove msg1 (100)
	tracker.Remove(chain, "msg1")

	// Checkpoint should now be 104 (min=105 - 1)
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(104), checkpoint)
}

func TestPendingWritingTracker_CheckpointOnlyAdvances(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// Add message at level 100
	tracker.Add(chain, "msg1", 100)
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Try to get checkpoint again without changes
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced) // Not advanced

	// Add message at level 105
	tracker.Add(chain, "msg2", 105)

	// Checkpoint should still be 99 (min still=100)
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)

	// Remove msg1
	tracker.Remove(chain, "msg1")

	// Checkpoint advances to 104
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(104), checkpoint)
}

func TestPendingWritingTracker_IdempotentAdd(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// Add message multiple times
	tracker.Add(chain, "msg1", 100)
	tracker.Add(chain, "msg1", 100)
	tracker.Add(chain, "msg1", 100)

	// Should only be tracked once
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Single remove should clear it
	tracker.Remove(chain, "msg1")

	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)
}

func TestPendingWritingTracker_MultipleLevels(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// Add multiple messages at same level
	tracker.Add(chain, "msg1", 100)
	tracker.Add(chain, "msg2", 100)
	tracker.Add(chain, "msg3", 100)

	// Checkpoint should be 99
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Remove one message
	tracker.Remove(chain, "msg1")

	// Checkpoint should still be 99 (other messages at 100 still pending)
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)

	// Remove second message
	tracker.Remove(chain, "msg2")

	// Still 99
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)

	// Remove last message
	tracker.Remove(chain, "msg3")

	// Now no more pending
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)
}

func TestPendingWritingTracker_MultipleChains(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain1 := protocol.ChainSelector(1)
	chain2 := protocol.ChainSelector(2)

	// Add messages for different chains
	tracker.Add(chain1, "msg1", 100)
	tracker.Add(chain2, "msg2", 200)

	// Check chain1
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain1)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Check chain2
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain2)
	require.True(t, advanced)
	require.Equal(t, uint64(199), checkpoint)

	// Remove from chain1
	tracker.Remove(chain1, "msg1")

	// Chain1 should have no more pending
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain1)
	require.False(t, advanced)

	// Chain2 should be unaffected
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain2)
	require.False(t, advanced) // Already at 199, no new advancement
}

func TestPendingWritingTracker_RetryScenario(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// SRS reads and adds message
	tracker.Add(chain, "msg1", 100)

	// TVP receives, adds again (should be idempotent)
	tracker.Add(chain, "msg1", 100)

	// Checkpoint should be 99
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// TVP retries, adds again (still idempotent)
	tracker.Add(chain, "msg1", 100)

	// SWP finally succeeds and removes
	tracker.Remove(chain, "msg1")

	// No more pending
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)
}

func TestPendingWritingTracker_ReorgScenario(t *testing.T) {
	tracker := NewPendingWritingTracker()
	chain := protocol.ChainSelector(1)

	// Add messages
	tracker.Add(chain, "msg1", 100)
	tracker.Add(chain, "msg2", 100)
	tracker.Add(chain, "msg3", 102)

	// Checkpoint at 99
	checkpoint, advanced := tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(99), checkpoint)

	// Reorg detected - SRS removes msg1
	tracker.Remove(chain, "msg1")

	// Checkpoint still at 99 (msg2 still at 100)
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.False(t, advanced)

	// msg2 written successfully
	tracker.Remove(chain, "msg2")

	// Checkpoint advances to 101
	checkpoint, advanced = tracker.CheckpointIfAdvanced(chain)
	require.True(t, advanced)
	require.Equal(t, uint64(101), checkpoint)
}
