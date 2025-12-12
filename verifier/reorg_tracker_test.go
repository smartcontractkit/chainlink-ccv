package verifier

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/stretchr/testify/require"
)

func TestReorgTracker_Track_AddsToSet(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 10)
	tracker.Track(dest, 15)

	require.True(t, tracker.RequiresFinalization(dest, 10))
	require.True(t, tracker.RequiresFinalization(dest, 15))
	require.False(t, tracker.RequiresFinalization(dest, 12))
}

func TestReorgTracker_Track_IndependentDestinations(t *testing.T) {
	tracker := NewReorgTracker()
	dest1 := protocol.ChainSelector(1337)
	dest2 := protocol.ChainSelector(2337)

	tracker.Track(dest1, 10)
	tracker.Track(dest2, 20)

	require.True(t, tracker.RequiresFinalization(dest1, 10))
	require.False(t, tracker.RequiresFinalization(dest1, 20))
	require.True(t, tracker.RequiresFinalization(dest2, 20))
	require.False(t, tracker.RequiresFinalization(dest2, 10))
}

func TestReorgTracker_RequiresFinalization_InSet(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 10)

	require.True(t, tracker.RequiresFinalization(dest, 10))
}

func TestReorgTracker_RequiresFinalization_NotInSet(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	require.False(t, tracker.RequiresFinalization(dest, 10))
}

func TestReorgTracker_RequiresFinalization_UnknownDestination(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)
	unknownDest := protocol.ChainSelector(9999)

	tracker.Track(dest, 10)

	require.False(t, tracker.RequiresFinalization(unknownDest, 10))
}

func TestReorgTracker_Remove_RemovesFromSet(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 10)
	tracker.Track(dest, 15)
	require.True(t, tracker.RequiresFinalization(dest, 10))

	tracker.Remove(dest, 10)

	require.False(t, tracker.RequiresFinalization(dest, 10))
	require.True(t, tracker.RequiresFinalization(dest, 15))
}

func TestReorgTracker_Remove_CleansUpEmptyDestination(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 10)
	require.True(t, len(tracker.reorgedSeqNums) > 0)

	tracker.Remove(dest, 10)

	require.False(t, len(tracker.reorgedSeqNums) > 0)
}

func TestReorgTracker_Remove_NoOpForUnknownSeqNum(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 10)

	tracker.Remove(dest, 999)

	require.True(t, tracker.RequiresFinalization(dest, 10))
}

func TestReorgTracker_Remove_NoOpForUnknownDestination(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)
	unknownDest := protocol.ChainSelector(9999)

	tracker.Track(dest, 10)

	tracker.Remove(unknownDest, 10)

	require.True(t, tracker.RequiresFinalization(dest, 10))
}

func TestReorgTracker_MultipleReorgsToSameDest(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 1)
	tracker.Track(dest, 5)
	tracker.Track(dest, 800)
	tracker.Track(dest, 999)

	require.True(t, tracker.RequiresFinalization(dest, 1))
	require.True(t, tracker.RequiresFinalization(dest, 5))
	require.True(t, tracker.RequiresFinalization(dest, 800))
	require.True(t, tracker.RequiresFinalization(dest, 999))

	require.False(t, tracker.RequiresFinalization(dest, 2))
	require.False(t, tracker.RequiresFinalization(dest, 100))
	require.False(t, tracker.RequiresFinalization(dest, 700))
}

func TestReorgTracker_DuplicateTrackIsIdempotent(t *testing.T) {
	tracker := NewReorgTracker()
	dest := protocol.ChainSelector(1337)

	tracker.Track(dest, 10)
	tracker.Track(dest, 10)
	tracker.Track(dest, 10)

	require.True(t, tracker.RequiresFinalization(dest, 10))

	tracker.Remove(dest, 10)

	require.False(t, tracker.RequiresFinalization(dest, 10))
}
