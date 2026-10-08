package admin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestActionLogRoundTrip(t *testing.T) {
	log := NewActionLog()

	log.Record(Action{Actor: "alice@example.com", Action: "reschedule", Target: "0xabc", Outcome: "success", Detail: "job restored"})
	log.Record(Action{Actor: "bob@example.com", Action: "recovery-submit", Target: "owner=o chain=1", OperationID: "11111111-1111-1111-1111-111111111111", Outcome: "success", Detail: "accepted"})
	log.Record(Action{Actor: "alice@example.com", Action: "reschedule", Target: "0xdef", Outcome: "skipped", Detail: "already attested"})

	actions := log.List(100, 0)
	require.Len(t, actions, 3)
	// Newest first, with session-stable IDs and timestamps.
	for i := 1; i < len(actions); i++ {
		require.Less(t, actions[i].ID, actions[i-1].ID)
		require.False(t, actions[i].CreatedAt.IsZero())
	}
	require.Equal(t, "skipped", actions[0].Outcome)
	require.Equal(t, "success", actions[1].Outcome)
	require.Equal(t, "alice@example.com", actions[2].Actor)

	// Pagination: beforeID excludes the boundary row itself.
	older := log.List(100, actions[0].ID)
	require.Len(t, older, 2)
	require.Equal(t, "success", older[0].Outcome)

	// The log is session-scoped: a fresh instance starts empty.
	require.Empty(t, NewActionLog().List(100, 0))
}
