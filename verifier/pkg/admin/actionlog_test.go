package admin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// TestActionLogRoundTrip proves the verifier migrations create the console's action
// table (testutil.NewTestDB has already run them) and that Record/List round-trip.
func TestActionLogRoundTrip(t *testing.T) {
	db := testutil.NewTestDB(t)

	log := NewActionLog(db)
	ctx := context.Background()
	require.NoError(t, log.Record(ctx, Action{
		Actor: "alice@example.com", Action: "reschedule",
		Target: "0xabc", Outcome: "success", Detail: "job restored to active queue",
	}))
	require.NoError(t, log.Record(ctx, Action{
		Actor: "alice@example.com", Action: "reschedule",
		Target: "0xdef", Outcome: "failed", Detail: "active job may already exist",
	}))

	actions, err := log.List(ctx, 100, 0)
	require.NoError(t, err)
	require.Len(t, actions, 2)
	require.Equal(t, "failed", actions[0].Outcome, "newest first")
	require.Equal(t, "success", actions[1].Outcome)

	// Pagination: beforeID excludes the boundary row itself.
	older, err := log.List(ctx, 100, actions[0].ID)
	require.NoError(t, err)
	require.Len(t, older, 1)
}
