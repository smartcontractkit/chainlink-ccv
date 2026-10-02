package admin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

func TestActionLogRoundTrip(t *testing.T) {
	db := testutil.NewTestDB(t)
	require.NoError(t, runAdminMigrations(db))

	log := NewActionLog(db)
	ctx := context.Background()
	require.NoError(t, log.Record(ctx, Action{
		Actor: "alice@example.com", Action: "reschedule", NodeName: "verifier-1",
		Target: "0xabc", Outcome: "success", Detail: "job restored to active queue",
	}))
	require.NoError(t, log.Record(ctx, Action{
		Actor: "alice@example.com", Action: "reschedule", NodeName: "verifier-2",
		Target: "0xabc", Outcome: "failed", Detail: "node unreachable",
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

// TestActionLogMigrationsCoexistWithVerifierMigrations proves the console can share a
// database with a verifier: testutil.NewTestDB has already run the verifier migrations,
// and the admin migrations still apply cleanly on their own goose table.
func TestActionLogMigrationsCoexistWithVerifierMigrations(t *testing.T) {
	db := testutil.NewTestDB(t)
	require.NoError(t, runAdminMigrations(db))
	// Idempotent on a second console start.
	require.NoError(t, runAdminMigrations(db))
}
