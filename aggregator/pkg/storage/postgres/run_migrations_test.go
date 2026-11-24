package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
)

// A caller whose context expires while another migration holds the gate must
// return promptly instead of blocking on the gate past its deadline.
func TestRunMigrationsContext_GateHonorsContext(t *testing.T) {
	migrationGate <- struct{}{}
	defer func() { <-migrationGate }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := RunMigrationsContext(ctx, nil, "postgres")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// Replicas that start at the same time must all migrate successfully.
func TestRunMigrationsContext_ConcurrentProcesses(t *testing.T) {
	uri, cleanup := testutil.SetupTestPostgresURI(t)
	defer cleanup()

	const replicas = 3
	errs := make(chan error, replicas)
	for range replicas {
		db, err := sqlx.Open("postgres", uri)
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		go func() {
			// Use the internal runner per goroutine: the in-process gate would hide the race.
			errs <- runLockedMigrations(t.Context(), db)
		}()
	}
	for range replicas {
		require.NoError(t, <-errs)
	}
}
