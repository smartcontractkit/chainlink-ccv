package e2e

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
)

func recoveryCLIEnvironment(t *testing.T) (*verifiercli.Client, *sql.DB, string, string, uint64) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires a running devenv")
	}
	in, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)
	require.NotEmpty(t, in.Verifier)
	require.NotNil(t, in.Verifier[0].Out)
	out := in.Verifier[0].Out
	db, err := sql.Open("postgres", out.DBConnectionString)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var chain string
	var head uint64
	require.Eventually(t, func() bool {
		return db.QueryRowContext(t.Context(), `SELECT chain_selector::text, latest_block::text FROM ccv_recovery_readers
			WHERE owner_id=$1 AND NOT disabled AND head_observed_at > NOW()-INTERVAL '1 minute'
			ORDER BY latest_block DESC LIMIT 1`, out.VerifierID).Scan(&chain, &head) == nil
	}, time.Minute, time.Second, "running readers must register their recovery capability")
	return verifiercli.NewClient(out.ContainerName), db, out.VerifierID, chain, head
}

func TestE2ESmoke_RecoveryCLI(t *testing.T) {
	vc, _, owner, chain, head := recoveryCLIEnvironment(t)
	ctx := t.Context()
	identity, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	from, to := head+1000000, head+1000001
	key := uuid.NewString()
	o, err := vc.Recovery().Submit(ctx, "replay", owner, chain, from, &to, key)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = vc.Recovery().Action(context.Background(), "cancel", o.ID) })
	repeated, err := vc.Recovery().Submit(ctx, "replay", owner, chain, from, &to, key)
	require.NoError(t, err)
	require.Equal(t, o.ID, repeated.ID)
	require.Eventually(t, func() bool {
		current, err := vc.Recovery().Action(ctx, "status", o.ID)
		return err == nil && current.State == "running" && strings.Contains(current.LastError, "waiting for source head")
	}, time.Minute, time.Second)
	cancelled, err := vc.Recovery().Action(ctx, "cancel", o.ID)
	require.NoError(t, err)
	require.Equal(t, "cancelled", cancelled.State)
	require.Equal(t, from, cancelled.NextBlock)
	resumed, err := vc.Recovery().Action(ctx, "resume", o.ID)
	require.NoError(t, err)
	require.Equal(t, from, resumed.NextBlock)
	repeated, err = vc.Recovery().Action(ctx, "resume", o.ID)
	require.NoError(t, err, "repeated resume is idempotent")
	require.Equal(t, to, repeated.ToBlock)
	after, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, identity, after, "submit/cancel/resume must leave the service running")
}

// The restart here injects a process failure after a committed chunk. It is a
// separate durability scenario, not part of the live recovery workflow.
func TestE2ESmoke_RecoverySurvivesProcessFailure(t *testing.T) {
	vc, _, owner, chain, head := recoveryCLIEnvironment(t)
	ctx := t.Context()
	to := head + 1000000
	o, err := vc.Recovery().Submit(ctx, "replay", owner, chain, 0, &to, "")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = vc.Recovery().Action(context.Background(), "cancel", o.ID) })
	var progress uint64
	var updatedAt time.Time
	require.Eventually(t, func() bool {
		current, err := vc.Recovery().Action(ctx, "status", o.ID)
		if err != nil {
			return false
		}
		progress = current.NextBlock
		updatedAt = current.UpdatedAt
		return current.State == "running" && progress > 0
	}, 90*time.Second, time.Second, "at least one chunk must commit before failure injection")
	identity, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	require.NoError(t, vc.CrashAndWaitReady(ctx))
	after, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	require.NotEqual(t, identity, after, "failure injection must replace the service process")
	require.Eventually(t, func() bool {
		current, err := vc.Recovery().Action(ctx, "status", o.ID)
		return err == nil && current.State == "running" && current.NextBlock >= progress &&
			current.ToBlock == to && current.UpdatedAt.After(updatedAt)
	}, 90*time.Second, time.Second, "the same durable operation must survive a process failure")
}
