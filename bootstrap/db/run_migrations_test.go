package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A caller whose context expires while another migration holds the gate must
// return promptly instead of blocking on the gate past its deadline.
func TestRunMigrationsContext_GateHonorsContext(t *testing.T) {
	migrationGate <- struct{}{}
	defer func() { <-migrationGate }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := RunMigrationsContext(ctx, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
