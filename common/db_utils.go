package common

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	maxRetries    = 10
	timeout       = 1 * time.Second
	retryInterval = 3 * time.Second
)

// Pingable is implemented by servers that support pings.
type Pingable interface {
	// PingContext pings the server and returns an error if the ping is unsuccessful.
	PingContext(ctx context.Context) error
}

// EnsureDBConnection ensures that the database is up and running by pinging it.
//
// Deprecated: use EnsureDBConnectionContext so a caller's startup deadline can
// cancel the retries; this wrapper is unbounded by any caller context.
func EnsureDBConnection(lggr logger.Logger, db Pingable) error {
	return EnsureDBConnectionContext(context.Background(), lggr, db)
}

// EnsureDBConnectionContext pings the database until it answers or ctx is done.
// Retries stop as soon as ctx is canceled, so a degraded database cannot block
// startup beyond the caller's deadline.
func EnsureDBConnectionContext(ctx context.Context, lggr logger.Logger, db Pingable) error {
	for attempt := range maxRetries {
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		err := db.PingContext(pingCtx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("database still unreachable (last ping: %w): %w", err, ctx.Err())
		}
		lggr.Warnw("failed to connect to database, retrying after sleeping",
			"err", err,
			"retryInterval", retryInterval.String(),
			"attempt", attempt+1,
			"maxRetries", maxRetries)
		select {
		case <-ctx.Done():
			return fmt.Errorf("database still unreachable (last ping: %w): %w", err, ctx.Err())
		case <-time.After(retryInterval):
		}
	}
	return fmt.Errorf("failed to connect to database after %d retries", maxRetries)
}
