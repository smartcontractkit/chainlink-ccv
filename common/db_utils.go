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
func EnsureDBConnection(lggr logger.Logger, db Pingable) error {
	pingFn := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return db.PingContext(ctx)
	}
	for range maxRetries {
		err := pingFn()
		if err == nil {
			return nil
		}
		lggr.Warnw("failed to connect to database, retrying after sleeping",
			"err", err,
			"retryInterval", retryInterval.String(),
			"maxRetries", maxRetries)
		time.Sleep(retryInterval)
	}
	return fmt.Errorf("failed to connect to database after %d retries", maxRetries)
}
