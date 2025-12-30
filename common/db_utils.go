package common

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Pingable interface {
	PingContext(ctx context.Context) error
}

// EnsureDBConnection ensures that the database is up and running by pinging it.
func EnsureDBConnection(lggr logger.Logger, db Pingable) error {
	const (
		maxRetries    = 10
		timeout       = 1 * time.Second
		retryInterval = 3 * time.Second
	)
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
