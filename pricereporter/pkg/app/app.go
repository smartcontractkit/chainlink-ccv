// Package app provides the main application logic for the pricereporter service.
package app

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Run starts the pricereporter service and blocks until the context is cancelled.
func Run(ctx context.Context, lggr logger.SugaredLogger, interval time.Duration) error {
	lggr.Infow("pricereporter starting", "interval", interval)
	<-ctx.Done()
	lggr.Info("pricereporter shutting down")
	return nil
}
