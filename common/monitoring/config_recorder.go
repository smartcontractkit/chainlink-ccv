package monitoring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// DefaultBeholderConfigEmitInterval matches the CL node's beholder config recorder.
const DefaultBeholderConfigEmitInterval = time.Hour

// ConfigRecorder periodically records the Beholder client's own config as beholder.config.info,
// as the CL node does. It reads the global client, so it reports the config that client was built
// with rather than a copy that could drift from it.
type ConfigRecorder struct {
	services.Service
	eng *services.Engine

	interval time.Duration
}

// NewConfigRecorder builds the recorder. The global Beholder client is a noop until telemetry is
// configured, so this is safe to start when Beholder is disabled.
func NewConfigRecorder(lggr logger.Logger) *ConfigRecorder {
	r := &ConfigRecorder{interval: DefaultBeholderConfigEmitInterval}
	r.Service, r.eng = services.Config{
		Name:  "BeholderConfigRecorder",
		Start: r.start,
	}.NewServiceEngine(lggr)
	return r
}

func (r *ConfigRecorder) start(ctx context.Context) error {
	// Record once now so the series exists immediately, then on the hourly tick.
	r.record(ctx)
	r.eng.Go(func(ctx context.Context) {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.record(ctx)
			}
		}
	})
	return nil
}

// StartConfigRecorder builds and starts the recorder. The caller owns its lifecycle — defer Close in
// a main function, or keep it and close on shutdown — and owns the context: the recorder's goroutine
// ends on Close, not on ctx, so ctx only bounds the start.
func StartConfigRecorder(ctx context.Context, lggr logger.Logger) (*ConfigRecorder, error) {
	recorder := NewConfigRecorder(lggr)
	if err := recorder.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start beholder config recorder: %w", err)
	}
	return recorder, nil
}

func (r *ConfigRecorder) record(ctx context.Context) {
	if err := beholder.GetClient().RecordConfigMetric(ctx); err != nil {
		r.eng.Errorw("failed to record beholder config metric", "error", err)
	}
}

// Close stops the recorder. It is a no-op when the recorder never started or already stopped.
func (r *ConfigRecorder) Close() error {
	err := r.Service.Close()
	if errors.Is(err, services.ErrCannotStopUnstarted) || errors.Is(err, services.ErrAlreadyStopped) {
		return nil
	}
	return err
}
