package health

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"

	"github.com/smartcontractkit/chainlink-ccv/common/static"
)

const (
	// metricsInterval matches the CL node's health check cadence.
	metricsInterval = 15 * time.Second

	healthInstrument   = "health"
	uptimeInstrument   = "uptime_seconds"
	versionInstrument  = "version"
	serviceIDAttribute = "service_id"
	versionAttribute   = "version"
	commitAttribute    = "commit"
)

// MetricsRecorder publishes the health, uptime_seconds and version instruments the CL node emits.
// It reads the Manager it was built with, so the metric and /health agree on which components exist.
type MetricsRecorder struct {
	services.Service
	eng *services.Engine

	manager  *Manager
	interval time.Duration

	health  metric.Int64Gauge
	uptime  metric.Float64Counter
	version metric.Int64Counter
}

// NewMetricsRecorder creates the instruments on the global Beholder meter, which is a noop client
// until telemetry is configured, so this is safe when Beholder is disabled.
func NewMetricsRecorder(lggr logger.Logger, manager *Manager) (*MetricsRecorder, error) {
	meter := beholder.GetMeter()

	healthGauge, err := meter.Int64Gauge(healthInstrument,
		metric.WithDescription("Health status by service"))
	if err != nil {
		return nil, err
	}
	uptime, err := meter.Float64Counter(uptimeInstrument,
		metric.WithDescription("Uptime of the service in seconds"))
	if err != nil {
		return nil, err
	}
	version, err := meter.Int64Counter(versionInstrument,
		metric.WithDescription("Version and SHA of the service"))
	if err != nil {
		return nil, err
	}

	r := &MetricsRecorder{
		manager:  manager,
		interval: metricsInterval,
		health:   healthGauge,
		uptime:   uptime,
		version:  version,
	}
	r.Service, r.eng = services.Config{
		Name:  "HealthMetricsRecorder",
		Start: r.start,
	}.NewServiceEngine(lggr)
	return r, nil
}

func (r *MetricsRecorder) start(ctx context.Context) error {
	r.version.Add(ctx, 1, metric.WithAttributes(
		attribute.String(versionAttribute, static.Version),
		attribute.String(commitAttribute, static.Sha),
	))
	// Record once before ticking so the series exist immediately, as the CL node's checker does.
	r.record(ctx)
	r.eng.GoTick(services.NewTicker(r.interval), r.record)
	return nil
}

// record writes one value per registered component and accumulates uptime.
func (r *MetricsRecorder) record(ctx context.Context) {
	for _, component := range r.manager.CheckReadiness(ctx).Services {
		r.health.Record(ctx, healthStatusValue(component.Status),
			metric.WithAttributes(attribute.String(serviceIDAttribute, component.Name)))
	}
	r.uptime.Add(ctx, r.interval.Seconds())
}

// healthStatusValue maps readiness onto the two-valued health metric. Degraded counts as healthy:
// the component still works, and the gap is what /health reports.
func healthStatusValue(status ReadinessStatus) int64 {
	if status == NotReady {
		return 0
	}
	return 1
}

// Close stops the recorder. It is a no-op when the recorder never started or already stopped.
func (r *MetricsRecorder) Close() error {
	err := r.Service.Close()
	if errors.Is(err, services.ErrCannotStopUnstarted) || errors.Is(err, services.ErrAlreadyStopped) {
		return nil
	}
	return err
}
