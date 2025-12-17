package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// AggregatorMetrics provides all metrics provided by the indexer.
type AggregatorMetrics struct {
	activeRequestsUpDownCounter            metric.Int64UpDownCounter
	completedAggregations                  metric.Int64Counter
	apiRequestDuration                     metric.Float64Histogram
	apiRequestError                        metric.Int64Counter
	getMessageSinceNumberOfRecordsReturned metric.Int64Histogram
	pendingAggregationsChannelBuffer       metric.Int64UpDownCounter
	timeToAggregation                      metric.Float64Histogram

	// Storage metrics
	storageLatency metric.Float64Histogram
	storageError   metric.Int64Counter

	// Orphan recovery metrics
	orphanBacklog          metric.Int64Gauge
	orphanExpiredBacklog   metric.Int64Gauge
	orphanRecoveryDuration metric.Float64Histogram
	orphanCleanupDuration  metric.Float64Histogram
	orphanRecordsExpired   metric.Int64Counter
	orphanRecoveryErrors   metric.Int64Counter
}

func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_time_to_aggregation_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_api_request_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_get_message_since_number_of_records_returns"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_storage_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_orphan_recovery_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_orphan_cleanup_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300},
			}},
		),
	}
}

func InitMetrics() (am *AggregatorMetrics, err error) {
	am = &AggregatorMetrics{}

	am.activeRequestsUpDownCounter, err = beholder.GetMeter().Int64UpDownCounter(
		"aggregator_active_requests",
		metric.WithDescription("Total number of active requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register active requests up down counter: %w", err)
	}

	am.completedAggregations, err = beholder.GetMeter().Int64Counter(
		"aggregator_completed_aggregations",
		metric.WithDescription("Total number of completed aggregations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register completed aggregations counter: %w", err)
	}

	am.apiRequestDuration, err = beholder.GetMeter().Float64Histogram(
		"aggregator_api_request_duration_seconds",
		metric.WithDescription("Duration of API requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register API request duration histogram: %w", err)
	}

	am.apiRequestError, err = beholder.GetMeter().Int64Counter(
		"aggregator_api_request_errors",
		metric.WithDescription("Total number of API request errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register API request errors counter: %w", err)
	}

	am.getMessageSinceNumberOfRecordsReturned, err = beholder.GetMeter().Int64Histogram(
		"aggregator_get_message_since_number_of_records_returns",
		metric.WithDescription("Number of records returned by GetMessagesSince"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register GetMessagesSince number of records returned histogram: %w", err)
	}

	am.pendingAggregationsChannelBuffer, err = beholder.GetMeter().Int64UpDownCounter(
		"aggregator_pending_aggregations_channel_buffer",
		metric.WithDescription("Current size of the pending aggregations channel buffer"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register pending aggregations channel buffer up down counter: %w", err)
	}

	am.storageLatency, err = beholder.GetMeter().Float64Histogram(
		"aggregator_storage_duration_seconds",
		metric.WithDescription("Latency of storage operations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage latency histogram: %w", err)
	}

	am.storageError, err = beholder.GetMeter().Int64Counter(
		"aggregator_storage_errors",
		metric.WithDescription("Total number of storage errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage errors counter: %w", err)
	}

	am.timeToAggregation, err = beholder.GetMeter().Float64Histogram(
		"aggregator_time_to_aggregation_seconds",
		metric.WithDescription("Time taken to complete an aggregation"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register time to aggregation histogram: %w", err)
	}

	am.orphanBacklog, err = beholder.GetMeter().Int64Gauge(
		"aggregator_orphan_backlog",
		metric.WithDescription("Current count of non-expired orphan records (recovery queue)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register orphan backlog gauge: %w", err)
	}

	am.orphanExpiredBacklog, err = beholder.GetMeter().Int64Gauge(
		"aggregator_orphan_expired_backlog",
		metric.WithDescription("Current count of expired orphan records (pending cleanup)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register orphan expired backlog gauge: %w", err)
	}

	am.orphanRecoveryDuration, err = beholder.GetMeter().Float64Histogram(
		"aggregator_orphan_recovery_duration_seconds",
		metric.WithDescription("Duration of orphan recovery scans in seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register orphan recovery duration histogram: %w", err)
	}

	am.orphanCleanupDuration, err = beholder.GetMeter().Float64Histogram(
		"aggregator_orphan_cleanup_duration_seconds",
		metric.WithDescription("Duration of orphan cleanup runs in seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register orphan cleanup duration histogram: %w", err)
	}

	am.orphanRecordsExpired, err = beholder.GetMeter().Int64Counter(
		"aggregator_orphan_records_expired",
		metric.WithDescription("Total number of orphan records deleted due to expiry"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register orphan records expired counter: %w", err)
	}

	am.orphanRecoveryErrors, err = beholder.GetMeter().Int64Counter(
		"aggregator_orphan_recovery_errors",
		metric.WithDescription("Total number of errors during orphan recovery"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register orphan recovery errors counter: %w", err)
	}

	return am, nil
}

type AggregatorMetricLabeler struct {
	metrics.Labeler
	am *AggregatorMetrics
}

func NewAggregatorMetricLabeler(labeler metrics.Labeler, am *AggregatorMetrics) common.AggregatorMetricLabeler {
	return &AggregatorMetricLabeler{
		Labeler: labeler,
		am:      am,
	}
}

func (c *AggregatorMetricLabeler) With(keyValues ...string) common.AggregatorMetricLabeler {
	return &AggregatorMetricLabeler{c.Labeler.With(keyValues...), c.am}
}

func (c *AggregatorMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.activeRequestsUpDownCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.activeRequestsUpDownCounter.Add(ctx, -1, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementCompletedAggregations(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.completedAggregations.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordAPIRequestDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.apiRequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementAPIRequestErrors(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.apiRequestError.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordMessageSinceNumberOfRecordsReturned(ctx context.Context, count int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.getMessageSinceNumberOfRecordsReturned.Record(ctx, int64(count), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementPendingAggregationsChannelBuffer(ctx context.Context, count int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.pendingAggregationsChannelBuffer.Add(ctx, int64(count), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) DecrementPendingAggregationsChannelBuffer(ctx context.Context, count int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.pendingAggregationsChannelBuffer.Add(ctx, -int64(count), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordStorageLatency(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.storageLatency.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementStorageError(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.storageError.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordTimeToAggregation(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.timeToAggregation.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) SetOrphanBacklog(ctx context.Context, count int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.orphanBacklog.Record(ctx, int64(count), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) SetOrphanExpiredBacklog(ctx context.Context, count int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.orphanExpiredBacklog.Record(ctx, int64(count), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordOrphanRecoveryDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.orphanRecoveryDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordOrphanCleanupDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.orphanCleanupDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementOrphanRecordsExpired(ctx context.Context, count int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.orphanRecordsExpired.Add(ctx, int64(count), metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementOrphanRecoveryErrors(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.orphanRecoveryErrors.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}
