package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// IndexerMetrics provides all metrics provided by the indexer.
type IndexerMetrics struct {
	// HTTP Metrics
	httpRequestsCounter         metric.Int64Counter
	activeRequestsUpDownCounter metric.Int64UpDownCounter
	requestDurationSeconds      metric.Float64Histogram

	// Storage Metrics
	uniqueMessagesCounter       metric.Int64Counter
	verificationRecordsCounter  metric.Int64Counter
	storageQueryDurationSeconds metric.Float64Histogram
	storageWriteDurationSeconds metric.Float64Histogram
	storageInsertErrorsCounter  metric.Int64Counter

	// Scanner Metrics
	scannerPollingErrorsCounter        metric.Int64Counter
	verificationRecordChannelSizeGauge metric.Int64Gauge
	activeReadersGauge                 metric.Int64Gauge
	discoveryLatencySeconds            metric.Float64Histogram
	timeToIndexSeconds                 metric.Float64Histogram
}

func InitMetrics() (im *IndexerMetrics, err error) {
	im = &IndexerMetrics{}

	im.activeRequestsUpDownCounter, err = beholder.GetMeter().Int64UpDownCounter(
		"indexer_active_requests",
		metric.WithDescription("Total number of active requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register active requests up down counter: %w", err)
	}

	im.requestDurationSeconds, err = beholder.GetMeter().Float64Histogram("indexer_http_request_duration_seconds",
		metric.WithDescription("Total duration of requesting the HTTP request"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register http request duration histogram: %w", err)
	}

	im.uniqueMessagesCounter, err = beholder.GetMeter().Int64Counter(
		"indexer_unique_messages_total",
		metric.WithDescription("Total number of unique messages"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register unique messages counter: %w", err)
	}

	im.verificationRecordsCounter, err = beholder.GetMeter().Int64Counter(
		"indexer_verification_records_total",
		metric.WithDescription("Total number of verification records"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verification records counter: %w", err)
	}

	im.storageQueryDurationSeconds, err = beholder.GetMeter().Float64Histogram(
		"indexer_storage_query_duration_seconds",
		metric.WithDescription("Total duration of querying the storage of the Indexer"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage query duration histogram: %w", err)
	}

	im.storageWriteDurationSeconds, err = beholder.GetMeter().Float64Histogram("indexer_storage_write_duration_seconds",
		metric.WithDescription("Total duration of writing to the storage of the Indexer"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage write duration histogram: %w", err)
	}

	im.discoveryLatencySeconds, err = beholder.GetMeter().Float64Histogram("indexer_message_discovery_latency_seconds",
		metric.WithDescription("Latency between message discovery and processing (seconds)"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register message discovery latency histogram: %w", err)
	}

	im.storageInsertErrorsCounter, err = beholder.GetMeter().Int64Counter("indexer_storage_insert_errors_total",
		metric.WithDescription("Total number of errors when inserting into Indexer Storage"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register storage insert errors counter: %w", err)
	}

	im.scannerPollingErrorsCounter, err = beholder.GetMeter().Int64Counter("indexer_scanner_polling_errors_total",
		metric.WithDescription("Total number of errors when polling the scanner"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register scanner polling errors counter: %w", err)
	}

	im.verificationRecordChannelSizeGauge, err = beholder.GetMeter().Int64Gauge("indexer_verification_record_channel_size",
		metric.WithDescription("Total number of verification records in the channel"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register verification record channel size gauge: %w", err)
	}

	im.activeReadersGauge, err = beholder.GetMeter().Int64Gauge("indexer_active_readers",
		metric.WithDescription("Total number of active readers"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register active readers gauge: %w", err)
	}

	im.timeToIndexSeconds, err = beholder.GetMeter().Float64Histogram("indexer_time_to_index_seconds",
		metric.WithDescription("Total duration between aggregation and indexing"),
		metric.WithUnit("seconds"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register time to index histogram: %w", err)
	}
	return im, nil
}

// Note: due to the OTEL specification, all histogram buckets. Must be defined when the beholder client is created.
func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "indexer_storage_query_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "indexer_storage_write_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "indexer_http_request_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "indexer_message_discovery_latency_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "indexer_time_to_index_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			}},
		),
	}
}

var _ common.IndexerMetricLabeler = (*IndexerMetricLabeler)(nil)

type IndexerMetricLabeler struct {
	metrics.Labeler
	im *IndexerMetrics
}

func NewIndexerMetricLabeler(labeler metrics.Labeler, im *IndexerMetrics) common.IndexerMetricLabeler {
	return &IndexerMetricLabeler{
		Labeler: labeler,
		im:      im,
	}
}

func (c *IndexerMetricLabeler) With(keyValues ...string) common.IndexerMetricLabeler {
	return &IndexerMetricLabeler{c.Labeler.With(keyValues...), c.im}
}

func (c *IndexerMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.activeRequestsUpDownCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.activeRequestsUpDownCounter.Add(ctx, -1, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.requestDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes([]attribute.KeyValue{
		attribute.String("path", path),
		attribute.String("method", method),
		attribute.Int("status", status),
	}...), metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) IncrementUniqueMessagesCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.uniqueMessagesCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) IncrementVerificationRecordsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.verificationRecordsCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordStorageQueryDuration(ctx context.Context, duration time.Duration, queryName string) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.storageQueryDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes([]attribute.KeyValue{
		attribute.String("query", queryName),
	}...), metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.storageWriteDurationSeconds.Record(ctx, duration.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordStorageInsertErrorsCounter(ctx context.Context, queryName string) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.storageInsertErrorsCounter.Add(ctx, 1, metric.WithAttributes([]attribute.KeyValue{
		attribute.String("query", queryName),
	}...), metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordScannerPollingErrorsCounter(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.scannerPollingErrorsCounter.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordVerificationRecordChannelSizeGauge(ctx context.Context, size int64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.verificationRecordChannelSizeGauge.Record(ctx, size, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordActiveReadersGauge(ctx context.Context, count int64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.activeReadersGauge.Record(ctx, count, metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordIndexerMessageDiscoveryLatency(ctx context.Context, latency time.Duration) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.discoveryLatencySeconds.Record(ctx, latency.Seconds(), metric.WithAttributes(otelLabels...))
}

func (c *IndexerMetricLabeler) RecordTimeToIndex(ctx context.Context, latency time.Duration, discoveryType string) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.im.timeToIndexSeconds.Record(ctx, latency.Seconds(), metric.WithAttributes([]attribute.KeyValue{
		attribute.String("query", discoveryType),
	}...), metric.WithAttributes(otelLabels...))
}
