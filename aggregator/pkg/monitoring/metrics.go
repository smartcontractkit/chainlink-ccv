//nolint:gci,goimports
package monitoring

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// IndexerMetrics provides all metrics provided by the indexer.
type AggregatorMetrics struct {
	activeRequestsUpDownCounter            metric.Int64UpDownCounter
	completedAggregations                  metric.Int64Counter
	apiRequestDuration                     metric.Int64Histogram
	apiRequestError                        metric.Int64Counter
	getMessageSinceNumberOfRecordsReturned metric.Int64Histogram
	pendingAggregationsChannelBuffer       metric.Int64UpDownCounter
	timeToAggregation                      metric.Int64Histogram

	// Storage metrics
	storageLatency             metric.Int64Histogram
	storageError               metric.Int64Counter
	dynamodbReadCapacityUnits  metric.Float64Counter
	dynamodbWriteCapacityUnits metric.Float64Counter
}

func MetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_time_to_aggregation"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_api_request_duration"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_get_message_since_number_of_records_returns"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
			}},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "aggregator_storage_latency"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
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

	am.apiRequestDuration, err = beholder.GetMeter().Int64Histogram(
		"aggregator_api_request_duration",
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

	am.storageLatency, err = beholder.GetMeter().Int64Histogram(
		"aggregator_storage_latency",
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

	am.timeToAggregation, err = beholder.GetMeter().Int64Histogram(
		"aggregator_time_to_aggregation",
		metric.WithDescription("Time taken to complete an aggregation"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register time to aggregation histogram: %w", err)
	}

	am.dynamodbReadCapacityUnits, err = beholder.GetMeter().Float64Counter(
		"aggregator_dynamodb_read_capacity_units",
		metric.WithDescription("DynamoDB read capacity units consumed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register DynamoDB read capacity units counter: %w", err)
	}

	am.dynamodbWriteCapacityUnits, err = beholder.GetMeter().Float64Counter(
		"aggregator_dynamodb_write_capacity_units",
		metric.WithDescription("DynamoDB write capacity units consumed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register DynamoDB write capacity units histogram: %w", err)
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

func (c *AggregatorMetricLabeler) RecordAPIRequestDuration(ctx context.Context, durationMs int64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.apiRequestDuration.Record(ctx, durationMs, metric.WithAttributes(otelLabels...))
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

func (c *AggregatorMetricLabeler) RecordStorageLatency(ctx context.Context, latencyMs int64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.storageLatency.Record(ctx, latencyMs, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) IncrementStorageError(ctx context.Context) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.storageError.Add(ctx, 1, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordTimeToAggregation(ctx context.Context, durationMs int64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.timeToAggregation.Record(ctx, durationMs, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordDynamoDBReadCapacityUnits(ctx context.Context, units float64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.dynamodbReadCapacityUnits.Add(ctx, units, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordDynamoDBWriteCapacityUnits(ctx context.Context, units float64) {
	otelLabels := beholder.OtelAttributes(c.Labels).AsStringAttributes()
	c.am.dynamodbWriteCapacityUnits.Add(ctx, units, metric.WithAttributes(otelLabels...))
}

func (c *AggregatorMetricLabeler) RecordCapacity(capacity *types.ConsumedCapacity) {
	if capacity == nil {
		return
	}

	c.recordTableCapacity(capacity)
	c.recordGSICapacity(capacity)
}

func (c *AggregatorMetricLabeler) recordTableCapacity(capacity *types.ConsumedCapacity) {
	if capacity.TableName == nil || capacity.Table == nil {
		return
	}

	metrics := c.With("table", *capacity.TableName)
	if capacity.Table.ReadCapacityUnits != nil {
		metrics.RecordDynamoDBReadCapacityUnits(context.Background(), *capacity.Table.ReadCapacityUnits)
	}
	if capacity.Table.WriteCapacityUnits != nil {
		metrics.RecordDynamoDBWriteCapacityUnits(context.Background(), *capacity.Table.WriteCapacityUnits)
	}
}

func (c *AggregatorMetricLabeler) recordGSICapacity(capacity *types.ConsumedCapacity) {
	if capacity.GlobalSecondaryIndexes == nil || capacity.TableName == nil {
		return
	}

	for gsiName, gsiCapacity := range capacity.GlobalSecondaryIndexes {
		gsiMetrics := c.With("table", *capacity.TableName, "gsi", gsiName)
		if gsiCapacity.ReadCapacityUnits != nil {
			gsiMetrics.RecordDynamoDBReadCapacityUnits(context.Background(), *gsiCapacity.ReadCapacityUnits)
		}
		if gsiCapacity.WriteCapacityUnits != nil {
			gsiMetrics.RecordDynamoDBWriteCapacityUnits(context.Background(), *gsiCapacity.WriteCapacityUnits)
		}
	}
}
