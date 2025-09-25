package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
)

type Storage interface {
	common.CommitVerificationStore
	common.CommitVerificationAggregatedStore
	common.Sink
}

type MetricsAwareStorage struct {
	inner Storage
	m     common.AggregatorMonitoring
}

func NewMetricsAwareStorage(inner Storage, m common.AggregatorMonitoring) *MetricsAwareStorage {
	return &MetricsAwareStorage{
		inner: inner,
		m:     m,
	}
}

func (s *MetricsAwareStorage) metrics(ctx context.Context, operation string) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, s.m.Metrics())
	return metrics.With("operation", operation)
}

func WrapWithMetrics(inner Storage, m common.AggregatorMonitoring) Storage {
	return NewMetricsAwareStorage(inner, m)
}

func (s *MetricsAwareStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	metrics := s.metrics(ctx, "SaveCommitVerification")

	now := time.Now()
	defer func() {
		latency := time.Since(now).Milliseconds()
		metrics.RecordStorageLatency(ctx, latency)
	}()
	err := s.inner.SaveCommitVerification(ctx, record)
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return err
}

func (s *MetricsAwareStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	metrics := s.metrics(ctx, "GetCommitVerification")

	now := time.Now()
	defer func() {
		latency := time.Since(now).Milliseconds()
		metrics.RecordStorageLatency(ctx, latency)
	}()
	record, err := s.inner.GetCommitVerification(ctx, id)
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return record, err
}

func (s *MetricsAwareStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	metrics := s.metrics(ctx, "ListCommitVerificationByMessageID")

	now := time.Now()
	defer func() {
		latency := time.Since(now).Milliseconds()
		metrics.RecordStorageLatency(ctx, latency)
	}()
	records, err := s.inner.ListCommitVerificationByMessageID(ctx, messageID, committee)
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return records, err
}

func (s *MetricsAwareStorage) ListOrphanedMessageCommitteePairs(ctx context.Context) (<-chan *model.MessageCommitteePair, <-chan error) {
	return s.inner.ListOrphanedMessageCommitteePairs(ctx)
}

func (s *MetricsAwareStorage) QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string) ([]*model.CommitAggregatedReport, error) {
	metrics := s.metrics(ctx, "QueryAggregatedReports")

	now := time.Now()
	defer func() {
		latency := time.Since(now).Milliseconds()
		metrics.RecordStorageLatency(ctx, latency)
	}()
	reports, err := s.inner.QueryAggregatedReports(ctx, start, end, committeeID)
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return reports, err
}

func (s *MetricsAwareStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	metrics := s.metrics(ctx, "GetCCVData")

	now := time.Now()
	defer func() {
		latency := time.Since(now).Milliseconds()
		metrics.RecordStorageLatency(ctx, latency)
	}()
	report, err := s.inner.GetCCVData(ctx, messageID, committeeID)
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return report, err
}

func (s *MetricsAwareStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	metrics := s.metrics(ctx, "SubmitReport")

	now := time.Now()
	defer func() {
		latency := time.Since(now).Milliseconds()
		metrics.RecordStorageLatency(ctx, latency)
	}()
	err := s.inner.SubmitReport(ctx, report)
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return err
}
