package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	operationLabel = "operation"
	saveOp         = "SaveCommitVerification"
	getOp          = "GetCommitVerification"
	listByMsgIDOp  = "ListCommitVerificationByMessageID"

	queryAggregatedReportsOp = "QueryAggregatedReports"
	getCCVDataOp             = "GetCCVData"
	getBatchCCVDataOp        = "GetBatchCCVData"
	submitReportOp           = "SubmitReport"
	ListOrphanedKeysOp       = "ListOrphanedKeys"
	orphanedKeyStatsOp       = "OrphanedKeyStats"

	defaultSlowQueryThreshold = 500 * time.Millisecond
)

type MetricsAwareStorage struct {
	inner              CommitVerificationStorage
	m                  common.AggregatorMonitoring
	l                  logger.SugaredLogger
	slowQueryThreshold time.Duration
}

type MetricsAwareStorageOption func(*MetricsAwareStorage)

func WithSlowQueryThreshold(threshold time.Duration) MetricsAwareStorageOption {
	return func(s *MetricsAwareStorage) {
		s.slowQueryThreshold = threshold
	}
}

func NewMetricsAwareStorage(inner CommitVerificationStorage, m common.AggregatorMonitoring, l logger.SugaredLogger, opts ...MetricsAwareStorageOption) *MetricsAwareStorage {
	s := &MetricsAwareStorage{
		inner:              inner,
		m:                  m,
		l:                  l,
		slowQueryThreshold: defaultSlowQueryThreshold,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *MetricsAwareStorage) metrics(ctx context.Context, operation string) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, s.m.Metrics())
	return metrics.With(operationLabel, operation)
}

func (s *MetricsAwareStorage) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, s.l)
}

func WrapWithMetrics(inner CommitVerificationStorage, m common.AggregatorMonitoring, l logger.SugaredLogger, opts ...MetricsAwareStorageOption) CommitVerificationStorage {
	return NewMetricsAwareStorage(inner, m, l, opts...)
}

func (s *MetricsAwareStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error {
	return s.captureMetricsNoReturn(ctx, saveOp, func() error {
		return s.inner.SaveCommitVerification(ctx, record, aggregationKey)
	})
}

func (s *MetricsAwareStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	return captureMetrics(ctx, s.metrics(ctx, getOp), s.logger(ctx), s.slowQueryThreshold, getOp, func() (*model.CommitVerificationRecord, error) {
		return s.inner.GetCommitVerification(ctx, id)
	})
}

func (s *MetricsAwareStorage) ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
	return captureMetrics(ctx, s.metrics(ctx, listByMsgIDOp), s.logger(ctx), s.slowQueryThreshold, listByMsgIDOp, func() ([]*model.CommitVerificationRecord, error) {
		return s.inner.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey)
	})
}

func (s *MetricsAwareStorage) QueryAggregatedReports(ctx context.Context, sinceSequenceInclusive int64) (*model.AggregatedReportBatch, error) {
	return captureMetrics(ctx, s.metrics(ctx, queryAggregatedReportsOp), s.logger(ctx), s.slowQueryThreshold, queryAggregatedReportsOp, func() (*model.AggregatedReportBatch, error) {
		return s.inner.QueryAggregatedReports(ctx, sinceSequenceInclusive)
	})
}

func (s *MetricsAwareStorage) GetCommitAggregatedReportByMessageID(ctx context.Context, messageID model.MessageID) (*model.CommitAggregatedReport, error) {
	return captureMetrics(ctx, s.metrics(ctx, getCCVDataOp), s.logger(ctx), s.slowQueryThreshold, getCCVDataOp, func() (*model.CommitAggregatedReport, error) {
		return s.inner.GetCommitAggregatedReportByMessageID(ctx, messageID)
	})
}

func (s *MetricsAwareStorage) GetBatchAggregatedReportByMessageIDs(ctx context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error) {
	return captureMetrics(ctx, s.metrics(ctx, getBatchCCVDataOp), s.logger(ctx), s.slowQueryThreshold, getBatchCCVDataOp, func() (map[string]*model.CommitAggregatedReport, error) {
		return s.inner.GetBatchAggregatedReportByMessageIDs(ctx, messageIDs)
	})
}

func (s *MetricsAwareStorage) SubmitAggregatedReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	return s.captureMetricsNoReturn(ctx, submitReportOp, func() error {
		return s.inner.SubmitAggregatedReport(ctx, report)
	})
}

func (s *MetricsAwareStorage) ListOrphanedKeys(ctx context.Context, newerThan time.Time) (<-chan model.OrphanedKey, <-chan error) {
	metrics := s.metrics(ctx, ListOrphanedKeysOp)
	resultChan := make(chan model.OrphanedKey, 100)
	errorChan := make(chan error, 1)

	innerResultChan, innerErrorChan := s.inner.ListOrphanedKeys(ctx, newerThan)

	go func() {
		now := time.Now()
		defer func() {
			metrics.RecordStorageLatency(ctx, time.Since(now))
		}()

		for {
			select {
			case id, ok := <-innerResultChan:
				if !ok {
					close(resultChan)
					return
				}
				resultChan <- id

			case err := <-innerErrorChan:
				errorChan <- err
			}
		}
	}()

	return resultChan, errorChan
}

func (s *MetricsAwareStorage) OrphanedKeyStats(ctx context.Context, cutoff time.Time) (*model.OrphanStats, error) {
	return captureMetrics(ctx, s.metrics(ctx, orphanedKeyStatsOp), s.logger(ctx), s.slowQueryThreshold, orphanedKeyStatsOp, func() (*model.OrphanStats, error) {
		return s.inner.OrphanedKeyStats(ctx, cutoff)
	})
}

func captureMetrics[T any](ctx context.Context, metrics common.AggregatorMetricLabeler, l logger.SugaredLogger, threshold time.Duration, operation string, fn func() (T, error)) (T, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		metrics.RecordStorageLatency(ctx, duration)
		if duration > threshold {
			l.Warnw("Slow storage operation", "operation", operation, "duration_ms", duration.Milliseconds())
		}
	}()

	res, err := fn()
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}

	return res, err
}

func (s *MetricsAwareStorage) captureMetricsNoReturn(ctx context.Context, operation string, fn func() error) error {
	_, err := captureMetrics(ctx, s.metrics(ctx, operation), s.logger(ctx), s.slowQueryThreshold, operation, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
