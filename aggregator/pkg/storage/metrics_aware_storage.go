package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
)

const (
	operationLabel = "operation"
	saveOp         = "SaveCommitVerification"
	getOp          = "GetCommitVerification"
	listByMsgIDOp  = "ListCommitVerificationByMessageID"

	queryAggregatedReportsOp = "QueryAggregatedReports"
	getCCVDataOp             = "GetCCVData"
	submitReportOp           = "SubmitReport"
	ListOrphanedMessageIDsOp = "ListOrphanedMessageIDs"
)

type MetricsAwareStorage struct {
	inner CommitVerificationStorage
	m     common.AggregatorMonitoring
}

func NewMetricsAwareStorage(inner CommitVerificationStorage, m common.AggregatorMonitoring) *MetricsAwareStorage {
	return &MetricsAwareStorage{
		inner: inner,
		m:     m,
	}
}

func (s *MetricsAwareStorage) metrics(ctx context.Context, operation string) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, s.m.Metrics())
	return metrics.With(operationLabel, operation)
}

func WrapWithMetrics(inner CommitVerificationStorage, m common.AggregatorMonitoring) CommitVerificationStorage {
	return NewMetricsAwareStorage(inner, m)
}

func (s *MetricsAwareStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	return captureMetricsNoReturn(ctx, s.metrics(ctx, saveOp), func() error {
		return s.inner.SaveCommitVerification(ctx, record)
	})
}

func (s *MetricsAwareStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	return captureMetrics(ctx, s.metrics(ctx, getOp), func() (*model.CommitVerificationRecord, error) {
		return s.inner.GetCommitVerification(ctx, id)
	})
}

func (s *MetricsAwareStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	return captureMetrics(ctx, s.metrics(ctx, listByMsgIDOp), func() ([]*model.CommitVerificationRecord, error) {
		return s.inner.ListCommitVerificationByMessageID(ctx, messageID, committee)
	})
}

func (s *MetricsAwareStorage) QueryAggregatedReports(ctx context.Context, start, end int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error) {
	return captureMetrics(ctx, s.metrics(ctx, queryAggregatedReportsOp), func() (*model.PaginatedAggregatedReports, error) {
		return s.inner.QueryAggregatedReports(ctx, start, end, committeeID, token)
	})
}

func (s *MetricsAwareStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	return captureMetrics(ctx, s.metrics(ctx, getCCVDataOp), func() (*model.CommitAggregatedReport, error) {
		return s.inner.GetCCVData(ctx, messageID, committeeID)
	})
}

func (s *MetricsAwareStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	return captureMetricsNoReturn(ctx, s.metrics(ctx, submitReportOp), func() error {
		return s.inner.SubmitReport(ctx, report)
	})
}

func (s *MetricsAwareStorage) ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error) {
	metrics := s.metrics(ctx, ListOrphanedMessageIDsOp)
	resultChan := make(chan model.MessageID, 100)
	errorChan := make(chan error, 1)

	innerResultChan, innerErrorChan := s.inner.ListOrphanedMessageIDs(ctx, committeeID)

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

const (
	storeCheckpointsOp     = "StoreCheckpoints"
	getClientCheckpointsOp = "GetClientCheckpoints"
	getAllClientsOp        = "GetAllClients"
)

type MetricsAwareCheckpointStorage struct {
	inner common.CheckpointStorageInterface
	m     common.AggregatorMonitoring
}

func NewMetricsAwareCheckpointStorage(inner common.CheckpointStorageInterface, m common.AggregatorMonitoring) *MetricsAwareCheckpointStorage {
	return &MetricsAwareCheckpointStorage{
		inner: inner,
		m:     m,
	}
}

func (s *MetricsAwareCheckpointStorage) metrics(ctx context.Context, operation string) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, s.m.Metrics())
	return metrics.With(operationLabel, operation)
}

func WrapCheckpointWithMetrics(inner common.CheckpointStorageInterface, m common.AggregatorMonitoring) common.CheckpointStorageInterface {
	return NewMetricsAwareCheckpointStorage(inner, m)
}

func (s *MetricsAwareCheckpointStorage) StoreCheckpoints(ctx context.Context, clientID string, checkpoints map[uint64]uint64) error {
	return captureMetricsNoReturn(ctx, s.metrics(ctx, storeCheckpointsOp), func() error {
		return s.inner.StoreCheckpoints(ctx, clientID, checkpoints)
	})
}

func (s *MetricsAwareCheckpointStorage) GetClientCheckpoints(ctx context.Context, clientID string) (map[uint64]uint64, error) {
	return captureMetrics(ctx, s.metrics(ctx, getClientCheckpointsOp), func() (map[uint64]uint64, error) {
		return s.inner.GetClientCheckpoints(ctx, clientID)
	})
}

func (s *MetricsAwareCheckpointStorage) GetAllClients(ctx context.Context) ([]string, error) {
	return captureMetrics(ctx, s.metrics(ctx, getAllClientsOp), func() ([]string, error) {
		return s.inner.GetAllClients(ctx)
	})
}

func captureMetrics[T any](ctx context.Context, metrics common.AggregatorMetricLabeler, fn func() (T, error)) (T, error) {
	now := time.Now()
	defer func() {
		metrics.RecordStorageLatency(ctx, time.Since(now))
	}()

	res, err := fn()
	if err != nil {
		metrics.IncrementStorageError(ctx)
	}
	return res, err
}

func captureMetricsNoReturn(ctx context.Context, metrics common.AggregatorMetricLabeler, fn func() error) error {
	_, err := captureMetrics(ctx, metrics, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
