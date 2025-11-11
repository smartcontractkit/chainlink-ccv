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
	getBatchCCVDataOp        = "GetBatchCCVData"
	submitReportOp           = "SubmitReport"
	ListOrphanedKeysOp       = "ListOrphanedKeys"
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

func (s *MetricsAwareStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord, aggregationKey model.AggregationKey) error {
	return captureMetricsNoReturn(ctx, s.metrics(ctx, saveOp), func() error {
		return s.inner.SaveCommitVerification(ctx, record, aggregationKey)
	})
}

func (s *MetricsAwareStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	return captureMetrics(ctx, s.metrics(ctx, getOp), func() (*model.CommitVerificationRecord, error) {
		return s.inner.GetCommitVerification(ctx, id)
	})
}

func (s *MetricsAwareStorage) ListCommitVerificationByAggregationKey(ctx context.Context, messageID model.MessageID, aggregationKey model.AggregationKey, committee string) ([]*model.CommitVerificationRecord, error) {
	return captureMetrics(ctx, s.metrics(ctx, listByMsgIDOp), func() ([]*model.CommitVerificationRecord, error) {
		return s.inner.ListCommitVerificationByAggregationKey(ctx, messageID, aggregationKey, committee)
	})
}

func (s *MetricsAwareStorage) QueryAggregatedReports(ctx context.Context, start int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error) {
	return captureMetrics(ctx, s.metrics(ctx, queryAggregatedReportsOp), func() (*model.PaginatedAggregatedReports, error) {
		return s.inner.QueryAggregatedReports(ctx, start, committeeID, token)
	})
}

func (s *MetricsAwareStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	return captureMetrics(ctx, s.metrics(ctx, getCCVDataOp), func() (*model.CommitAggregatedReport, error) {
		return s.inner.GetCCVData(ctx, messageID, committeeID)
	})
}

func (s *MetricsAwareStorage) GetBatchCCVData(ctx context.Context, messageIDs []model.MessageID, committeeID string) (map[string]*model.CommitAggregatedReport, error) {
	return captureMetrics(ctx, s.metrics(ctx, getBatchCCVDataOp), func() (map[string]*model.CommitAggregatedReport, error) {
		return s.inner.GetBatchCCVData(ctx, messageIDs, committeeID)
	})
}

func (s *MetricsAwareStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	return captureMetricsNoReturn(ctx, s.metrics(ctx, submitReportOp), func() error {
		return s.inner.SubmitReport(ctx, report)
	})
}

func (s *MetricsAwareStorage) ListOrphanedKeys(ctx context.Context, committeeID model.CommitteeID) (<-chan model.OrphanedKey, <-chan error) {
	metrics := s.metrics(ctx, ListOrphanedKeysOp)
	resultChan := make(chan model.OrphanedKey, 100)
	errorChan := make(chan error, 1)

	innerResultChan, innerErrorChan := s.inner.ListOrphanedKeys(ctx, committeeID)

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
	storeChainStatusesOp     = "StoreChainStatus"
	getClientChainStatusesOp = "GetClientChainStatuses"
	getAllClientsOp          = "GetAllClients"
)

type MetricsAwareChainStatusStorage struct {
	inner common.ChainStatusStorageInterface
	m     common.AggregatorMonitoring
}

func NewMetricsAwareChainStatusStorage(inner common.ChainStatusStorageInterface, m common.AggregatorMonitoring) *MetricsAwareChainStatusStorage {
	return &MetricsAwareChainStatusStorage{
		inner: inner,
		m:     m,
	}
}

func (s *MetricsAwareChainStatusStorage) metrics(ctx context.Context, operation string) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, s.m.Metrics())
	return metrics.With(operationLabel, operation)
}

func WrapChainStatusWithMetrics(inner common.ChainStatusStorageInterface, m common.AggregatorMonitoring) common.ChainStatusStorageInterface {
	return NewMetricsAwareChainStatusStorage(inner, m)
}

func (s *MetricsAwareChainStatusStorage) StoreChainStatus(ctx context.Context, clientID string, chainStatuses map[uint64]*common.ChainStatus) error {
	return captureMetricsNoReturn(ctx, s.metrics(ctx, storeChainStatusesOp), func() error {
		return s.inner.StoreChainStatus(ctx, clientID, chainStatuses)
	})
}

func (s *MetricsAwareChainStatusStorage) GetClientChainStatus(ctx context.Context, clientID string) (map[uint64]*common.ChainStatus, error) {
	return captureMetrics(ctx, s.metrics(ctx, getClientChainStatusesOp), func() (map[uint64]*common.ChainStatus, error) {
		return s.inner.GetClientChainStatus(ctx, clientID)
	})
}

func (s *MetricsAwareChainStatusStorage) GetAllClients(ctx context.Context) ([]string, error) {
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
