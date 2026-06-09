package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	opGetCCVData            = "GetCCVData"
	opQueryCCVData          = "QueryCCVData"
	opInsertVerifierResults = "InsertVerifierResults"
	opGetMessage            = "GetMessage"
	opQueryMessages         = "QueryMessages"
	opUpdateMessageStatus   = "UpdateMessageStatus"
	opCreateDiscoveryState  = "CreateDiscoveryState"
	opGetDiscoverySequence  = "GetDiscoverySequenceNumber"
	opPersistDiscoveryBatch = "PersistDiscoveryBatch"

	defaultSlowQueryThreshold = 500 * time.Millisecond
)

type MetricsAwareStorage struct {
	inner              common.IndexerStorage
	m                  common.IndexerMonitoring
	l                  logger.Logger
	slowQueryThreshold time.Duration
}

type MetricsAwareStorageOption func(*MetricsAwareStorage)

func WithSlowQueryThreshold(threshold time.Duration) MetricsAwareStorageOption {
	return func(s *MetricsAwareStorage) {
		s.slowQueryThreshold = threshold
	}
}

func NewMetricsAwareStorage(inner common.IndexerStorage, m common.IndexerMonitoring, l logger.Logger, opts ...MetricsAwareStorageOption) *MetricsAwareStorage {
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

func WrapWithMetrics(inner common.IndexerStorage, m common.IndexerMonitoring, l logger.Logger, opts ...MetricsAwareStorageOption) common.IndexerStorage {
	return NewMetricsAwareStorage(inner, m, l, opts...)
}

func (s *MetricsAwareStorage) GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error) {
	return captureMetrics(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opGetCCVData, func() ([]common.VerifierResultWithMetadata, error) {
		return s.inner.GetCCVData(ctx, messageID)
	})
}

func (s *MetricsAwareStorage) QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]common.VerifierResultWithMetadata, error) {
	return captureMetrics(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opQueryCCVData, func() (map[string][]common.VerifierResultWithMetadata, error) {
		return s.inner.QueryCCVData(ctx, start, end, sourceChainSelectors, destChainSelectors, limit, offset)
	})
}

func (s *MetricsAwareStorage) InsertVerifierResults(ctx context.Context, verifierResults []common.VerifierResultWithMetadata) error {
	return captureMetricsNoReturn(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opInsertVerifierResults, func() error {
		return s.inner.InsertVerifierResults(ctx, verifierResults)
	})
}

func (s *MetricsAwareStorage) GetMessage(ctx context.Context, messageID protocol.Bytes32) (common.MessageWithMetadata, error) {
	return captureMetrics(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opGetMessage, func() (common.MessageWithMetadata, error) {
		return s.inner.GetMessage(ctx, messageID)
	})
}

func (s *MetricsAwareStorage) QueryMessages(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) ([]common.MessageWithMetadata, error) {
	return captureMetrics(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opQueryMessages, func() ([]common.MessageWithMetadata, error) {
		return s.inner.QueryMessages(ctx, start, end, sourceChainSelectors, destChainSelectors, limit, offset)
	})
}

func (s *MetricsAwareStorage) UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status common.MessageStatus, lastErr string) error {
	return captureMetricsNoReturn(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opUpdateMessageStatus, func() error {
		return s.inner.UpdateMessageStatus(ctx, messageID, status, lastErr)
	})
}

func (s *MetricsAwareStorage) CreateDiscoveryState(ctx context.Context, discoveryLocation string, startingSequenceNumber int) error {
	return captureMetricsNoReturn(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opCreateDiscoveryState, func() error {
		return s.inner.CreateDiscoveryState(ctx, discoveryLocation, startingSequenceNumber)
	})
}

func (s *MetricsAwareStorage) GetDiscoverySequenceNumber(ctx context.Context, discoveryLocation string) (int, error) {
	return captureMetrics(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opGetDiscoverySequence, func() (int, error) {
		return s.inner.GetDiscoverySequenceNumber(ctx, discoveryLocation)
	})
}

func (s *MetricsAwareStorage) PersistDiscoveryBatch(ctx context.Context, batch common.DiscoveryBatch) error {
	return captureMetricsNoReturn(ctx, s.m.Metrics(), s.l, s.slowQueryThreshold, opPersistDiscoveryBatch, func() error {
		return s.inner.PersistDiscoveryBatch(ctx, batch)
	})
}

func captureMetrics[T any](ctx context.Context, metrics common.IndexerMetricLabeler, l logger.Logger, threshold time.Duration, operation string, fn func() (T, error)) (T, error) {
	start := time.Now()

	res, err := fn()

	duration := time.Since(start)
	metrics.RecordStorageLatency(ctx, operation, duration, err != nil)
	if duration > threshold {
		l.Warnw("Slow storage operation", "operation", operation, "duration_ms", duration.Milliseconds())
	}

	if err != nil {
		metrics.IncrementStorageError(ctx, operation)
	}

	return res, err
}

func captureMetricsNoReturn(ctx context.Context, metrics common.IndexerMetricLabeler, l logger.Logger, threshold time.Duration, operation string, fn func() error) error {
	_, err := captureMetrics(ctx, metrics, l, threshold, operation, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
