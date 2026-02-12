package ccvstorage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

var _ CCVStorage = (*MonitoredStorage)(nil)

// MonitoredStorage is a decorator that adds monitoring to CCVStorage operations.
type MonitoredStorage struct {
	storage CCVStorage
	metrics verifier.MetricLabeler
}

// NewMonitoredStorage creates a new MonitoredStorage decorator.
func NewMonitoredStorage(storage CCVStorage, metrics verifier.MetricLabeler) *MonitoredStorage {
	return &MonitoredStorage{
		storage: storage,
		metrics: metrics,
	}
}

// Get retrieves entries and records query duration with method "readCCV".
func (m *MonitoredStorage) Get(ctx context.Context, keys []protocol.Bytes32) (map[protocol.Bytes32]Entry, error) {
	start := time.Now()
	result, err := m.storage.Get(ctx, keys)
	duration := time.Since(start)

	m.metrics.RecordStorageQueryDuration(ctx, "readCCV", duration)

	return result, err
}

// Set stores entries and records query duration with method "writeCCV".
func (m *MonitoredStorage) Set(ctx context.Context, entries []Entry) error {
	start := time.Now()
	err := m.storage.Set(ctx, entries)
	duration := time.Since(start)

	m.metrics.RecordStorageQueryDuration(ctx, "writeCCV", duration)

	return err
}
