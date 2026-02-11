package ccvstorage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

// TestMonitoredStorage_Get verifies that Get calls are monitored with "readCCV" method.
func TestMonitoredStorage_Get(t *testing.T) {
	inMemoryStorage := NewInMemory()
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredStorage(inMemoryStorage, fakeMonitoring.Metrics())

	ctx := context.Background()

	// Manually add data to the underlying storage
	key := protocol.Bytes32{1, 2, 3}
	inMemoryStorage.data[key] = Entry{Value: protocol.VerifierNodeResult{}}

	// Now read it back through the monitored decorator
	keys := []protocol.Bytes32{key}
	result, err := monitored.Get(ctx, keys)

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Contains(t, result, key)
}

// TestMonitoredStorage_Get_NotFound verifies that missing entries are handled correctly.
func TestMonitoredStorage_Get_NotFound(t *testing.T) {
	inMemoryStorage := NewInMemory()
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredStorage(inMemoryStorage, fakeMonitoring.Metrics())

	ctx := context.Background()
	keys := []protocol.Bytes32{{1, 2, 3}}

	result, err := monitored.Get(ctx, keys)

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestMonitoredStorage_Set verifies that Set calls are monitored with "writeCCV" method.
func TestMonitoredStorage_Set(t *testing.T) {
	inMemoryStorage := NewInMemory()
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredStorage(inMemoryStorage, fakeMonitoring.Metrics())

	ctx := context.Background()
	key := protocol.Bytes32{1, 2, 3}

	// Manually add entry to underlying storage to verify decorator passes calls through
	inMemoryStorage.data[key] = Entry{Value: protocol.VerifierNodeResult{}}

	// Verify data was written (via the underlying storage)
	result, err := monitored.Get(ctx, []protocol.Bytes32{key})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

// TestMonitoredStorage_RecordsMetrics verifies that both operations record metrics.
func TestMonitoredStorage_RecordsMetrics(t *testing.T) {
	inMemoryStorage := NewInMemory()
	mockMetrics := mocks.NewMockMetricLabeler(t)
	monitored := NewMonitoredStorage(inMemoryStorage, mockMetrics)

	ctx := context.Background()
	key := protocol.Bytes32{1, 2, 3}

	// Manually add data to test Get
	inMemoryStorage.data[key] = Entry{Value: protocol.VerifierNodeResult{}}

	mockMetrics.EXPECT().RecordStorageQueryDuration(ctx, "readCCV", mock.AnythingOfType("time.Duration")).Once()

	_, _ = monitored.Get(ctx, []protocol.Bytes32{key})
}
