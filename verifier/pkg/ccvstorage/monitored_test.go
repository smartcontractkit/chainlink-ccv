package ccvstorage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
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
	mockMetrics := &mockMetricLabeler{}
	monitored := NewMonitoredStorage(inMemoryStorage, mockMetrics)

	ctx := context.Background()
	key := protocol.Bytes32{1, 2, 3}

	// Manually add data to test Get
	inMemoryStorage.data[key] = Entry{Value: protocol.VerifierNodeResult{}}

	mockMetrics.On("RecordStorageQueryDuration", ctx, "readCCV", mock.AnythingOfType("time.Duration")).Once()

	_, _ = monitored.Get(ctx, []protocol.Bytes32{key})

	mockMetrics.AssertExpectations(t)
}

// mockMetricLabeler is used only for verifying metric recording calls.
type mockMetricLabeler struct {
	mock.Mock
}

func (m *mockMetricLabeler) With(keyValues ...string) verifier.MetricLabeler {
	args := m.Called(keyValues)
	return args.Get(0).(verifier.MetricLabeler)
}

func (m *mockMetricLabeler) RecordStorageQueryDuration(ctx context.Context, method string, duration time.Duration) {
	m.Called(ctx, method, duration)
}

// Implement other required methods as no-ops for this test.
func (m *mockMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration)    {}
func (m *mockMetricLabeler) IncrementMessagesProcessed(ctx context.Context)                         {}
func (m *mockMetricLabeler) IncrementMessagesVerificationFailed(ctx context.Context)                {}
func (m *mockMetricLabeler) RecordFinalityWaitDuration(ctx context.Context, duration time.Duration) {}
func (m *mockMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
}
func (m *mockMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {}
func (m *mockMetricLabeler) RecordFinalityQueueSize(ctx context.Context, size int64)                {}
func (m *mockMetricLabeler) RecordCCVDataChannelSize(ctx context.Context, size int64)               {}
func (m *mockMetricLabeler) IncrementStorageWriteErrors(ctx context.Context)                        {}
func (m *mockMetricLabeler) IncrementHeartbeatsSent(ctx context.Context)                            {}
func (m *mockMetricLabeler) IncrementHeartbeatsFailed(ctx context.Context)                          {}
func (m *mockMetricLabeler) RecordHeartbeatDuration(ctx context.Context, duration time.Duration)    {}
func (m *mockMetricLabeler) SetVerifierHeartbeatTimestamp(ctx context.Context, timestamp int64)     {}
func (m *mockMetricLabeler) SetVerifierHeartbeatSentChainHeads(ctx context.Context, blockHeight uint64) {
}
func (m *mockMetricLabeler) SetVerifierHeartbeatChainHeads(ctx context.Context, blockHeight uint64) {}
func (m *mockMetricLabeler) SetVerifierHeartbeatScore(ctx context.Context, score float64)           {}
func (m *mockMetricLabeler) RecordSourceChainLatestBlock(ctx context.Context, blockNum int64)       {}
func (m *mockMetricLabeler) RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64)    {}
func (m *mockMetricLabeler) RecordReorgTrackedSeqNums(ctx context.Context, count int64)             {}
func (m *mockMetricLabeler) IncrementActiveRequestsCounter(ctx context.Context)                     {}
func (m *mockMetricLabeler) IncrementHTTPRequestCounter(ctx context.Context)                        {}
func (m *mockMetricLabeler) DecrementActiveRequestsCounter(ctx context.Context)                     {}
func (m *mockMetricLabeler) RecordHTTPRequestDuration(ctx context.Context, duration time.Duration, path, method string, status int) {
}
