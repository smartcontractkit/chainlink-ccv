package chainstatus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

// TestMonitoredChainStatusManager_ReadChainStatuses verifies that read calls are monitored.
func TestMonitoredChainStatusManager_ReadChainStatuses(t *testing.T) {
	mockManager := mocks.NewMockChainStatusManager(t)
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredChainStatusManager(mockManager, fakeMonitoring.Metrics())

	ctx := context.Background()
	selectors := []protocol.ChainSelector{1, 2}
	expectedResult := map[protocol.ChainSelector]*protocol.ChainStatusInfo{
		1: {},
	}

	mockManager.EXPECT().ReadChainStatuses(ctx, selectors).Return(expectedResult, nil)

	result, err := monitored.ReadChainStatuses(ctx, selectors)

	require.NoError(t, err)
	require.Equal(t, expectedResult, result)
}

// TestMonitoredChainStatusManager_ReadChainStatuses_Error verifies errors are propagated.
func TestMonitoredChainStatusManager_ReadChainStatuses_Error(t *testing.T) {
	mockManager := mocks.NewMockChainStatusManager(t)
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredChainStatusManager(mockManager, fakeMonitoring.Metrics())

	ctx := context.Background()
	selectors := []protocol.ChainSelector{1, 2}
	expectedErr := errors.New("read error")

	mockManager.EXPECT().ReadChainStatuses(ctx, selectors).Return(
		map[protocol.ChainSelector]*protocol.ChainStatusInfo(nil), expectedErr)

	result, err := monitored.ReadChainStatuses(ctx, selectors)

	require.Error(t, err)
	require.Equal(t, expectedErr, err)
	require.Nil(t, result)
}

// TestMonitoredChainStatusManager_WriteChainStatuses verifies that write calls are monitored.
func TestMonitoredChainStatusManager_WriteChainStatuses(t *testing.T) {
	mockManager := mocks.NewMockChainStatusManager(t)
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredChainStatusManager(mockManager, fakeMonitoring.Metrics())

	ctx := context.Background()
	statuses := []protocol.ChainStatusInfo{
		{ChainSelector: 1},
	}

	mockManager.EXPECT().WriteChainStatuses(ctx, statuses).Return(nil)

	err := monitored.WriteChainStatuses(ctx, statuses)

	require.NoError(t, err)
}

// TestMonitoredChainStatusManager_WriteChainStatuses_Error verifies errors are propagated.
func TestMonitoredChainStatusManager_WriteChainStatuses_Error(t *testing.T) {
	mockManager := mocks.NewMockChainStatusManager(t)
	fakeMonitoring := monitoring.NewFakeVerifierMonitoring()
	monitored := NewMonitoredChainStatusManager(mockManager, fakeMonitoring.Metrics())

	ctx := context.Background()
	statuses := []protocol.ChainStatusInfo{
		{ChainSelector: 1},
	}
	expectedErr := errors.New("write error")

	mockManager.EXPECT().WriteChainStatuses(ctx, statuses).Return(expectedErr)

	err := monitored.WriteChainStatuses(ctx, statuses)

	require.Error(t, err)
	require.Equal(t, expectedErr, err)
}

// TestMonitoredChainStatusManager_RecordsMetrics verifies both operations record metrics.
func TestMonitoredChainStatusManager_RecordsMetrics(t *testing.T) {
	mockManager := mocks.NewMockChainStatusManager(t)
	mockMetrics := &mockMetricLabeler{}
	monitored := NewMonitoredChainStatusManager(mockManager, mockMetrics)

	ctx := context.Background()
	selectors := []protocol.ChainSelector{1}
	statuses := []protocol.ChainStatusInfo{{ChainSelector: 1}}

	mockManager.EXPECT().ReadChainStatuses(ctx, selectors).Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil)
	mockManager.EXPECT().WriteChainStatuses(ctx, statuses).Return(nil)
	mockMetrics.On("RecordStorageQueryDuration", ctx, "readChainStatus", mock.AnythingOfType("time.Duration")).Once()
	mockMetrics.On("RecordStorageQueryDuration", ctx, "writeChainStatus", mock.AnythingOfType("time.Duration")).Once()

	_, _ = monitored.ReadChainStatuses(ctx, selectors)
	_ = monitored.WriteChainStatuses(ctx, statuses)

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
