package chainstatus

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	vmocks "github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
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
	mockMetrics := vmocks.NewMockMetricLabeler(t)
	monitored := NewMonitoredChainStatusManager(mockManager, mockMetrics)

	ctx := context.Background()
	selectors := []protocol.ChainSelector{1}
	statuses := []protocol.ChainStatusInfo{{ChainSelector: 1}}

	mockManager.EXPECT().ReadChainStatuses(ctx, selectors).Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil)
	mockManager.EXPECT().WriteChainStatuses(ctx, statuses).Return(nil)
	mockMetrics.EXPECT().RecordStorageQueryDuration(ctx, "readChainStatus", mock.AnythingOfType("time.Duration")).Once()
	mockMetrics.EXPECT().RecordStorageQueryDuration(ctx, "writeChainStatus", mock.AnythingOfType("time.Duration")).Once()

	_, _ = monitored.ReadChainStatuses(ctx, selectors)
	_ = monitored.WriteChainStatuses(ctx, statuses)
}
