package verifier_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// mockHeartbeatClient is a mock implementation of heartbeatclient.HeartbeatSender for testing.
type mockHeartbeatClient struct {
	mock.Mock
}

func (m *mockHeartbeatClient) SendHeartbeat(ctx context.Context, blockHeightsByChain map[uint64]uint64) (heartbeatclient.HeartbeatResponse, error) {
	args := m.Called(ctx, blockHeightsByChain)
	return args.Get(0).(heartbeatclient.HeartbeatResponse), args.Error(1)
}

func (m *mockHeartbeatClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewHeartbeatReporter_Success(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1, 10, 100}

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		10*time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, reporter)
}

func TestNewHeartbeatReporter_NilLogger(t *testing.T) {
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)
	selectors := []protocol.ChainSelector{1}

	_, err := verifier.NewHeartbeatReporter(
		nil,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		10*time.Second,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger cannot be nil")
}

func TestNewHeartbeatReporter_NilChainStatusManager(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	selectors := []protocol.ChainSelector{1}

	_, err := verifier.NewHeartbeatReporter(
		lggr,
		nil,
		mockClient,
		selectors,
		"test-verifier",
		10*time.Second,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chainStatusManager cannot be nil")
}

func TestNewHeartbeatReporter_NilHeartbeatClient(t *testing.T) {
	lggr := logger.Test(t)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)
	selectors := []protocol.ChainSelector{1}

	_, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		nil,
		selectors,
		"test-verifier",
		10*time.Second,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "heartbeatClient cannot be nil")
}

func TestNewHeartbeatReporter_EmptySelectors(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	_, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		[]protocol.ChainSelector{},
		"test-verifier",
		10*time.Second,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allSelectors cannot be empty")
}

func TestNewHeartbeatReporter_EmptyVerifierID(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)
	selectors := []protocol.ChainSelector{1}

	_, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"",
		10*time.Second,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifierID cannot be empty")
}

func TestNewHeartbeatReporter_DefaultInterval(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)
	selectors := []protocol.ChainSelector{1}

	// Create with 0 interval - should use default
	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		0,
	)
	require.NoError(t, err)
	require.NotNil(t, reporter)
}

func TestHeartbeatReporter_StartAndStop(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1, 10}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Setup mock responses
	chainStatusInfo := &protocol.ChainStatusInfo{
		ChainSelector:        1,
		FinalizedBlockHeight: big.NewInt(100),
		Disabled:             false,
	}

	mockStatusMgr.On("ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors).Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
		1:  chainStatusInfo,
		10: chainStatusInfo,
	}, nil)

	mockClient.On("SendHeartbeat", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), mock.MatchedBy(func(blockHeights map[uint64]uint64) bool {
		return len(blockHeights) > 0
	})).Return(heartbeatclient.HeartbeatResponse{
		Timestamp:       time.Now().Unix(),
		AggregatorID:    "test-aggregator",
		ChainBenchmarks: map[uint64]heartbeatclient.ChainBenchmark{},
	}, nil)

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		50*time.Millisecond, // Short interval for testing
	)
	require.NoError(t, err)

	err = reporter.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for the reporter to send a heartbeat
	time.Sleep(100 * time.Millisecond)

	// Stop the reporter
	err = reporter.Close()
	require.NoError(t, err)
}

func TestHeartbeatReporter_SendHeartbeatFailure(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	chainStatusInfo := &protocol.ChainStatusInfo{
		ChainSelector:        1,
		FinalizedBlockHeight: big.NewInt(100),
		Disabled:             false,
	}

	mockStatusMgr.On("ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors).Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
		1: chainStatusInfo,
	}, nil)

	// Mock client returns error
	mockClient.On("SendHeartbeat", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), mock.MatchedBy(func(blockHeights map[uint64]uint64) bool {
		return true
	})).Return(heartbeatclient.HeartbeatResponse{}, errors.New("connection refused"))

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		50*time.Millisecond,
	)
	require.NoError(t, err)

	err = reporter.Start(ctx)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = reporter.Close()
	require.NoError(t, err)
}

func TestHeartbeatReporter_ChainStatusReadError(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Mock status manager returns error
	mockStatusMgr.On("ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors).Return(nil, errors.New("database error"))

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		50*time.Millisecond,
	)
	require.NoError(t, err)

	err = reporter.Start(ctx)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = reporter.Close()
	require.NoError(t, err)

	// Verify that ReadChainStatuses was called at least once
	mockStatusMgr.AssertCalled(t, "ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors)
}

func TestHeartbeatReporter_MultipleChains(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1, 10, 100, 1000}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Setup chain statuses for all selectors
	statusMap := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	for i, selector := range selectors {
		statusMap[selector] = &protocol.ChainStatusInfo{
			ChainSelector:        selector,
			FinalizedBlockHeight: big.NewInt(int64(100 + i*100)),
			Disabled:             false,
		}
	}

	mockStatusMgr.On("ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors).Return(statusMap, nil)

	// Verify the request has all chain heights
	mockClient.On("SendHeartbeat", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), mock.MatchedBy(func(blockHeights map[uint64]uint64) bool {
		return len(blockHeights) == len(selectors)
	})).Return(heartbeatclient.HeartbeatResponse{
		Timestamp:       time.Now().Unix(),
		AggregatorID:    "test-aggregator",
		ChainBenchmarks: map[uint64]heartbeatclient.ChainBenchmark{},
	}, nil)

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		50*time.Millisecond,
	)
	require.NoError(t, err)

	err = reporter.Start(ctx)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = reporter.Close()
	require.NoError(t, err)

	// Verify SendHeartbeat was called with all chains
	mockClient.AssertCalled(t, "SendHeartbeat", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), mock.MatchedBy(func(blockHeights map[uint64]uint64) bool {
		return len(blockHeights) == len(selectors)
	}))
}

func TestHeartbeatReporter_Name(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)
	selectors := []protocol.ChainSelector{1}

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"my-verifier",
		10*time.Second,
	)
	require.NoError(t, err)

	name := reporter.Name()
	assert.Contains(t, name, "my-verifier")
	assert.Contains(t, name, "HeartbeatReporter")
}

func TestHeartbeatReporter_HealthReport(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)
	selectors := []protocol.ChainSelector{1}

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		10*time.Second,
	)
	require.NoError(t, err)

	report := reporter.HealthReport()
	assert.NotNil(t, report)
	assert.Greater(t, len(report), 0)
}

func TestHeartbeatReporter_ContextCancellation(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1}
	ctx, cancel := context.WithCancel(context.Background())

	chainStatusInfo := &protocol.ChainStatusInfo{
		ChainSelector:        1,
		FinalizedBlockHeight: big.NewInt(100),
		Disabled:             false,
	}

	mockStatusMgr.On("ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors).Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
		1: chainStatusInfo,
	}, nil)

	mockClient.On("SendHeartbeat", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), mock.MatchedBy(func(blockHeights map[uint64]uint64) bool {
		return true
	})).Return(heartbeatclient.HeartbeatResponse{
		Timestamp:       time.Now().Unix(),
		AggregatorID:    "test-aggregator",
		ChainBenchmarks: map[uint64]heartbeatclient.ChainBenchmark{},
	}, nil)

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		50*time.Millisecond,
	)
	require.NoError(t, err)

	err = reporter.Start(ctx)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Cancel context - should stop the reporter
	cancel()

	time.Sleep(100 * time.Millisecond)

	err = reporter.Close()
	require.NoError(t, err)
}

func TestHeartbeatReporter_MissingChainStatus(t *testing.T) {
	lggr := logger.Test(t)
	mockClient := new(mockHeartbeatClient)
	mockStatusMgr := mocks.NewMockChainStatusManager(t)

	selectors := []protocol.ChainSelector{1, 10}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Only return status for one chain (not the other)
	statusMap := map[protocol.ChainSelector]*protocol.ChainStatusInfo{
		1: {
			ChainSelector:        1,
			FinalizedBlockHeight: big.NewInt(100),
			Disabled:             false,
		},
	}

	mockStatusMgr.On("ReadChainStatuses", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), selectors).Return(statusMap, nil)

	// Should send heartbeat with only the available chain
	mockClient.On("SendHeartbeat", mock.MatchedBy(func(c context.Context) bool {
		return c != nil
	}), mock.MatchedBy(func(blockHeights map[uint64]uint64) bool {
		// Should only have 1 chain since the other one is missing
		return len(blockHeights) == 1
	})).Return(heartbeatclient.HeartbeatResponse{
		Timestamp:       time.Now().Unix(),
		AggregatorID:    "test-aggregator",
		ChainBenchmarks: map[uint64]heartbeatclient.ChainBenchmark{},
	}, nil)

	reporter, err := verifier.NewHeartbeatReporter(
		lggr,
		mockStatusMgr,
		mockClient,
		selectors,
		"test-verifier",
		50*time.Millisecond,
	)
	require.NoError(t, err)

	err = reporter.Start(ctx)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = reporter.Close()
	require.NoError(t, err)
}
