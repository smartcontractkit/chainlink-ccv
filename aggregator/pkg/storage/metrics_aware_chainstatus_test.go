package storage

import (
	"context"
	"errors"
	"testing"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/stretchr/testify/mock"
)

type fakeChainStatusStorage struct {
	storeErr   error
	getMap     map[uint64]*common.ChainStatus
	getErr     error
	clients    []string
	clientsErr error
}

func (f *fakeChainStatusStorage) StoreChainStatus(ctx context.Context, clientID string, chainStatuses map[uint64]*common.ChainStatus) error {
	return f.storeErr
}
func (f *fakeChainStatusStorage) GetClientChainStatus(ctx context.Context, clientID string) (map[uint64]*common.ChainStatus, error) {
	return f.getMap, f.getErr
}
func (f *fakeChainStatusStorage) GetAllClients(ctx context.Context) ([]string, error) {
	return f.clients, f.clientsErr
}

func setupChainStatusMetricMocks(t *testing.T) (*aggregation_mocks.MockAggregatorMetricLabeler, *aggregation_mocks.MockAggregatorMonitoring) {
	t.Helper()
	metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	metric.On("With", mock.Anything, mock.Anything).Return(metric).Maybe()
	metric.On("RecordStorageLatency", mock.Anything, mock.Anything).Maybe()
	metric.On("IncrementStorageError", mock.Anything).Maybe()

	mon := aggregation_mocks.NewMockAggregatorMonitoring(t)
	mon.EXPECT().Metrics().Return(metric).Maybe()
	return metric, mon
}

func TestMetricsAwareChainStatusStorage_SuccessPaths(t *testing.T) {
	metric, mon := setupChainStatusMetricMocks(t)
	inner := &fakeChainStatusStorage{
		getMap:  map[uint64]*common.ChainStatus{},
		clients: []string{"a", "b"},
	}
	s := NewMetricsAwareChainStatusStorage(inner, mon)

	ctx := context.Background()
	_ = s.StoreChainStatus(ctx, "client", map[uint64]*common.ChainStatus{})
	_, _ = s.GetClientChainStatus(ctx, "client")
	_, _ = s.GetAllClients(ctx)

	metric.AssertNumberOfCalls(t, "RecordStorageLatency", 3)
	metric.AssertNumberOfCalls(t, "IncrementStorageError", 0)
}

func TestMetricsAwareChainStatusStorage_ErrorPaths(t *testing.T) {
	metric, mon := setupChainStatusMetricMocks(t)
	inner := &fakeChainStatusStorage{
		storeErr:   errors.New("store err"),
		getErr:     errors.New("get err"),
		clientsErr: errors.New("clients err"),
	}
	s := NewMetricsAwareChainStatusStorage(inner, mon)

	ctx := context.Background()
	_ = s.StoreChainStatus(ctx, "client", map[uint64]*common.ChainStatus{})
	_, _ = s.GetClientChainStatus(ctx, "client")
	_, _ = s.GetAllClients(ctx)

	metric.AssertNumberOfCalls(t, "RecordStorageLatency", 3)
	metric.AssertNumberOfCalls(t, "IncrementStorageError", 3)
}
