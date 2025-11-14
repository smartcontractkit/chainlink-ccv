package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
)

type fakeInnerStorage struct {
	saveErr   error
	getRes    *model.CommitVerificationRecord
	getErr    error
	listRes   []*model.CommitVerificationRecord
	listErr   error
	queryRes  *model.PaginatedAggregatedReports
	queryErr  error
	ccvRes    *model.CommitAggregatedReport
	ccvErr    error
	batchRes  map[string]*model.CommitAggregatedReport
	batchErr  error
	submitErr error
	// orphaning
	orphanIDs []model.MessageID
	orphanErr error
}

func (f *fakeInnerStorage) SaveCommitVerification(ctx context.Context, record *model.CommitVerificationRecord) error {
	return f.saveErr
}

func (f *fakeInnerStorage) GetCommitVerification(ctx context.Context, id model.CommitVerificationRecordIdentifier) (*model.CommitVerificationRecord, error) {
	return f.getRes, f.getErr
}

func (f *fakeInnerStorage) ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID, committee string) ([]*model.CommitVerificationRecord, error) {
	return f.listRes, f.listErr
}

func (f *fakeInnerStorage) QueryAggregatedReports(ctx context.Context, start int64, committeeID string, token *string) (*model.PaginatedAggregatedReports, error) {
	return f.queryRes, f.queryErr
}

func (f *fakeInnerStorage) GetCCVData(ctx context.Context, messageID model.MessageID, committeeID string) (*model.CommitAggregatedReport, error) {
	return f.ccvRes, f.ccvErr
}

func (f *fakeInnerStorage) GetBatchCCVData(ctx context.Context, messageIDs []model.MessageID, committeeID string) (map[string]*model.CommitAggregatedReport, error) {
	return f.batchRes, f.batchErr
}

func (f *fakeInnerStorage) SubmitReport(ctx context.Context, report *model.CommitAggregatedReport) error {
	return f.submitErr
}

func (f *fakeInnerStorage) ListOrphanedMessageIDs(ctx context.Context, committeeID model.CommitteeID) (<-chan model.MessageID, <-chan error) {
	outIDs := make(chan model.MessageID, 1)
	outErrs := make(chan error, 1)
	go func() {
		defer close(outIDs)
		// Send any configured ids
		for _, id := range f.orphanIDs {
			outIDs <- id
		}
		if f.orphanErr != nil {
			outErrs <- f.orphanErr
		}
		// Do not close outErrs: mirrors production interface behavior
	}()
	return outIDs, outErrs
}

func setupMetricsMocks(t *testing.T) (*aggregation_mocks.MockAggregatorMetricLabeler, *aggregation_mocks.MockAggregatorMonitoring) {
	t.Helper()
	metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	// Any With(...), return itself to allow chaining
	metric.On("With", mock.Anything, mock.Anything).Return(metric).Maybe()
	metric.On("RecordStorageLatency", mock.Anything, mock.Anything).Maybe()
	metric.On("IncrementStorageError", mock.Anything).Maybe()

	mon := aggregation_mocks.NewMockAggregatorMonitoring(t)
	mon.EXPECT().Metrics().Return(metric).Maybe()
	return metric, mon
}

func TestMetricsAwareStorage_SuccessPaths(t *testing.T) {
	metric, mon := setupMetricsMocks(t)
	// We'll count RecordStorageLatency calls after invoking all success paths
	inner := &fakeInnerStorage{
		getRes:   &model.CommitVerificationRecord{},
		listRes:  []*model.CommitVerificationRecord{},
		queryRes: &model.PaginatedAggregatedReports{},
		ccvRes:   &model.CommitAggregatedReport{},
		batchRes: map[string]*model.CommitAggregatedReport{},
	}
	s := NewMetricsAwareStorage(inner, mon)

	ctx := context.Background()
	_ = s.SaveCommitVerification(ctx, &model.CommitVerificationRecord{})
	_, _ = s.GetCommitVerification(ctx, model.CommitVerificationRecordIdentifier{})
	_, _ = s.ListCommitVerificationByMessageID(ctx, make([]byte, 0), "c")
	_, _ = s.QueryAggregatedReports(ctx, time.Now().Unix(), "c", nil)
	_, _ = s.GetCCVData(ctx, make([]byte, 0), "c")
	_, _ = s.GetBatchCCVData(ctx, []model.MessageID{}, "c")
	_ = s.SubmitReport(ctx, &model.CommitAggregatedReport{})

	// 7 operations should each record latency once
	metric.AssertNumberOfCalls(t, "RecordStorageLatency", 7)
	metric.AssertNumberOfCalls(t, "IncrementStorageError", 0)
}

func TestMetricsAwareStorage_ErrorPaths(t *testing.T) {
	metric, mon := setupMetricsMocks(t)
	inner := &fakeInnerStorage{
		saveErr:   errors.New("save err"),
		getErr:    errors.New("get err"),
		listErr:   errors.New("list err"),
		queryErr:  errors.New("query err"),
		ccvErr:    errors.New("ccv err"),
		batchErr:  errors.New("batch err"),
		submitErr: errors.New("submit err"),
	}
	s := NewMetricsAwareStorage(inner, mon)

	ctx := context.Background()
	_ = s.SaveCommitVerification(ctx, &model.CommitVerificationRecord{})
	_, _ = s.GetCommitVerification(ctx, model.CommitVerificationRecordIdentifier{})
	_, _ = s.ListCommitVerificationByMessageID(ctx, make([]byte, 0), "c")
	_, _ = s.QueryAggregatedReports(ctx, time.Now().Unix(), "c", nil)
	_, _ = s.GetCCVData(ctx, make([]byte, 0), "c")
	_, _ = s.GetBatchCCVData(ctx, []model.MessageID{}, "c")
	_ = s.SubmitReport(ctx, &model.CommitAggregatedReport{})

	// 7 latency + 7 errors
	metric.AssertNumberOfCalls(t, "RecordStorageLatency", 7)
	metric.AssertNumberOfCalls(t, "IncrementStorageError", 7)
}

func TestMetricsAwareStorage_ListOrphanedMessageIDs_ProxiesAndRecordsLatency(t *testing.T) {
	metric, mon := setupMetricsMocks(t)
	// One orphan id and no error
	inner := &fakeInnerStorage{
		orphanIDs: []model.MessageID{[]byte{0x01}},
	}
	s := NewMetricsAwareStorage(inner, mon)

	ctx := context.Background()
	ids, errs := s.ListOrphanedMessageIDs(ctx, "committee-1")

	got := make([]model.MessageID, 0, 1)
	for id := range ids {
		got = append(got, id)
	}
	// Allow deferred metric recording to run after goroutine exit
	time.Sleep(10 * time.Millisecond)
	select {
	case <-errs:
		// ignore; not expected but channel may have residual
	default:
	}

	assert.Equal(t, 1, len(got))
	// Latency should be recorded once when the goroutine exits
	metric.AssertNumberOfCalls(t, "RecordStorageLatency", 1)
}
