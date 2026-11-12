package aggregation

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/quorum"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

func exportableAggregationFixture(t *testing.T, ctx context.Context) (
	exportConfig *model.AggregatorConfig,
	blockedConfig *model.AggregatorConfig,
	records []*model.CommitVerificationRecord,
	msgID model.MessageID,
	aggKey model.AggregationKey,
) {
	t.Helper()
	sourceVerifierAddress, destVerifierAddress := testutil.GenerateVerifierAddresses(t)
	signer := testutil.NewSignerFixture(t, "n1")
	exportCommittee := testutil.NewCommitteeFixture(sourceVerifierAddress, destVerifierAddress, signer.Signer)
	testutil.UpdateCommitteeQuorumWithThreshold(exportCommittee, sourceVerifierAddress, 1, signer.Signer)

	blockedCommittee := &model.Committee{}
	testutil.UpdateCommitteeQuorumWithThreshold(blockedCommittee, sourceVerifierAddress, 1, signer.Signer)
	blockedCommittee.DestinationVerifiers = map[string]string{
		"999": ethcommon.BytesToAddress(destVerifierAddress).Hex(),
	}
	require.NoError(t, (&model.AggregatorConfig{Committee: blockedCommittee}).ValidateCommitteeConfig())

	agg := model.AggregationConfig{BackgroundWorkerCount: 1}
	exportConfig = &model.AggregatorConfig{Committee: exportCommittee, Aggregation: agg}
	blockedConfig = &model.AggregatorConfig{Committee: blockedCommittee, Aggregation: agg}

	validator := quorum.NewQuorumValidator(exportConfig, logger.Sugared(logger.Test(t)))
	message := testutil.NewProtocolMessage(t)
	protoMsg, msgFull := testutil.NewMessageWithCCVNodeData(t, message, sourceVerifierAddress, testutil.WithSignatureFrom(t, signer))
	record, err := model.CommitVerificationRecordFromProto(protoMsg)
	require.NoError(t, err)
	sigResult, err := validator.ValidateSignature(ctx, record)
	require.NoError(t, err)
	record.SignerIdentifier = sigResult.Signer
	aggKey, err = validator.DeriveAggregationKey(ctx, record)
	require.NoError(t, err)
	return exportConfig, blockedConfig, []*model.CommitVerificationRecord{record}, msgFull[:], aggKey
}

func TestShouldSkipAggregationDueToExistingQuorum(t *testing.T) {
	messageID := model.MessageID{1, 2, 3}
	aggregationKey := model.AggregationKey("test-agg-key")

	t.Run("should not skip when aggregated store is nil", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				BackgroundWorkerCount: 1,
			},
		}

		queue := newFakeQueue()
		aggregator := NewCommitReportAggregator(
			store,
			nil,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			queue,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when no existing report", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(nil, common.ErrNotFound)

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				BackgroundWorkerCount: 1,
			},
		}

		queue := newFakeQueue()
		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			queue,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should skip when existing report meets quorum", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				BackgroundWorkerCount: 1,
			},
		}

		existingReport := &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggregationKey,
			Verifications:  []*model.CommitVerificationRecord{},
		}

		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(true, nil)

		queue := newFakeQueue()
		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			queue,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.True(t, shouldSkip)
		quorum.AssertExpectations(t)
	})

	t.Run("should not skip when existing report does not meet quorum", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				BackgroundWorkerCount: 1,
			},
		}

		existingReport := &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggregationKey,
			Verifications:  []*model.CommitVerificationRecord{},
		}

		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, nil)

		queue := newFakeQueue()
		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			queue,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when GetCommitAggregatedReportByAggregationKey errors", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(nil, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
		shouldSkip := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when quorum check errors", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		existingReport := &model.CommitAggregatedReport{MessageID: messageID, AggregationKey: aggregationKey}
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
		shouldSkip := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when no report exists for requested aggregation key", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(nil, common.ErrNotFound)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
		shouldSkip := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})
}

func TestHealthCheck(t *testing.T) {
	cases := []struct {
		name           string
		stopped        bool
		notStarted     bool
		wantReadyError bool
		wantMsgPrefix  string
	}{
		{name: "healthy", wantReadyError: false},
		{name: "stopped", stopped: true, wantReadyError: true, wantMsgPrefix: "aggregation worker stopped"},
		{name: "not_started", notStarted: true, wantReadyError: true, wantMsgPrefix: "aggregation worker not started"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := mocks.NewMockCommitVerificationStore(t)
			sink := mocks.NewMockSink(t)
			monitoring := mocks.NewMockAggregatorMonitoring(t)
			testutil.StubTracing(monitoring)
			metric := mocks.NewMockAggregatorMetricLabeler(t)
			monitoring.EXPECT().Metrics().Return(metric).Maybe()

			config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
			a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, newFakeQueue())

			if tc.stopped {
				a.done = make(chan struct{})
				close(a.done)
			} else if !tc.notStarted {
				a.done = make(chan struct{})
			}

			err := a.Ready()
			if tc.wantReadyError {
				assert.Error(t, err)
				assert.Equal(t, tc.wantMsgPrefix, err.Error())
			}
		})
	}
}

func TestCheckAggregation_Publishes(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(monitoring)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
	queue := newFakeQueue()
	a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, queue)

	require.NoError(t, a.CheckAggregation(t.Context(), model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "test-key"}))

	size, err := queue.Size(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, size)
}

func TestCheckAggregationAndSubmitComplete(t *testing.T) {
	ctx := t.Context()
	msgID := model.MessageID{0x1}
	aggregationKey := "key"

	request := aggregationRequest{
		MessageID:      msgID,
		AggregationKey: aggregationKey,
	}

	exportConfig, blockedConfig, exportRecords, exportMsgID, exportAggKey := exportableAggregationFixture(t, ctx)
	exportRequest := aggregationRequest{
		MessageID:      exportMsgID,
		AggregationKey: exportAggKey,
	}

	t.Run("list error", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, msgID, aggregationKey).Return(nil, errors.New("boom"))

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, mocks.NewMockSink(t), mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum error", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, errors.New("boom")).Maybe()

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, mocks.NewMockSink(t), quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum met submits and records metrics", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, exportMsgID, exportAggKey).Return(exportRecords, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(true, nil).Maybe()
		sink := mocks.NewMockSink(t)
		sink.EXPECT().SubmitAggregatedReport(mock.Anything, mock.Anything).Return(true, nil)

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With("component", "aggregator_worker").Return(metric).Maybe()
		metric.EXPECT().IncrementCompletedAggregations(mock.Anything)
		metric.EXPECT().RecordTimeToAggregation(mock.Anything, mock.Anything)

		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, sink, quorum, exportConfig, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, exportRequest)
		require.NoError(t, err)
	})

	t.Run("quorum met submit error", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, exportMsgID, exportAggKey).Return(exportRecords, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(true, nil).Maybe()
		sink := mocks.NewMockSink(t)
		sink.EXPECT().SubmitAggregatedReport(mock.Anything, mock.Anything).Return(false, errors.New("boom"))

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With("component", "aggregator_worker").Return(metric).Maybe()

		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, sink, quorum, exportConfig, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, exportRequest)
		require.Error(t, err)
	})

	t.Run("quorum met_missing_destination_increments_blocked_unexportable_and_does_not_submit", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, exportMsgID, exportAggKey).Return(exportRecords, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(true, nil).Maybe()
		sink := mocks.NewMockSink(t)

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With("component", "aggregator_worker").Return(metric).Maybe()
		metric.EXPECT().IncrementAggregationsBlockedUnexportable(mock.Anything)

		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, sink, quorum, blockedConfig, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, exportRequest)
		require.NoError(t, err)
	})

	t.Run("quorum met_nil_committee_increments_blocked_unexportable_and_does_not_submit", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, exportMsgID, exportAggKey).Return(exportRecords, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(true, nil).Maybe()
		sink := mocks.NewMockSink(t)

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With("component", "aggregator_worker").Return(metric).Maybe()
		metric.EXPECT().IncrementAggregationsBlockedUnexportable(mock.Anything)

		config := &model.AggregatorConfig{Aggregation: exportConfig.Aggregation}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, exportRequest)
		require.NoError(t, err)
	})

	t.Run("quorum not met", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(storage, nil, mocks.NewMockSink(t), quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.NoError(t, err)
	})
}

func TestHealthCheck_ReportsStoppedAfterContextCancellation(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(monitoring)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
	queue := newFakeQueue()
	a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, queue)

	ctx, cancel := context.WithCancel(t.Context())
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	cancel()

	require.Eventually(t, func() bool {
		return a.Ready() != nil
	}, 2*time.Second, 10*time.Millisecond)
	err := a.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped")
}

func TestHealthCheck_RecoversPanicEmitsMetricAndKeepsRunning(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(monitoring)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()
	metric.EXPECT().IncrementPanics(mock.Anything).Times(1)

	panicCount := 0
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) {
			panicCount++
			if panicCount == 1 {
				panic("simulated panic in storage")
			}
		}).Return([]*model.CommitVerificationRecord{}, nil).Maybe()

	quorum := mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
	queue := newFakeQueue()
	a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)

	ctx, cancel := context.WithCancel(t.Context())
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	// First request panics
	_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{1, 2, 3}, AggregationKey: "test-key"})
	time.Sleep(100 * time.Millisecond)

	// Still healthy after panic - we now emit metrics instead of tracking consecutive panics
	require.NoError(t, a.Ready())

	// Second request succeeds
	_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{4, 5, 6}, AggregationKey: "test-key-2"})
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, a.Ready())

	cancel()
	require.Eventually(t, func() bool {
		return a.Ready() != nil
	}, tests.WaitTimeout(t), 10*time.Millisecond, "aggregator should shut down before test exits")
}

func TestHealthCheck_ReturnsErrorAfterConsecutiveWorkerFailures(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(monitoring)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()

	var listCallCount atomic.Int32
	storageErr := errors.New("storage error")
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
			callNum := listCallCount.Add(1)
			if callNum <= 3 {
				return nil, storageErr
			}
			return []*model.CommitVerificationRecord{}, nil
		}).Maybe()

	quorum := mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

	config := &model.AggregatorConfig{
		Aggregation: model.AggregationConfig{
			BackgroundWorkerCount: 1,
			MaxConsecutiveErrors:  3,
		},
	}
	queue := newFakeQueue()
	a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)

	ctx, cancel := context.WithCancel(t.Context())
	a.StartBackground(ctx)

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, a.Ready(), "should be ready after start")

	_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "key-1"})
	_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{2}, AggregationKey: "key-2"})
	_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{3}, AggregationKey: "key-3"})

	require.Eventually(t, func() bool {
		err := a.Ready()
		return err != nil
	}, 5*time.Second, 20*time.Millisecond, "Ready() should return error after 3 consecutive worker failures")

	err := a.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "times in a row")

	_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{4}, AggregationKey: "key-4"})

	require.Eventually(t, func() bool {
		return a.Ready() == nil
	}, 5*time.Second, 20*time.Millisecond, "Ready() should return nil again after a successful aggregation")

	cancel()
	require.Eventually(t, func() bool {
		return a.Ready() != nil
	}, tests.WaitTimeout(t), 10*time.Millisecond, "aggregator should shut down before test exits")
}

func TestStartBackground_Shutdown(t *testing.T) {
	t.Run("drains in-flight workers and leaves unclaimed jobs pending", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()
		metric.EXPECT().IncrementCompletedAggregations(mock.Anything).Maybe()
		metric.EXPECT().RecordTimeToAggregation(mock.Anything, mock.Anything).Maybe()

		var processedCount atomic.Int32
		workerDelay := make(chan struct{})
		store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
				<-workerDelay
				processedCount.Add(1)
				return []*model.CommitVerificationRecord{}, nil
			}).Maybe()

		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 2, DrainTimeout: 5 * time.Second}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)

		ctx, cancel := context.WithCancel(t.Context())
		a.StartBackground(ctx)

		_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "key-1"})
		_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{2}, AggregationKey: "key-2"})
		_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{3}, AggregationKey: "key-3"})

		time.Sleep(50 * time.Millisecond)
		require.Equal(t, int32(0), processedCount.Load(), "no requests should be processed before drain")
		cancel()
		close(workerDelay)

		require.Eventually(t, func() bool {
			return a.Ready() != nil
		}, 5*time.Second, 10*time.Millisecond, "aggregator should signal done after drain")

		require.Equal(t, int32(2), processedCount.Load(), "both in-flight requests should finish during drain")
		size, err := queue.Size(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, size, "the unclaimed request stays queued for the next replica")
	})

	t.Run("in-flight worker completes with valid context after cancellation", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()

		workerStarted := make(chan struct{})
		var ctxWasCancelled atomic.Bool
		store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(ctx context.Context, _ model.MessageID, _ model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
				close(workerStarted)
				time.Sleep(100 * time.Millisecond)
				ctxWasCancelled.Store(ctx.Err() != nil)
				return []*model.CommitVerificationRecord{}, nil
			})

		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1, DrainTimeout: 5 * time.Second}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)

		ctx, cancel := context.WithCancel(t.Context())
		a.StartBackground(ctx)

		_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "key-1"})

		<-workerStarted
		cancel()

		require.Eventually(t, func() bool {
			return a.Ready() != nil
		}, 5*time.Second, 10*time.Millisecond)

		require.False(t, ctxWasCancelled.Load(), "worker context should not be cancelled (WithoutCancel)")
	})

	t.Run("drain timeout forces immediate shutdown dropping in-flight work", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()

		workerStarted := make(chan struct{})
		workerRelease := make(chan struct{})
		store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(ctx context.Context, _ model.MessageID, _ model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
				close(workerStarted)
				select {
				case <-workerRelease:
					return []*model.CommitVerificationRecord{}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})

		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1, DrainTimeout: 50 * time.Millisecond}}
		queue := newFakeQueue()
		// Nop logger: the abandoned worker keeps logging after the test returns.
		a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Nop()), monitoring, queue)

		ctx, cancel := context.WithCancel(t.Context())
		a.StartBackground(ctx)

		_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "key-1"})
		<-workerStarted
		cancel()

		require.Eventually(t, func() bool {
			return a.Ready() != nil
		}, 2*time.Second, 10*time.Millisecond, "done should close after drain timeout even with in-flight work")

		close(workerRelease)
	})

	t.Run("worker errors during drain are logged and shutdown completes", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()

		store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
			Return(nil, errors.New("storage unavailable")).Maybe()

		quorum := mocks.NewMockQuorumValidator(t)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1, DrainTimeout: 5 * time.Second}}
		queue := newFakeQueue()
		a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)

		ctx, cancel := context.WithCancel(t.Context())
		a.StartBackground(ctx)

		_ = a.CheckAggregation(ctx, model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "key-1"})

		time.Sleep(50 * time.Millisecond)
		cancel()

		require.Eventually(t, func() bool {
			return a.Ready() != nil
		}, 5*time.Second, 10*time.Millisecond, "aggregator should shut down cleanly despite worker errors")
	})
}

// TestStartBackground_ClaimsOnlyFreeWorkerSlots checks claims never exceed free workers and
// that a freed slot picks up the backlog without waiting for the fallback tick.
func TestStartBackground_ClaimsOnlyFreeWorkerSlots(t *testing.T) {
	const workers, jobs = 2, 6
	release := make(chan struct{})
	var started atomic.Int64

	store := mocks.NewMockCommitVerificationStore(t)
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, model.MessageID, model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
			started.Add(1)
			<-release
			return nil, nil
		})
	quorum := mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(monitoring)
	monitoring.EXPECT().Metrics().Return(mocks.NewMockAggregatorMetricLabeler(t)).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: workers}}
	queue := newFakeQueue()
	a := NewCommitReportAggregator(store, nil, mocks.NewMockSink(t), quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)
	for i := range jobs {
		require.NoError(t, a.CheckAggregation(t.Context(), model.AggregationTrigger{MessageID: []byte{byte(i)}, AggregationKey: fmt.Sprintf("key-%d", i)}))
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a.StartBackground(ctx)

	require.Eventually(t, func() bool { return started.Load() == workers }, 5*time.Second, 10*time.Millisecond)
	size, err := queue.Size(t.Context())
	require.NoError(t, err)
	assert.Equal(t, jobs-workers, size, "jobs beyond the free slots must stay pending")

	close(release)
	require.Eventually(t, func() bool { return started.Load() == jobs }, 5*time.Second, 10*time.Millisecond)
	for _, claim := range queue.claimSizes() {
		assert.LessOrEqual(t, claim, workers)
	}
}

func TestCheckAggregation_EnqueuesOnlyKeysAtQuorumThreshold(t *testing.T) {
	newAggregator := func(t *testing.T, store *mocks.MockCommitVerificationStore) (*CommitReportAggregator, *fakeQueue) {
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		monitoring.EXPECT().Metrics().Return(mocks.NewMockAggregatorMetricLabeler(t)).Maybe()
		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1},
			Committee:   &model.Committee{QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{"1": {Threshold: 2}}},
		}
		queue := newFakeQueue()
		return NewCommitReportAggregator(store, nil, mocks.NewMockSink(t), mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, queue), queue
	}
	triggers := []model.AggregationTrigger{
		{MessageID: []byte{1}, AggregationKey: "below-threshold"},
		{MessageID: []byte{2}, AggregationKey: "at-threshold"},
		{MessageID: []byte{3}, AggregationKey: "unknown-chain"},
		{MessageID: []byte{4}, AggregationKey: "no-rows"},
	}
	queued := func(q *fakeQueue) []model.AggregationKey {
		jobs, err := q.ConsumePending(t.Context(), 10)
		require.NoError(t, err)
		keys := make([]model.AggregationKey, 0, len(jobs))
		for _, j := range jobs {
			keys = append(keys, j.Payload.AggregationKey)
		}
		return keys
	}

	t.Run("drops keys below their chain's threshold", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		store.EXPECT().CountSigners(mock.Anything, triggers).Return(map[model.AggregationKey]model.SignerCount{
			"below-threshold": {Signers: 1, SourceChainSelector: 1},
			"at-threshold":    {Signers: 2, SourceChainSelector: 1},
			"unknown-chain":   {Signers: 1, SourceChainSelector: 99},
		}, nil)
		a, q := newAggregator(t, store)
		require.NoError(t, a.CheckAggregation(t.Context(), triggers...))
		assert.Equal(t, []model.AggregationKey{"at-threshold", "unknown-chain"}, queued(q))
	})

	t.Run("enqueues every trigger when counting fails", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		store.EXPECT().CountSigners(mock.Anything, triggers).Return(nil, errors.New("db down"))
		a, q := newAggregator(t, store)
		require.NoError(t, a.CheckAggregation(t.Context(), triggers...))
		assert.Len(t, queued(q), len(triggers))
	})
}

func TestReady_ReportsRepeatedQueueClaimFailures(t *testing.T) {
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	testutil.StubTracing(monitoring)
	monitoring.EXPECT().Metrics().Return(mocks.NewMockAggregatorMetricLabeler(t)).Maybe()
	store := mocks.NewMockCommitVerificationStore(t)
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	quorum := mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()
	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1, MaxConsecutiveErrors: 2}}
	queue := newFakeQueue()
	queue.setConsumeErr(errors.New("database is read-only"))
	a := NewCommitReportAggregator(store, nil, mocks.NewMockSink(t), quorum, config, logger.Sugared(logger.Test(t)), monitoring, queue)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a.StartBackground(ctx)
	trigger := model.AggregationTrigger{MessageID: []byte{1}, AggregationKey: "key"}

	require.Eventually(t, func() bool {
		_ = a.CheckAggregation(ctx, trigger)
		return a.Ready() != nil
	}, 5*time.Second, 20*time.Millisecond, "repeated claim failures must make the aggregator not ready")
	assert.ErrorContains(t, a.Ready(), "aggregation queue claim failed")

	queue.setConsumeErr(nil)
	require.Eventually(t, func() bool {
		_ = a.CheckAggregation(ctx, trigger)
		return a.Ready() == nil
	}, 5*time.Second, 20*time.Millisecond, "a successful claim must clear the failure count")
}
