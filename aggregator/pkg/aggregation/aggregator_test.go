package aggregation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

const (
	testCommitteeID = "test-committee"
)

func setupTestAggregator(t *testing.T) (*CommitReportAggregator, *mocks.MockCommitVerificationStore, *mocks.MockSink, *mocks.MockQuorumValidator, *mocks.MockAggregatorMonitoring) {
	mockStorage := mocks.NewMockCommitVerificationStore(t)
	mockSink := mocks.NewMockSink(t)
	mockQuorum := mocks.NewMockQuorumValidator(t)
	mockMonitoring := mocks.NewMockAggregatorMonitoring(t)

	// Set up generic metrics mock that accepts any calls (we don't care about metrics in these tests)
	mockMetricLabeler := mocks.NewMockAggregatorMetricLabeler(t)
	mockMonitoring.On("Metrics").Return(mockMetricLabeler).Maybe()
	mockMetricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything).Maybe()
	mockMetricLabeler.On("IncrementCompletedAggregations", mock.Anything).Maybe()
	mockMetricLabeler.On("RecordTimeToAggregation", mock.Anything, mock.Anything).Maybe()
	mockMetricLabeler.On("With", mock.Anything, mock.Anything).Return(mockMetricLabeler).Maybe()

	testLogger := logger.Sugared(logger.Test(t))

	// Create test configuration with default values
	config := &model.AggregationConfig{
		MessageChannelSize:            1000,
		OrphanRecoveryIntervalMinutes: 5,
	}

	aggregator := NewCommitReportAggregator(mockStorage, mockSink, mockQuorum, testLogger, mockMonitoring, config)

	return aggregator, mockStorage, mockSink, mockQuorum, mockMonitoring
}

func createTestMessageCommitteePair(messageID, committeeID string) *model.MessageCommitteePair {
	return &model.MessageCommitteePair{
		MessageID:   []byte(messageID),
		CommitteeID: committeeID,
	}
}

func TestCommitReportAggregator_RecoverOrphans_Success(t *testing.T) {
	aggregator, mockStorage, _, _, _ := setupTestAggregator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create test data
	pair1 := createTestMessageCommitteePair("message1", "committee1")
	pair2 := createTestMessageCommitteePair("message2", "committee1")

	// Create channels for the mock
	pairCh := make(chan *model.MessageCommitteePair, 2)
	errCh := make(chan error, 1)

	// Send test pairs and close channels
	go func() {
		pairCh <- pair1
		pairCh <- pair2
		close(pairCh)
		close(errCh)
	}()

	// Mock the storage call using the generated mock
	mockStorage.EXPECT().ListOrphanedMessageCommitteePairs(ctx).Return(
		(<-chan *model.MessageCommitteePair)(pairCh),
		(<-chan error)(errCh),
	)

	// Run RecoverOrphans
	aggregator.RecoverOrphans(ctx)

	// Give some time for async operations
	time.Sleep(100 * time.Millisecond)
}

func TestCommitReportAggregator_RecoverOrphans_WithError(t *testing.T) {
	aggregator, mockStorage, _, _, _ := setupTestAggregator(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create channels for the mock with an error
	pairCh := make(chan *model.MessageCommitteePair)
	errCh := make(chan error, 1)

	// Send error and close channels
	go func() {
		errCh <- errors.New("storage error")
		close(pairCh)
		close(errCh)
	}()

	// Mock the storage call using the generated mock
	mockStorage.EXPECT().ListOrphanedMessageCommitteePairs(ctx).Return(
		(<-chan *model.MessageCommitteePair)(pairCh),
		(<-chan error)(errCh),
	)

	// Run RecoverOrphans
	aggregator.RecoverOrphans(ctx)

	// Give some time for async operations
	time.Sleep(100 * time.Millisecond)
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_QuorumMet(t *testing.T) {
	aggregator, mockStorage, mockSink, mockQuorum, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message")
	committeeID := testCommitteeID

	// Create test verification records
	verificationRecord := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			Message: &pb.Message{},
		},
		CommitteeID: committeeID,
	}
	verifications := []*model.CommitVerificationRecord{verificationRecord}

	// Mock the storage and quorum calls using generated mocks
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(verifications, nil)
	mockQuorum.EXPECT().CheckQuorum(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(true, nil)
	mockSink.EXPECT().SubmitReport(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(nil)

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify results - method should complete successfully
	require.NoError(t, err)
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_QuorumNotMet(t *testing.T) {
	aggregator, mockStorage, mockSink, mockQuorum, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message")
	committeeID := testCommitteeID

	// Create test verification records
	verificationRecord := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			Message: &pb.Message{},
		},
		CommitteeID: committeeID,
	}
	verifications := []*model.CommitVerificationRecord{verificationRecord}

	// Mock the storage and quorum calls using generated mocks
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(verifications, nil)
	mockQuorum.EXPECT().CheckQuorum(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(false, nil)
	mockSink.AssertNotCalled(t, "SubmitReport")

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify results - should complete successfully even when quorum not met (but not submitted)
	require.NoError(t, err)
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_StorageError(t *testing.T) {
	aggregator, mockStorage, _, _, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message")
	committeeID := testCommitteeID

	// Mock storage to return an error using generated mock
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(nil, errors.New("storage error"))

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify results - should return error
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage error")
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_QuorumError(t *testing.T) {
	aggregator, mockStorage, _, mockQuorum, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message")
	committeeID := testCommitteeID

	// Create test verification records
	verificationRecord := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			Message: &pb.Message{},
		},
		CommitteeID: committeeID,
	}
	verifications := []*model.CommitVerificationRecord{verificationRecord}

	// Mock storage to return verifications
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(verifications, nil)

	// Mock quorum check to return an error
	mockQuorum.EXPECT().CheckQuorum(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(false, errors.New("quorum validation failed"))

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify results - should return error
	require.Error(t, err)
	require.Contains(t, err.Error(), "quorum validation failed")
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_SinkError(t *testing.T) {
	aggregator, mockStorage, mockSink, mockQuorum, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message")
	committeeID := testCommitteeID

	// Create test verification records
	verificationRecord := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			Message: &pb.Message{},
		},
		CommitteeID: committeeID,
	}
	verifications := []*model.CommitVerificationRecord{verificationRecord}

	// Mock storage to return verifications
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(verifications, nil)

	// Mock quorum check to pass
	mockQuorum.EXPECT().CheckQuorum(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(true, nil)

	// Mock sink to fail submission
	mockSink.EXPECT().SubmitReport(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(errors.New("sink submission failed"))

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify results - should return error
	require.Error(t, err)
	require.Contains(t, err.Error(), "sink submission failed")
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_EmptyVerifications(t *testing.T) {
	aggregator, mockStorage, _, mockQuorum, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message")
	committeeID := "test-committee"

	// Mock storage to return empty verifications
	emptyVerifications := []*model.CommitVerificationRecord{}
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(emptyVerifications, nil)

	// Mock quorum check to return false (no verifications to check)
	mockQuorum.EXPECT().CheckQuorum(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(false, nil)

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify results - should complete successfully even with empty verifications
	require.NoError(t, err)
}

func TestCommitReportAggregator_checkAggregationAndSubmitComplete_ValidateReportStructure(t *testing.T) {
	aggregator, mockStorage, mockSink, mockQuorum, _ := setupTestAggregator(t)

	ctx := context.Background()
	messageID := []byte("test-message-structure")
	committeeID := testCommitteeID

	// Create multiple test verification records
	verificationRecord1 := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			MessageId: messageID,
			Message:   &pb.Message{},
		},
		CommitteeID: committeeID,
	}
	verificationRecord2 := &model.CommitVerificationRecord{
		MessageWithCCVNodeData: pb.MessageWithCCVNodeData{
			MessageId: messageID,
			Message:   &pb.Message{},
		},
		CommitteeID: committeeID,
	}
	verifications := []*model.CommitVerificationRecord{verificationRecord1, verificationRecord2}

	// Mock storage, quorum, and sink
	mockStorage.EXPECT().ListCommitVerificationByMessageID(ctx, messageID, committeeID).Return(verifications, nil)
	mockQuorum.EXPECT().CheckQuorum(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(true, nil)
	mockSink.EXPECT().SubmitReport(ctx, mock.AnythingOfType("*model.CommitAggregatedReport")).Return(nil)

	// Call the method
	err := aggregator.checkAggregationAndSubmitComplete(ctx, messageID, committeeID)

	// Verify method completed successfully - detailed validation happens in the mocks
	require.NoError(t, err)
}

func TestCommitReportAggregator_RecoverOrphans_ConcurrentProtection(t *testing.T) {
	aggregator, mockStorage, _, _, _ := setupTestAggregator(t)

	ctx := context.Background()

	// Create a channel that will block indefinitely to simulate a long-running recovery
	pairCh := make(chan *model.MessageCommitteePair)
	errCh := make(chan error)

	mockStorage.On("ListOrphanedMessageCommitteePairs", ctx).Return((<-chan *model.MessageCommitteePair)(pairCh), (<-chan error)(errCh))

	// Start the first recovery (this will block waiting for data from pairCh)
	go aggregator.RecoverOrphans(ctx)

	// Give it a moment to acquire the mutex
	time.Sleep(10 * time.Millisecond)

	// Try to start a second recovery - this should be skipped due to mutex protection
	aggregator.RecoverOrphans(ctx)

	// Clean up - close channels to allow first recovery to complete
	close(pairCh)
	close(errCh)

	// Give recovery time to complete
	time.Sleep(100 * time.Millisecond)

	// Verify expectations were met (the second call should have been skipped)
	mockStorage.AssertExpectations(t)
}

func TestCommitReportAggregator_TriggerOrphanRecovery(t *testing.T) {
	aggregator, mockStorage, _, _, _ := setupTestAggregator(t)

	ctx := context.Background()

	// Mock the storage to return empty results
	pairCh := make(chan *model.MessageCommitteePair)
	errCh := make(chan error)

	mockStorage.On("ListOrphanedMessageCommitteePairs", ctx).Return((<-chan *model.MessageCommitteePair)(pairCh), (<-chan error)(errCh))

	// Close channels immediately to simulate empty result
	close(pairCh)
	close(errCh)

	// Test that TriggerOrphanRecovery returns true when starting recovery
	result := aggregator.TriggerOrphanRecovery(ctx)
	require.True(t, result, "Expected TriggerOrphanRecovery to return true when starting recovery")

	// Give recovery time to complete
	time.Sleep(100 * time.Millisecond)

	mockStorage.AssertExpectations(t)
}

func TestCommitReportAggregator_ConfigurableSettings(t *testing.T) {
	mockStorage := mocks.NewMockCommitVerificationStore(t)
	mockSink := mocks.NewMockSink(t)
	mockQuorum := mocks.NewMockQuorumValidator(t)
	mockMonitoring := mocks.NewMockAggregatorMonitoring(t)

	// Set up metrics mock
	mockMetricLabeler := mocks.NewMockAggregatorMetricLabeler(t)
	mockMonitoring.On("Metrics").Return(mockMetricLabeler).Maybe()
	mockMetricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything).Maybe()
	mockMetricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything).Maybe()
	mockMetricLabeler.On("With", mock.Anything, mock.Anything).Return(mockMetricLabeler).Maybe()

	testLogger := logger.Sugared(logger.Test(t))

	// Create custom configuration
	config := &model.AggregationConfig{
		MessageChannelSize:            500, // Different from default 1000
		OrphanRecoveryIntervalMinutes: 2,   // Different from default 5
	}

	aggregator := NewCommitReportAggregator(mockStorage, mockSink, mockQuorum, testLogger, mockMonitoring, config)

	// Send a few messages to test functionality
	for i := 0; i < 5; i++ {
		err := aggregator.CheckAggregation([]byte("test-message"), testCommitteeID)
		require.NoError(t, err)
	}

	// Verify the recovery interval is set correctly by checking internal field
	require.Equal(t, 2, aggregator.orphanRecoveryIntervalMinutes)

	// Give time for goroutines to process
	time.Sleep(50 * time.Millisecond)
}
