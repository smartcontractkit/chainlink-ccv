package cctp_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/internal"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var ccvVerifierVersion = protocol.ByteSlice{0x00, 0x00, 0x00, 0x01}

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	testAttestation := createTestAttestation()

	mockAttestationService.EXPECT().
		Fetch(ctx, task.TxHash, task.Message).
		Return(testAttestation, nil).
		Once()

	v := cctp.NewVerifier(lggr, mockAttestationService, testCCTPConfig())
	results := v.VerifyMessages(ctx, tasks)

	require.Len(t, results, 1, "Expected one result")
	assert.Nil(t, results[0].Error, "Expected no error")
	assert.NotNil(t, results[0].Result, "Expected successful result")
	mockAttestationService.AssertExpectations(t)

	t.Cleanup(func() {
		cancel()
	})

	attestation, err := testAttestation.ToVerifierFormat()
	require.NoError(t, err)
	assert.Equal(t, task.MessageID, results[0].Result.MessageID.String())
	assert.Equal(t, attestation, results[0].Result.Signature)
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, results[0].Result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, results[0].Result.ExecutorAddress)
	assert.Equal(t, ccvVerifierVersion, results[0].Result.CCVVersion)
}

func TestVerifier_VerifyMessages_AttestationServiceFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	expectedErr := errors.New("attestation service unavailable")
	mockAttestationService.EXPECT().
		Fetch(ctx, task.TxHash, task.Message).
		Return(cctp.Attestation{}, expectedErr).
		Once()

	v := cctp.NewVerifier(lggr, mockAttestationService, testCCTPConfig())
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 1, "Expected one result")
	assert.Nil(t, results[0].Result, "Expected no successful result")
	assert.NotNil(t, results[0].Error, "Expected an error")

	verificationError := results[0].Error
	assert.Equal(t, expectedErr, verificationError.Error)
	assert.Equal(t, task.MessageID, verificationError.Task.MessageID)
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_AttestationNotReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task := internal.CreateTestVerificationTask(1)
	tasks := []verifier.VerificationTask{task}

	notReadyAttestation := cctp.Attestation{} // Empty attestation (not ready)

	mockAttestationService.EXPECT().
		Fetch(mock.Anything, task.TxHash, task.Message).
		Return(notReadyAttestation, nil).
		Once()

	v := cctp.NewVerifier(lggr, mockAttestationService, testCCTPConfig())
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 1, "Expected one result")
	assert.Nil(t, results[0].Result, "Expected no successful result")
	assert.NotNil(t, results[0].Error, "Expected an error")

	verificationError := results[0].Error
	assert.Error(t, verificationError.Error, "Expected error for attestation not ready")
	assert.Contains(t, verificationError.Error.Error(), "not ready")
	assert.Equal(t, task.MessageID, verificationError.Task.MessageID)
	assert.True(t, verificationError.Retryable, "Should be retryable")
	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_MultipleTasksWithMixedResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	task1 := internal.CreateTestVerificationTask(100)
	task2 := internal.CreateTestVerificationTask(101)
	task3 := internal.CreateTestVerificationTask(102)

	tasks := []verifier.VerificationTask{task1, task2, task3}

	// task1: success
	testAttestation := createTestAttestation()
	mockAttestationService.EXPECT().
		Fetch(ctx, task1.TxHash, task1.Message).
		Return(testAttestation, nil).
		Once()

	// task2: attestation service failure
	expectedErr := errors.New("network timeout")
	mockAttestationService.EXPECT().
		Fetch(ctx, task2.TxHash, task2.Message).
		Return(cctp.Attestation{}, expectedErr).
		Once()

	// task3: success
	mockAttestationService.EXPECT().
		Fetch(ctx, task3.TxHash, task3.Message).
		Return(testAttestation, nil).
		Once()

	v := cctp.NewVerifier(lggr, mockAttestationService, testCCTPConfig())
	results := v.VerifyMessages(ctx, tasks)

	t.Cleanup(func() {
		cancel()
	})

	require.Len(t, results, 3, "Expected three results")

	// Results are produced concurrently, so they may arrive in any order.
	// Index them by message ID rather than relying on input position.
	successByID := make(map[string]verifier.VerificationResult)
	errorByID := make(map[string]verifier.VerificationResult)
	for _, result := range results {
		switch {
		case result.Result != nil:
			successByID[result.Result.MessageID.String()] = result
		case result.Error != nil:
			errorByID[result.Error.Task.MessageID] = result
		default:
			t.Fatalf("result has neither Result nor Error: %+v", result)
		}
	}

	// task1 should succeed
	require.Contains(t, successByID, task1.MessageID, "Expected successful result for task1")
	assert.Nil(t, successByID[task1.MessageID].Error, "Expected no error for task1")

	// task2 should fail
	require.Contains(t, errorByID, task2.MessageID, "Expected error for task2")
	assert.Nil(t, errorByID[task2.MessageID].Result, "Expected no result for task2")
	assert.Equal(t, expectedErr, errorByID[task2.MessageID].Error.Error)

	// task3 should succeed
	require.Contains(t, successByID, task3.MessageID, "Expected successful result for task3")
	assert.Nil(t, successByID[task3.MessageID].Error, "Expected no error for task3")

	mockAttestationService.AssertExpectations(t)
}

func TestVerifier_VerifyMessages_RespectsMaxConcurrentFetchers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	lggr := logger.Test(t)
	mockAttestationService := mocks.NewCCTPAttestationService(t)

	const maxFetchers = 2
	const numTasks = 12

	var inFlight, maxObserved int64
	mockAttestationService.EXPECT().
		Fetch(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ protocol.ByteSlice, _ protocol.Message) {
			cur := atomic.AddInt64(&inFlight, 1)
			for {
				prev := atomic.LoadInt64(&maxObserved)
				if cur <= prev || atomic.CompareAndSwapInt64(&maxObserved, prev, cur) {
					break
				}
			}
			// Hold the fetch open so concurrent workers actually overlap.
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt64(&inFlight, -1)
		}).
		Return(createTestAttestation(), nil).
		Times(numTasks)

	tasks := make([]verifier.VerificationTask, 0, numTasks)
	for i := range numTasks {
		tasks = append(tasks, internal.CreateTestVerificationTask(i+1))
	}

	v := cctp.NewVerifierWithConfig(lggr, mockAttestationService, 30*time.Second, 5*time.Second, maxFetchers)
	results := v.VerifyMessages(ctx, tasks)

	require.Len(t, results, numTasks, "Expected one result per task")
	assert.LessOrEqual(t, atomic.LoadInt64(&maxObserved), int64(maxFetchers),
		"Concurrent Fetch calls must not exceed the configured maxFetchers")
	mockAttestationService.AssertExpectations(t)
}

// testCCTPConfig returns a config with sane non-zero values for verifier construction.
// AttestationConcurrentFetchers must be > 0, otherwise VerifyMessages spawns zero
// workers (min(len(tasks), 0)) and blocks forever waiting on results.
func testCCTPConfig() cctp.CCTPConfig {
	return cctp.CCTPConfig{
		AttestationNotReadyRetry:      30 * time.Second,
		AttestationGenericErrorRetry:  5 * time.Second,
		AttestationConcurrentFetchers: 10,
	}
}

func createTestAttestation() cctp.Attestation {
	msg := cctp.Message{
		Message:     "0x1234567890",
		Attestation: "0xabcdef",
		DecodedMessage: cctp.DecodedMessage{
			Sender: "0x1122334455",
		},
		Status: "complete",
	}

	attestation := cctp.NewAttestation(ccvVerifierVersion, msg)
	return attestation
}
