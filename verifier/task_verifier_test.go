package verifier_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

func Test_ProcessingReadyTasks(t *testing.T) {
	message1 := protocol.Message{SequenceNumber: 1}
	messageID1 := message1.MustMessageID()
	task1 := verifier.VerificationTask{MessageID: messageID1.String()}

	message2 := protocol.Message{SequenceNumber: 2}
	messageID2 := message2.MustMessageID()
	task2 := verifier.VerificationTask{MessageID: messageID2.String()}

	fanoutCh := make(chan batcher.BatchResult[verifier.VerificationTask], 10)
	fakeFanout := FakeSourceReaderFanout{
		batcher: batcher.NewBatcher(
			t.Context(),
			2,
			100*time.Millisecond,
			fanoutCh,
		),
		outCh: fanoutCh,
	}

	storageOutCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
	storageBatcher := batcher.NewBatcher(
		t.Context(),
		2,
		100*time.Millisecond,
		storageOutCh,
	)

	mockVerifier := &fakeVerifier{}
	taskVerifier, err := verifier.NewTaskVerifierProcessorWithFanouts(
		logger.Test(t),
		"verifier-1",
		mockVerifier,
		monitoring.NewFakeVerifierMonitoring(),
		map[protocol.ChainSelector]verifier.SourceReaderFanout{
			chain2337: fakeFanout,
		},
		storageBatcher,
	)
	require.NoError(t, err)
	require.NoError(t, taskVerifier.Start(t.Context()))

	t.Run("successful verification works", func(t *testing.T) {
		// Set the verifier to pass all verifications immediately
		mockVerifier.Set(0, nil)

		require.NoError(t, fakeFanout.batcher.Add(task1, task2))

		select {
		case res, ok := <-storageOutCh:
			require.True(t, ok)
			require.Len(t, res.Items, 2)
			require.Equal(t, res.Items[0].MessageID, messageID1)
			require.Equal(t, res.Items[1].MessageID, messageID2)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for storage batcher result")
		}
	})

	t.Run("retries failed verifications", func(t *testing.T) {
		fastRetry := 10 * time.Millisecond
		mockVerifier.Set(2, map[string]verifier.VerificationError{
			messageID1.String(): {Task: task1, Retryable: true, Delay: &fastRetry},
			messageID2.String(): {Task: task2, Retryable: true, Delay: &fastRetry},
		})

		require.NoError(t, fakeFanout.batcher.Add(task1, task2))

		require.Eventually(t, func() bool {
			return mockVerifier.Attempt(task1.MessageID) >= 3 &&
				mockVerifier.Attempt(task2.MessageID) >= 3
		}, tests.WaitTimeout(t), 10*time.Millisecond)

		select {
		case res, ok := <-storageOutCh:
			require.True(t, ok)
			require.Len(t, res.Items, 2)
			require.Equal(t, res.Items[0].MessageID, messageID1)
			require.Equal(t, res.Items[1].MessageID, messageID2)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for storage batcher result")
		}
	})
}

type FakeSourceReaderFanout struct {
	batcher *batcher.Batcher[verifier.VerificationTask]
	outCh   chan batcher.BatchResult[verifier.VerificationTask]
}

func (f FakeSourceReaderFanout) RetryTasks(minDelay time.Duration, tasks ...verifier.VerificationTask) error {
	return f.batcher.Retry(minDelay, tasks...)
}

func (f FakeSourceReaderFanout) ReadyTasksChannel() <-chan batcher.BatchResult[verifier.VerificationTask] {
	return f.outCh
}

type fakeVerifier struct {
	mu            sync.RWMutex
	passThreshold int
	counter       map[string]int
	errors        map[string]verifier.VerificationError
}

func (f *fakeVerifier) Set(passThreshold int, errors map[string]verifier.VerificationError) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.passThreshold = passThreshold
	f.errors = errors
	f.counter = make(map[string]int)
}

func (f *fakeVerifier) Attempt(key string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.counter[key]
}

func (f *fakeVerifier) VerifyMessages(_ context.Context, tasks []verifier.VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult]) batcher.BatchResult[verifier.VerificationError] {
	errors := make([]verifier.VerificationError, 0)
	results := make([]protocol.VerifierNodeResult, 0)

	for _, task := range tasks {
		f.mu.Lock()
		counter, ok := f.counter[task.MessageID]
		if !ok {
			counter = 0
		}
		counter++
		f.counter[task.MessageID] = counter
		f.mu.Unlock()

		if counter <= f.passThreshold {
			errors = append(errors, f.errors[task.MessageID])
		} else {
			messageID, err := protocol.NewBytes32FromString(task.MessageID)
			if err != nil {
				panic(err)
			}
			results = append(results, protocol.VerifierNodeResult{
				MessageID: messageID,
			})
		}
	}
	if len(results) > 0 {
		err := ccvDataBatcher.Add(results...)
		if err != nil {
			panic(err)
		}
	}
	return batcher.BatchResult[verifier.VerificationError]{Items: errors}
}
