package jobqueue_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestObservabilityDecorator(t *testing.T) {
	// Helper function for tests that don't care about metrics
	noopMetric := func(context.Context, int64) {}

	t.Run("NewObservabilityDecorator validation", func(t *testing.T) {
		q, _ := newTestQueue(t)
		lggr := logger.Test(t)

		// Happy path
		decorator, err := jobqueue.NewObservabilityDecorator(q, lggr, time.Second, noopMetric)
		require.NoError(t, err)
		require.NotNil(t, decorator)

		// Nil queue
		_, err = jobqueue.NewObservabilityDecorator[testJob](nil, lggr, time.Second, noopMetric)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "queue cannot be nil")

		// Nil logger
		_, err = jobqueue.NewObservabilityDecorator(q, nil, time.Second, noopMetric)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger cannot be nil")

		// Nil recordSizeMetric
		_, err = jobqueue.NewObservabilityDecorator(q, lggr, time.Second, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "recordSizeMetric cannot be nil")

		// Zero interval should use default
		decorator, err = jobqueue.NewObservabilityDecorator(q, lggr, 0, noopMetric)
		require.NoError(t, err)
		require.NotNil(t, decorator)
	})

	t.Run("Start and Close", func(t *testing.T) {
		q, _ := newTestQueue(t)
		lggr := logger.Test(t)

		decorator, err := jobqueue.NewObservabilityDecorator(q, lggr, 100*time.Millisecond, noopMetric)
		require.NoError(t, err)

		ctx := context.Background()

		// Start the decorator
		err = decorator.Start(ctx)
		require.NoError(t, err)

		// Wait a bit to let it log a few times
		time.Sleep(350 * time.Millisecond)

		// Close the decorator
		err = decorator.Close()
		require.NoError(t, err)

		// Verify it cannot be started again
		err = decorator.Start(ctx)
		require.Error(t, err)
	})

	t.Run("Delegates all JobQueue methods", func(t *testing.T) {
		q, _ := newTestQueue(t)
		lggr := logger.Test(t)

		decorator, err := jobqueue.NewObservabilityDecorator(q, lggr, time.Second, noopMetric)
		require.NoError(t, err)

		ctx := context.Background()

		// Test Publish
		job1 := testJob{Chain: 1, Message: []byte("msg1"), Data: "data1"}
		err = decorator.Publish(ctx, job1)
		require.NoError(t, err)

		// Test Size
		size, err := decorator.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, size)

		// Test Consume
		jobs, err := decorator.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Len(t, jobs, 1)

		// Test Complete
		err = decorator.Complete(ctx, jobs[0].ID)
		require.NoError(t, err)

		// Verify size is now 0
		size, err = decorator.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, size)

		// Test PublishWithDelay
		job2 := testJob{Chain: 2, Message: []byte("msg2"), Data: "data2"}
		err = decorator.PublishWithDelay(ctx, 100*time.Millisecond, job2)
		require.NoError(t, err)

		// Wait for job to become available
		time.Sleep(150 * time.Millisecond)

		// Test Retry
		jobs, err = decorator.Consume(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 1)

		errors := map[string]error{jobs[0].ID: assert.AnError}
		err = decorator.Retry(ctx, 50*time.Millisecond, errors, jobs[0].ID)
		require.NoError(t, err)

		// Wait for retry delay
		time.Sleep(100 * time.Millisecond)

		// Test Fail
		jobs, err = decorator.Consume(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 1)

		err = decorator.Fail(ctx, errors, jobs[0].ID)
		require.NoError(t, err)

		// Test Cleanup
		count, err := decorator.Cleanup(ctx, time.Hour)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, 0)

		// Test Name
		name := decorator.Name()
		assert.NotEmpty(t, name)
	})

	t.Run("Size monitoring in background", func(t *testing.T) {
		q, _ := newTestQueue(t)
		lggr := logger.Test(t)

		// Track metric calls
		var metricCallCount int
		var lastSize int64
		var mu sync.Mutex
		metricFunc := func(ctx context.Context, size int64) {
			mu.Lock()
			defer mu.Unlock()
			metricCallCount++
			lastSize = size
		}

		// Use a short interval for testing
		decorator, err := jobqueue.NewObservabilityDecorator(q, lggr, 100*time.Millisecond, metricFunc)
		require.NoError(t, err)

		ctx := context.Background()

		// Publish some jobs before starting
		job1 := testJob{Chain: 1, Message: []byte("msg1"), Data: "data1"}
		job2 := testJob{Chain: 2, Message: []byte("msg2"), Data: "data2"}
		job3 := testJob{Chain: 3, Message: []byte("msg3"), Data: "data3"}
		err = decorator.Publish(ctx, job1, job2, job3)
		require.NoError(t, err)

		// Start the decorator
		err = decorator.Start(ctx)
		require.NoError(t, err)

		// Wait for at least a couple monitoring cycles
		time.Sleep(250 * time.Millisecond)

		// Consume jobs to change the size
		jobs, err := decorator.Consume(ctx, 2)
		require.NoError(t, err)
		assert.Len(t, jobs, 2)

		// Wait for more monitoring cycles
		time.Sleep(250 * time.Millisecond)

		// Complete jobs
		err = decorator.Complete(ctx, jobs[0].ID, jobs[1].ID)
		require.NoError(t, err)

		// Wait for more monitoring cycles
		time.Sleep(250 * time.Millisecond)

		// Close the decorator
		err = decorator.Close()
		require.NoError(t, err)

		// Verify metric function was called multiple times
		mu.Lock()
		assert.Greater(t, metricCallCount, 5, "metric function should have been called at least 6 times")
		assert.Equal(t, int64(1), lastSize, "last recorded size should be 1")
		mu.Unlock()

		// Verify final size
		size, err := decorator.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, size) // One job still processing
	})

	t.Run("HealthReport", func(t *testing.T) {
		q, _ := newTestQueue(t)
		lggr := logger.Test(t)

		decorator, err := jobqueue.NewObservabilityDecorator(q, lggr, time.Second, noopMetric)
		require.NoError(t, err)

		ctx := context.Background()

		// Before start
		report := decorator.HealthReport()
		require.NotNil(t, report)
		assert.Contains(t, report, decorator.Name())

		// After start
		err = decorator.Start(ctx)
		require.NoError(t, err)

		report = decorator.HealthReport()
		require.NotNil(t, report)
		assert.Contains(t, report, decorator.Name())
		assert.NoError(t, report[decorator.Name()])

		// Cleanup
		err = decorator.Close()
		require.NoError(t, err)
	})
}
