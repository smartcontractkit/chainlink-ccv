package aggregation

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
)

// fakeQueue is an in-memory stand-in for the durable queue. Retry and Fail drop the job
// rather than redelivering it, which keeps unit tests bounded; redelivery and cross-replica
// handoff are covered by the Postgres-backed tests.
type fakeQueue struct {
	mu      sync.Mutex
	pending []jobqueue.Job[aggregationRequest]
	nextID  int
	signals chan struct{}
	// claims records the batch size of every ConsumePending call.
	claims []int
}

func newFakeQueue() *fakeQueue {
	return &fakeQueue{signals: make(chan struct{}, 1)}
}

func (q *fakeQueue) Publish(ctx context.Context, jobs ...aggregationRequest) error {
	return q.PublishWithDelay(ctx, 0, jobs...)
}

func (q *fakeQueue) PublishWithDelay(_ context.Context, _ time.Duration, jobs ...aggregationRequest) error {
	q.mu.Lock()
	for _, job := range jobs {
		q.nextID++
		q.pending = append(q.pending, jobqueue.Job[aggregationRequest]{ID: strconv.Itoa(q.nextID), Payload: job})
	}
	q.mu.Unlock()
	select {
	case q.signals <- struct{}{}:
	default:
	}
	return nil
}

func (q *fakeQueue) ConsumePending(_ context.Context, batchSize int) ([]jobqueue.Job[aggregationRequest], error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.claims = append(q.claims, batchSize)
	if len(q.pending) < batchSize {
		batchSize = len(q.pending)
	}
	jobs := q.pending[:batchSize]
	q.pending = q.pending[batchSize:]
	return jobs, nil
}

func (q *fakeQueue) ReclaimStale(context.Context, int) ([]jobqueue.Job[aggregationRequest], error) {
	return nil, nil
}

func (q *fakeQueue) Signals() <-chan struct{} { return q.signals }

func (q *fakeQueue) Complete(context.Context, ...string) error { return nil }

func (q *fakeQueue) Retry(context.Context, time.Duration, map[string]error, ...string) error {
	return nil
}

func (q *fakeQueue) Fail(context.Context, map[string]error, ...string) error { return nil }

func (q *fakeQueue) Cleanup(context.Context, time.Duration) (int, error) { return 0, nil }

func (q *fakeQueue) Size(context.Context) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), nil
}

func (q *fakeQueue) claimSizes() []int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]int(nil), q.claims...)
}

func (q *fakeQueue) Name() string { return "fake_aggregation_jobs" }

var _ Queue = (*fakeQueue)(nil)
