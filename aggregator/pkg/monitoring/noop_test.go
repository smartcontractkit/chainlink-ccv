package monitoring

import (
	"context"
	"testing"
	"time"
)

func TestNoopAggregatorMonitoring_DoesNotPanic(t *testing.T) {
	m := NewNoopAggregatorMonitoring()
	lbl := m.Metrics()

	ctx := context.Background()
	_ = lbl.With("key", "value")
	lbl.IncrementActiveRequestsCounter(ctx)
	lbl.DecrementActiveRequestsCounter(ctx)
	lbl.IncrementCompletedAggregations(ctx)
	lbl.RecordAPIRequestDuration(ctx, 10*time.Millisecond)
	lbl.IncrementAPIRequestErrors(ctx)
	lbl.RecordMessageSinceNumberOfRecordsReturned(ctx, 5)
	lbl.IncrementPendingAggregationsChannelBuffer(ctx, 2)
	lbl.DecrementPendingAggregationsChannelBuffer(ctx, 1)
	lbl.RecordStorageLatency(ctx, 5*time.Millisecond)
	lbl.IncrementStorageError(ctx)
	lbl.RecordTimeToAggregation(ctx, time.Second)
}
