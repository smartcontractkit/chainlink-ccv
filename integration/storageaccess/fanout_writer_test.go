package storageaccess

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// stubWriter returns canned per-item results (or a top-level error / short slice).
type stubWriter struct {
	results []protocol.WriteResult
	err     error
}

func (s *stubWriter) WriteCCVNodeData(_ context.Context, _ []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	return s.results, s.err
}

func item(b byte) protocol.VerifierNodeResult {
	var id protocol.Bytes32
	id[0] = b
	return protocol.VerifierNodeResult{MessageID: id}
}

func success(in protocol.VerifierNodeResult) protocol.WriteResult {
	return protocol.WriteResult{Input: in, Status: protocol.WriteSuccess}
}

func failure(in protocol.VerifierNodeResult, retryable bool) protocol.WriteResult {
	return protocol.WriteResult{Input: in, Status: protocol.WriteFailure, Error: errors.New("boom"), Retryable: retryable}
}

func newFanOut(t *testing.T, writers ...namedWriter) *FanOutWriter {
	t.Helper()
	acks, err := newAckCache(DefaultAckCacheSize)
	require.NoError(t, err)
	return &FanOutWriter{writers: writers, lggr: logger.Test(t), acks: acks}
}

func TestFanOutWriter_AllSucceed(t *testing.T) {
	in := []protocol.VerifierNodeResult{item(1), item(2)}
	f := newFanOut(t,
		namedWriter{label: "a", writer: &stubWriter{results: []protocol.WriteResult{success(in[0]), success(in[1])}}},
		namedWriter{label: "b", writer: &stubWriter{results: []protocol.WriteResult{success(in[0]), success(in[1])}}},
	)

	got, err := f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, r := range got {
		assert.Equal(t, protocol.WriteSuccess, r.Status)
	}
}

// outcome enumerates the three per-aggregator results that drive the merge.
type outcome int

const (
	ok    outcome = iota // WriteSuccess
	retry                // WriteFailure, retryable
	perm                 // WriteFailure, non-retryable
)

func resultFor(in protocol.VerifierNodeResult, o outcome) protocol.WriteResult {
	switch o {
	case ok:
		return success(in)
	case retry:
		return failure(in, true)
	case perm:
		return failure(in, false)
	default:
		panic("unknown outcome")
	}
}

// fanOutForOutcomes builds a fan-out with one aggregator per outcome ("agg0", "agg1", ...),
// each returning the corresponding single-item result.
func fanOutForOutcomes(t *testing.T, in protocol.VerifierNodeResult, outcomes ...outcome) *FanOutWriter {
	t.Helper()
	writers := make([]namedWriter, len(outcomes))
	for i, o := range outcomes {
		writers[i] = namedWriter{
			label:  fmt.Sprintf("agg%d", i),
			writer: &stubWriter{results: []protocol.WriteResult{resultFor(in, o)}},
		}
	}
	return newFanOut(t, writers...)
}

// TestFanOutWriter_Merge exhaustively covers the merge decision over every combination of
// per-aggregator outcomes for N = 1, 2, and 3 aggregators: an item succeeds only when all
// aggregators ack; otherwise it fails, and is retryable iff no aggregator failed non-retryably.
func TestFanOutWriter_Merge(t *testing.T) {
	tests := []struct {
		name          string
		outcomes      []outcome
		wantStatus    protocol.WriteResultStatus
		wantRetryable bool
		// wantFailedLabels are the aggregator labels that must appear in the joined error.
		wantFailedLabels []string
	}{
		// N = 1 (degenerate / legacy single-aggregator case).
		{"single success", []outcome{ok}, protocol.WriteSuccess, false, nil},
		{"single retryable", []outcome{retry}, protocol.WriteFailure, true, []string{"agg0"}},
		{"single permanent", []outcome{perm}, protocol.WriteFailure, false, []string{"agg0"}},

		// N = 2.
		{"both success", []outcome{ok, ok}, protocol.WriteSuccess, false, nil},
		{"success + retryable", []outcome{ok, retry}, protocol.WriteFailure, true, []string{"agg1"}},
		{"success + permanent", []outcome{ok, perm}, protocol.WriteFailure, false, []string{"agg1"}},
		{"both retryable", []outcome{retry, retry}, protocol.WriteFailure, true, []string{"agg0", "agg1"}},
		{"retryable + permanent", []outcome{retry, perm}, protocol.WriteFailure, false, []string{"agg0", "agg1"}},
		{"both permanent", []outcome{perm, perm}, protocol.WriteFailure, false, []string{"agg0", "agg1"}},

		// N = 3.
		{"all success", []outcome{ok, ok, ok}, protocol.WriteSuccess, false, nil},
		{"all retryable", []outcome{retry, retry, retry}, protocol.WriteFailure, true, []string{"agg0", "agg1", "agg2"}},
		{"success + retryable + permanent", []outcome{ok, retry, perm}, protocol.WriteFailure, false, []string{"agg1", "agg2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := item(1)
			f := fanOutForOutcomes(t, in, tt.outcomes...)

			got, err := f.WriteCCVNodeData(context.Background(), []protocol.VerifierNodeResult{in})
			require.NoError(t, err)
			require.Len(t, got, 1)

			assert.Equal(t, tt.wantStatus, got[0].Status)
			assert.Equal(t, tt.wantRetryable, got[0].Retryable)
			assert.Equal(t, in.MessageID, got[0].Input.MessageID, "merged result preserves the input")

			if tt.wantStatus == protocol.WriteSuccess {
				assert.NoError(t, got[0].Error)
				return
			}
			require.Error(t, got[0].Error)
			for _, label := range tt.wantFailedLabels {
				assert.ErrorContains(t, got[0].Error, fmt.Sprintf("aggregator %q", label),
					"joined error must name every failing aggregator")
			}
		})
	}
}

// TestFanOutWriter_Merge_HeterogeneousBatch verifies the merge is computed independently per
// item index within a single batch.
func TestFanOutWriter_Merge_HeterogeneousBatch(t *testing.T) {
	in := []protocol.VerifierNodeResult{item(1), item(2), item(3)}
	// agg "a" acks everything; agg "b" acks item0, fails item1 retryably, rejects item2 permanently.
	f := newFanOut(t,
		namedWriter{label: "a", writer: &stubWriter{results: []protocol.WriteResult{
			success(in[0]), success(in[1]), success(in[2]),
		}}},
		namedWriter{label: "b", writer: &stubWriter{results: []protocol.WriteResult{
			success(in[0]), failure(in[1], true), failure(in[2], false),
		}}},
	)

	got, err := f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 3)

	assert.Equal(t, protocol.WriteSuccess, got[0].Status)

	assert.Equal(t, protocol.WriteFailure, got[1].Status)
	assert.True(t, got[1].Retryable)

	assert.Equal(t, protocol.WriteFailure, got[2].Status)
	assert.False(t, got[2].Retryable)

	// Each merged result maps back to its own input.
	for i := range in {
		assert.Equal(t, in[i].MessageID, got[i].Input.MessageID, "item %d", i)
	}
}

// TestFanOutWriter_Merge_FailureWithNilError documents that a failure carrying no underlying
// error still yields a WriteFailure (with a nil joined error) rather than being treated as success.
func TestFanOutWriter_Merge_FailureWithNilError(t *testing.T) {
	in := item(1)
	f := newFanOut(t,
		namedWriter{label: "a", writer: &stubWriter{results: []protocol.WriteResult{success(in)}}},
		// Status=Failure but Error=nil (e.g. a writer that fails without populating Error).
		namedWriter{label: "b", writer: &stubWriter{results: []protocol.WriteResult{
			{Input: in, Status: protocol.WriteFailure, Retryable: true},
		}}},
	)

	got, err := f.WriteCCVNodeData(context.Background(), []protocol.VerifierNodeResult{in})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protocol.WriteFailure, got[0].Status, "a failure with a nil error is still a failure")
	assert.True(t, got[0].Retryable)
	assert.NoError(t, got[0].Error, "joining zero underlying errors yields nil")
}

func TestFanOutWriter_ShortResultSliceSynthesizesRetryableFailure(t *testing.T) {
	in := []protocol.VerifierNodeResult{item(1), item(2)}
	// a returns full success; b returns a short slice with a top-level error.
	f := newFanOut(t,
		namedWriter{label: "a", writer: &stubWriter{results: []protocol.WriteResult{success(in[0]), success(in[1])}}},
		namedWriter{label: "b", writer: &stubWriter{results: nil, err: errors.New("circuit open")}},
	)

	got, err := f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for i, r := range got {
		assert.Equal(t, protocol.WriteFailure, r.Status, "item %d", i)
		assert.True(t, r.Retryable, "synthesized failures are retryable")
	}
}

func TestFanOutWriter_EmptyInput(t *testing.T) {
	f := newFanOut(t, namedWriter{label: "a", writer: &stubWriter{}})
	got, err := f.WriteCCVNodeData(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// countingStub returns a scripted per-call result slice and records the number of
// invocations. Each stub is driven by a single aggregator goroutine and read only after the
// fan-out Wg has been waited on, so it needs no locking.
type countingStub struct {
	calls   int
	results [][]protocol.WriteResult
	errs    []error
}

func (s *countingStub) WriteCCVNodeData(_ context.Context, _ []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	s.calls++
	i := s.calls - 1
	if len(s.results) == 0 {
		return nil, nil
	}
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	var err error
	if i < len(s.errs) {
		err = s.errs[i]
	}
	return s.results[i], err
}

// TestFanOutWriter_SkipsAlreadyAckedAggregatorOnRetry verifies the core behavior: once an
// aggregator confirms a message, a later retry of that message does not re-send it to that
// aggregator — only the still-pending aggregator is re-attempted, so a down aggregator no
// longer makes the healthy ones receive the same item on every retry.
func TestFanOutWriter_SkipsAlreadyAckedAggregatorOnRetry(t *testing.T) {
	in := []protocol.VerifierNodeResult{item(1)}
	a := &countingStub{results: [][]protocol.WriteResult{{success(in[0])}}}
	b := &countingStub{results: [][]protocol.WriteResult{
		{failure(in[0], true)},
		{success(in[0])},
	}}
	f := newFanOut(t,
		namedWriter{label: "a", writer: a},
		namedWriter{label: "b", writer: b},
	)

	// First attempt: a acks, b fails retryably.
	got, err := f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protocol.WriteFailure, got[0].Status)
	assert.True(t, got[0].Retryable)
	assert.Equal(t, 1, a.calls)
	assert.Equal(t, 1, b.calls)

	// Retry: a already acked and is skipped; only b is re-attempted and now acks.
	got, err = f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protocol.WriteSuccess, got[0].Status)
	assert.Equal(t, 1, a.calls, "healthy aggregator must not be re-sent on retry")
	assert.Equal(t, 2, b.calls)
}

// TestFanOutWriter_RetryOnlyResendsFailedItems mirrors the real queue behavior: a batch
// failure retries only the items that failed, not the ones every aggregator already acked. A
// healthy aggregator that acked a failed item is therefore skipped, and only the still-pending
// aggregator is re-sent that item.
func TestFanOutWriter_RetryOnlyResendsFailedItems(t *testing.T) {
	in := []protocol.VerifierNodeResult{item(1), item(2)}
	// a acks both items up front; b acks item[0] but fails item[1] retryably, then acks it.
	a := &countingStub{results: [][]protocol.WriteResult{{success(in[0]), success(in[1])}}}
	b := &countingStub{results: [][]protocol.WriteResult{
		{success(in[0]), failure(in[1], true)},
		{success(in[1])},
	}}
	f := newFanOut(t,
		namedWriter{label: "a", writer: a},
		namedWriter{label: "b", writer: b},
	)

	got, err := f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, protocol.WriteSuccess, got[0].Status, "item[0] acked by both aggregators")
	assert.Equal(t, protocol.WriteFailure, got[1].Status, "item[1] failed by b")
	assert.True(t, got[1].Retryable)

	// The queue retries only the failed item[1].
	got, err = f.WriteCCVNodeData(context.Background(), []protocol.VerifierNodeResult{in[1]})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protocol.WriteSuccess, got[0].Status)
	assert.Equal(t, 1, a.calls, "a already acked item[1], must not be re-sent")
	assert.Equal(t, 2, b.calls)
}

// TestFanOutWriter_ForgetsFullyAckedItem verifies that once every aggregator has confirmed a
// message, its acks are dropped so tracking memory stays bounded. The tracking is a per-process
// optimization, not a guarantee: a fully acked item is never retried by the queue, so forgetting
// it cannot reintroduce spam in practice.
func TestFanOutWriter_ForgetsFullyAckedItem(t *testing.T) {
	in := []protocol.VerifierNodeResult{item(1)}
	a := &countingStub{results: [][]protocol.WriteResult{{success(in[0]), success(in[0])}}}
	b := &countingStub{results: [][]protocol.WriteResult{{success(in[0])}}}
	f := newFanOut(t,
		namedWriter{label: "a", writer: a},
		namedWriter{label: "b", writer: b},
	)

	got, err := f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protocol.WriteSuccess, got[0].Status)
	assert.Equal(t, 1, a.calls)
	assert.Equal(t, 1, b.calls)
	assert.Equal(t, 0, f.acks.len(), "fully acked item must be forgotten to bound memory")

	// A fresh call re-learns the acks because the previous ones were forgotten.
	got, err = f.WriteCCVNodeData(context.Background(), in)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protocol.WriteSuccess, got[0].Status)
	assert.Equal(t, 2, a.calls)
	assert.Equal(t, 2, b.calls)
}
