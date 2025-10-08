package query

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- helpers ----------.
func avN64(n int64) *types.AttributeValueMemberN {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

func mkItem(id string, timestamp int64) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"id": avS(id), "ts": avN64(timestamp)}
}

func extractTS(item map[string]types.AttributeValue) (time.Time, error) {
	n, ok := item["ts"].(*types.AttributeValueMemberN)
	if !ok {
		return time.Time{}, errors.New("ts not a number")
	}
	ms, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms).UTC(), nil
}

func extractID(item map[string]types.AttributeValue) (string, error) {
	s, ok := item["id"].(*types.AttributeValueMemberS)
	if !ok {
		return "", errors.New("id not a string")
	}
	return s.Value, nil
}

func keyFromID(item map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	// In production this should return the full table/index key (e.g., PK/SK).
	// For tests, we treat "id" as our unique key.
	return map[string]types.AttributeValue{"id": item["id"]}, nil
}

func idOf(item map[string]types.AttributeValue) string {
	return item["id"].(*types.AttributeValueMemberS).Value
}

// Trims items to the slice strictly AFTER the item with ID == lastID.
func sliceAfterID(items []map[string]types.AttributeValue, lastID string) []map[string]types.AttributeValue {
	if lastID == "" {
		return items
	}
	for i := range items {
		if idOf(items[i]) == lastID {
			return items[i+1:]
		}
	}
	return items
}

// ---------- stub iterator ----------.
type stubIter struct {
	items   []map[string]types.AttributeValue
	current map[string]types.AttributeValue
	i       int
	termErr error
}

func newStubIter(items []map[string]types.AttributeValue, termErr error) *stubIter {
	return &stubIter{items: items, termErr: termErr}
}

func (s *stubIter) Next(context.Context) bool {
	if s.i >= len(s.items) {
		return false
	}
	s.current = s.items[s.i]
	s.i++
	return true
}
func (s *stubIter) Item() map[string]types.AttributeValue { return s.current }
func (s *stubIter) Err() error {
	if s.i >= len(s.items) {
		return s.termErr
	}
	return nil
}

// ---------- tests ----------

func TestMergeIterator_OrdersByTimestampAscending(t *testing.T) {
	ctx := context.Background()

	i1 := newStubIter([]map[string]types.AttributeValue{
		mkItem("a1", 1_000), mkItem("a2", 5_000),
	}, nil)
	i2 := newStubIter([]map[string]types.AttributeValue{
		mkItem("b1", 2_000), mkItem("b2", 3_000), mkItem("b3", 9_000),
	}, nil)
	i3 := newStubIter([]map[string]types.AttributeValue{
		mkItem("c1", 4_000), mkItem("c2", 6_000), mkItem("c3", 7_000),
	}, nil)

	m := NewMergeIterator(
		[]ItemIterator{i1, i2, i3},
		[]string{"shard-a", "shard-b", "shard-c"},
		extractTS,
		keyFromID, // required for cursors (even if this test doesn't assert them)
	)

	var got []string
	last := int64(-1)
	for m.Next(ctx) {
		item := m.Item()
		got = append(got, idOf(item))

		// assert non-decreasing timestamps
		n := item["ts"].(*types.AttributeValueMemberN)
		ms, _ := strconv.ParseInt(n.Value, 10, 64)
		require.GreaterOrEqual(t, ms, last, "timestamps must be non-decreasing")
		last = ms
	}
	require.NoError(t, m.Err())

	assert.Equal(t, []string{"a1", "b1", "b2", "c1", "a2", "c2", "c3", "b3"}, got)
}

func TestMergeIterator_EqualTimestamps_UsesSecondaryKeyThenStableIndex(t *testing.T) {
	ctx := context.Background()

	// All items have the same timestamp. Secondary key is "id", so global ordering is by id asc.
	it0 := newStubIter([]map[string]types.AttributeValue{mkItem("a1", 1_000), mkItem("a2", 1_000)}, nil)
	it1 := newStubIter([]map[string]types.AttributeValue{mkItem("b1", 1_000), mkItem("b2", 1_000)}, nil)
	it2 := newStubIter([]map[string]types.AttributeValue{mkItem("c1", 1_000), mkItem("c2", 1_000)}, nil)

	m := NewMergeIterator(
		[]ItemIterator{it0, it1, it2},
		[]string{"s0", "s1", "s2"},
		extractTS,
		keyFromID,
		extractID, // secondary key
	)

	var got []string
	for m.Next(ctx) {
		got = append(got, idOf(m.Item()))
	}
	require.NoError(t, m.Err())

	// With secondary key "id", the order is lexicographic by id
	assert.Equal(t, []string{"a1", "a2", "b1", "b2", "c1", "c2"}, got)
}

func TestMergeIterator_ErrorDuringAdvance_IsDeferred(t *testing.T) {
	ctx := context.Background()

	// bad yields one, then errors
	bad := &stubIter{
		items:   []map[string]types.AttributeValue{mkItem("x1", 1_000)},
		termErr: errors.New("advance fail"),
	}
	ok := newStubIter([]map[string]types.AttributeValue{mkItem("y1", 2_000)}, nil)

	m := NewMergeIterator(
		[]ItemIterator{bad, ok},
		[]string{"s0", "s1"},
		extractTS,
		keyFromID,
		extractID,
	)

	require.True(t, m.Next(ctx))
	assert.Equal(t, "x1", idOf(m.Item()))

	// Second call detects the deferred error
	assert.False(t, m.Next(ctx))
	assert.Error(t, m.Err())
	assert.Contains(t, m.Err().Error(), "iterator 0")
}

func TestMergeIterator_Cursors_PerShardAfterPartialPage(t *testing.T) {
	ctx := context.Background()

	// shard-a: a1@1000, a2@3000
	// shard-b: b1@2000, b2@4000
	// Merge order: a1, b1, a2, b2
	aItems := []map[string]types.AttributeValue{mkItem("a1", 1_000), mkItem("a2", 3_000)}
	bItems := []map[string]types.AttributeValue{mkItem("b1", 2_000), mkItem("b2", 4_000)}

	m := NewMergeIterator(
		[]ItemIterator{newStubIter(aItems, nil), newStubIter(bItems, nil)},
		[]string{"shard-a", "shard-b"},
		extractTS,
		keyFromID,
		extractID,
	)

	// Simulate a page limit of 3 items: expect a1, b1, a2
	var page []string
	for len(page) < 3 && m.Next(ctx) {
		page = append(page, idOf(m.Item()))
	}
	require.NoError(t, m.Err())
	assert.Equal(t, []string{"a1", "b1", "a2"}, page)

	cursors := m.Cursors()
	// shard-a last emitted: a2
	require.Contains(t, cursors, "shard-a")
	assert.Equal(t, "a2", cursors["shard-a"]["id"].(*types.AttributeValueMemberS).Value)
	// shard-b last emitted: b1
	require.Contains(t, cursors, "shard-b")
	assert.Equal(t, "b1", cursors["shard-b"]["id"].(*types.AttributeValueMemberS).Value)
}

func TestMergeIterator_Cursors_OnlyForContributingShards(t *testing.T) {
	ctx := context.Background()

	// shard-a will contribute the earliest single item; shard-b won't contribute within a 1-item page.
	aItems := []map[string]types.AttributeValue{mkItem("a1", 1_000), mkItem("a2", 2_000)}
	bItems := []map[string]types.AttributeValue{mkItem("b1", 3_000), mkItem("b2", 4_000)}

	m := NewMergeIterator(
		[]ItemIterator{newStubIter(aItems, nil), newStubIter(bItems, nil)},
		[]string{"shard-a", "shard-b"},
		extractTS,
		keyFromID,
		extractID,
	)

	// Page size 1
	require.True(t, m.Next(ctx))
	assert.Equal(t, "a1", idOf(m.Item()))
	require.NoError(t, m.Err())

	cursors := m.Cursors()
	require.Contains(t, cursors, "shard-a")
	assert.Equal(t, "a1", cursors["shard-a"]["id"].(*types.AttributeValueMemberS).Value)
	assert.NotContains(t, cursors, "shard-b", "non-contributing shard should not have a cursor yet")
}

func TestMergeIterator_Cursors_EnableResumeWithoutDuplicates(t *testing.T) {
	ctx := context.Background()

	aItems := []map[string]types.AttributeValue{
		mkItem("a1", 1_000), mkItem("a2", 4_000), mkItem("a3", 7_000),
	}
	bItems := []map[string]types.AttributeValue{
		mkItem("b1", 2_000), mkItem("b2", 3_000), mkItem("b3", 8_000),
	}
	// Global order: a1, b1, b2, a2, a3, b3

	// --- Page 1: take first 3 items
	m1 := NewMergeIterator(
		[]ItemIterator{newStubIter(aItems, nil), newStubIter(bItems, nil)},
		[]string{"shard-a", "shard-b"},
		extractTS,
		keyFromID,
		extractID,
	)

	var page1 []string
	for len(page1) < 3 && m1.Next(ctx) {
		page1 = append(page1, idOf(m1.Item()))
	}
	require.NoError(t, m1.Err())
	assert.Equal(t, []string{"a1", "b1", "b2"}, page1)

	cur1 := m1.Cursors()
	require.Equal(t, "a1", cur1["shard-a"]["id"].(*types.AttributeValueMemberS).Value)
	require.Equal(t, "b2", cur1["shard-b"]["id"].(*types.AttributeValueMemberS).Value)

	// --- Resume: create new shard iterators starting AFTER those cursors
	aAfter := sliceAfterID(aItems, "a1") // -> a2, a3
	bAfter := sliceAfterID(bItems, "b2") // -> b3

	m2 := NewMergeIterator(
		[]ItemIterator{newStubIter(aAfter, nil), newStubIter(bAfter, nil)},
		[]string{"shard-a", "shard-b"},
		extractTS,
		keyFromID,
		extractID,
	)

	// Drain what's left
	var page2 []string
	for m2.Next(ctx) {
		page2 = append(page2, idOf(m2.Item()))
	}
	require.NoError(t, m2.Err())

	// Expect remainder without duplicates: a2, a3, b3
	assert.Equal(t, []string{"a2", "a3", "b3"}, page2)
}
