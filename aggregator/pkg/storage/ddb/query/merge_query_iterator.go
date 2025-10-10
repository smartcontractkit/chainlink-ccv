// file: ddb/merge_query_iterator.go
package query

import (
	"container/heap"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type ItemIterator interface {
	// Next advances the iterator to the next item
	Next(ctx context.Context) bool
	// Item returns the current item
	Item() map[string]types.AttributeValue
	// Err returns any error that occurred during iteration
	Err() error
}

// Extractors.
type (
	TimestampExtractor    func(map[string]types.AttributeValue) (time.Time, error)
	SecondaryKeyExtractor func(map[string]types.AttributeValue) (string, error)
)

// KeyExtractor must build the full DynamoDB key map (PK/SK for the table or index you queried).
type KeyExtractor func(map[string]types.AttributeValue) (map[string]types.AttributeValue, error)

type MergeIterator struct {
	iters                 []ItemIterator
	shards                []string
	timestampExtractor    TimestampExtractor
	secondaryKeyExtractor SecondaryKeyExtractor // optional
	KeyExtractor          KeyExtractor          // required for cursors

	h       *minHeap
	current map[string]types.AttributeValue
	err     error
	init    bool

	// cursors[shardID] = LastEvaluatedKey (built from the last item we EMITTED from that shard)
	cursors map[string]map[string]types.AttributeValue
}

func NewMergeIterator(
	iters []ItemIterator,
	shardIDs []string,
	tsExtractor TimestampExtractor,
	keyExtractor KeyExtractor,
	secondaryKeyExtractor ...SecondaryKeyExtractor,
) *MergeIterator {
	if len(iters) != len(shardIDs) {
		panic("len(iters) must equal len(shardIDs)")
	}
	var sk SecondaryKeyExtractor
	if len(secondaryKeyExtractor) > 0 {
		sk = secondaryKeyExtractor[0]
	}
	h := &minHeap{}
	heap.Init(h)
	return &MergeIterator{
		iters:                 iters,
		shards:                shardIDs,
		timestampExtractor:    tsExtractor,
		secondaryKeyExtractor: sk,
		KeyExtractor:          keyExtractor,
		h:                     h,
		cursors:               make(map[string]map[string]types.AttributeValue, len(iters)),
	}
}

func (m *MergeIterator) Item() map[string]types.AttributeValue { return m.current }
func (m *MergeIterator) Err() error                            { return m.err }

// Cursors returns the per-shard LastEvaluatedKey computed from the last item emitted from that shard.
// Shards that emitted nothing in this page will be absent from the map.
func (m *MergeIterator) Cursors() map[string]map[string]types.AttributeValue { return m.cursors }

func (m *MergeIterator) Next(ctx context.Context) bool {
	if m.err != nil {
		return false
	}

	// Prime
	if !m.init {
		if !m.initializeIterators(ctx) {
			return false
		}
	}

	if m.h.Len() == 0 {
		return false
	}

	// Pop the oldest item.
	hiInterface := heap.Pop(m.h)
	hi, ok := hiInterface.(heapItem)
	if !ok {
		m.err = fmt.Errorf("unexpected type in heap: %T", hiInterface)
		return false
	}
	m.current = hi.item

	// update this shard's cursor from the emitted item
	if lastEvaluatedKey, err := m.KeyExtractor(hi.item); err != nil {
		// We still return the popped item; record the error for the *next* call.
		m.err = fmt.Errorf("key extract (shard %s): %w", m.shards[hi.idx], err)
	} else {
		m.cursors[m.shards[hi.idx]] = lastEvaluatedKey
	}

	// Advance the source iterator that produced it and push its next item.
	src := m.iters[hi.idx]
	if src.Next(ctx) {
		if !m.processNextItem(src, hi.idx) {
			return true // we already have a valid item to return
		}
	} else if err := src.Err(); err != nil {
		m.err = fmt.Errorf("iterator %d: %w", hi.idx, err)
	}

	return true
}

// In merge_query_iterator.go

// HasMore reports if the merge heap still contains items to be emitted.
func (m *MergeIterator) HasMore() bool {
	return m.h != nil && m.h.Len() > 0
}

// ShardPending reports whether each shard still has at least one item
// pending in the heap after the last Next() call.
func (m *MergeIterator) ShardPending() map[string]bool {
	// build counts by scanning heap (cheap; heap is small vs. API page size)
	pending := make(map[string]bool, len(m.shards))
	for _, hi := range *m.h {
		pending[m.shards[hi.idx]] = true
	}
	return pending
}

// heap impl: sort by timestamp, then secondary key, then iterator index (stable).
type heapItem struct {
	ts   time.Time
	key  string
	idx  int
	item map[string]types.AttributeValue
}
type minHeap []heapItem

func (h minHeap) Len() int { return len(h) }
func (h minHeap) Less(i, j int) bool {
	if !h[i].ts.Equal(h[j].ts) {
		return h[i].ts.Before(h[j].ts)
	}
	if h[i].key != "" || h[j].key != "" {
		if h[i].key != h[j].key {
			return h[i].key < h[j].key
		}
	}
	return h[i].idx < h[j].idx
}
func (h minHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *minHeap) Push(x any) {
	item, ok := x.(heapItem)
	if !ok {
		panic(fmt.Sprintf("unexpected type in heap push: %T", x))
	}
	*h = append(*h, item)
}
func (h *minHeap) Pop() any { old := *h; n := len(old); x := old[n-1]; *h = old[:n-1]; return x }

// initializeIterators initializes all iterators and populates the heap.
func (m *MergeIterator) initializeIterators(ctx context.Context) bool {
	m.init = true
	for i, it := range m.iters {
		if it.Next(ctx) {
			if !m.addItemToHeap(it, i) {
				return false
			}
		} else if err := it.Err(); err != nil {
			m.err = fmt.Errorf("iterator %d priming: %w", i, err)
			return false
		}
	}
	return true
}

// addItemToHeap adds an item from an iterator to the heap.
func (m *MergeIterator) addItemToHeap(it ItemIterator, idx int) bool {
	return m.processNextItem(it, idx)
}

// processNextItem processes the next item from an iterator and adds it to the heap.
func (m *MergeIterator) processNextItem(src ItemIterator, idx int) bool {
	next := src.Item()
	ts, err := m.timestampExtractor(next)
	if err != nil {
		m.err = fmt.Errorf("timestamp extract: iterator %d: %w", idx, err)
		return false
	}
	key := ""
	if m.secondaryKeyExtractor != nil {
		if key, err = m.secondaryKeyExtractor(next); err != nil {
			m.err = fmt.Errorf("secondary key extract: iterator %d: %w", idx, err)
			return false
		}
	}
	heap.Push(m.h, heapItem{ts: ts, key: key, idx: idx, item: next})
	return true
}
