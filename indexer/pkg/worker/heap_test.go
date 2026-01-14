package worker

import (
	"container/heap"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestTaskAt(t time.Time) *Task {
	return &Task{runAt: t}
}

// TestDelayHeap_PushPopPeekOrdering verifies ordering semantics of the delay heap
// when pushing and popping tasks with different runAt times.
func TestDelayHeap_PushPopPeekOrdering(t *testing.T) {
	h := &DelayHeap{}
	heap.Init(h)

	now := time.Now()
	one := newTestTaskAt(now.Add(time.Second))
	two := newTestTaskAt(now.Add(2 * time.Second))
	zero := newTestTaskAt(now.Add(-time.Second))

	heap.Push(h, two)
	heap.Push(h, one)
	heap.Push(h, zero)

	// Peek should show the earliest (zero)
	p := h.Peek()
	require.NotNil(t, p)
	require.Equal(t, zero.runAt, p.runAt)

	// Pop order should be zero, one, two
	p0 := heap.Pop(h).(*Task)
	require.Equal(t, zero.runAt, p0.runAt)
	p1 := heap.Pop(h).(*Task)
	require.Equal(t, one.runAt, p1.runAt)
	p2 := heap.Pop(h).(*Task)
	require.Equal(t, two.runAt, p2.runAt)

	// popped tasks should have index -1
	require.Equal(t, -1, p0.index)
	require.Equal(t, -1, p1.index)
	require.Equal(t, -1, p2.index)
}

// TestDelayHeap_PeekEmpty ensures Peek returns nil for an empty heap.
func TestDelayHeap_PeekEmpty(t *testing.T) {
	h := &DelayHeap{}
	heap.Init(h)
	require.Nil(t, h.Peek())
}

// TestDelayHeap_PopAllReady verifies PopAllReady returns all tasks whose runAt is <= now
// and preserves their ordering.
func TestDelayHeap_PopAllReady(t *testing.T) {
	h := &DelayHeap{}
	heap.Init(h)

	now := time.Now()
	ready1 := newTestTaskAt(now.Add(-time.Second))
	ready2 := newTestTaskAt(now.Add(-2 * time.Second))
	future := newTestTaskAt(now.Add(5 * time.Second))

	heap.Push(h, future)
	heap.Push(h, ready1)
	heap.Push(h, ready2)

	// ensure heap invariant
	// PopAllReady should return ready2 and ready1 (ordered by runAt)
	ready := h.PopAllReady()
	require.Len(t, ready, 2)
	require.Equal(t, ready2.runAt, ready[0].runAt)
	require.Equal(t, ready1.runAt, ready[1].runAt)

	// future remains
	require.Equal(t, 1, h.Len())
	p := h.Peek()
	require.Equal(t, future.runAt, p.runAt)
}

// TestDelayHeap_PushWrongTypePanics verifies that pushing a non-*Task panics.
func TestDelayHeap_PushWrongTypePanics(t *testing.T) {
	defer func() {
		recover()
	}()
	// Using interface{} instead of *Task should panic
	h := &DelayHeap{}
	heap.Init(h)
	heap.Push(h, "not a task")
	t.Fatal("expected panic")
}
