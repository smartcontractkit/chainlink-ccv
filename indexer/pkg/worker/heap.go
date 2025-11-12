package worker

import (
	"container/heap"
	"time"
)

// DelayHeap implements a min-heap for scheduling delayed task execution.
// It orders tasks by their runAt time, with the earliest scheduled task
// at the root. This allows the worker pool to efficiently manage retries
// by enqueuing tasks that aren't ready for immediate execution.
//
// DelayHeap implements the heap.Interface from the container/heap package
// and can be used with the standard heap operations:
//
//	h := &DelayHeap{}
//	heap.Init(h)
//	heap.Push(h, task)
//	task := heap.Pop(h).(*Task)
//
// The heap maintains the index field of each Task to support efficient
// heap operations and reordering.
type DelayHeap []*Task

// Len returns the number of tasks in the heap.
func (h DelayHeap) Len() int { return len(h) }

// Less reports whether the task at index i should sort before the task at index j.
// Tasks are ordered by their runAt time, with earlier times sorting first.
func (h DelayHeap) Less(i, j int) bool { return h[i].runAt.Before(h[j].runAt) }

// Swap swaps the tasks at indices i and j and updates their index fields
// to maintain consistency with the heap structure.
func (h DelayHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].index, h[j].index = i, j }

// Push adds a task to the heap. The task's index field will be updated
// by subsequent heap operations. Push should be called through heap.Push,
// not directly.
func (h *DelayHeap) Push(x any) { *h = append(*h, x.(*Task)) }

// Pop removes and returns the task at the end of the heap slice.
// Pop should be called through heap.Pop, not directly, to ensure
// proper heap ordering. The returned task will be the one with the
// earliest runAt time after heap reordering.
func (h *DelayHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

func (h *DelayHeap) PopAllReady() []*Task {
	var ready []*Task
	for h.Len() > 0 && h.Peek().runAt.Before(time.Now()) {
		t, ok := heap.Pop(h).(*Task)
		if !ok {
			continue
		}
		ready = append(ready, t)
	}

	return ready
}

// Peek returns the task at the root of the heap (the earliest scheduled task)
// without removing it. If the heap is empty, Peek returns nil.
//
// Peek is safe to call without heap reordering, but note that the returned
// task may not be the minimum if the heap has been modified since the last
// heap.Init or heap operations.
func (h *DelayHeap) Peek() *Task {
	if len(*h) == 0 {
		return nil
	}
	return (*h)[0]
}
