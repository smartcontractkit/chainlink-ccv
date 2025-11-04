package common

import (
	"sync"
)

// Demultiplexer manages the distribution of results from batched operations
// to individual requesters identified by unique keys.
//
// It allows callers to register interest in results for specific keys.
// When results become available, they are delivered to the appropriate
// registered channel. This is useful for implementing request batching where
// results must be routed back to their originators.
type Demultiplexer[K comparable, R any] struct {
	mu   sync.Mutex
	wait map[K]chan Result[R]
}

// NewDemultiplexer creates and returns a new Demultiplexer instance.
// The returned demultiplexer is ready to accept registrations via Create
// and can be used to resolve results via Resolve.
func NewDemultiplexer[K comparable, R any]() *Demultiplexer[K, R] {
	return &Demultiplexer[K, R]{wait: make(map[K]chan Result[R])}
}

// Create registers a new result channel for the given key and returns
// a channel that will receive the result when Resolve is called with
// the same key.
func (d *Demultiplexer[K, R]) Create(id K) chan Result[R] {
	d.mu.Lock()
	defer d.mu.Unlock()

	ch := make(chan Result[R], 1)
	d.wait[id] = ch
	return ch
}

// Resolve delivers a result to the channel registered for the given key
// via Create. If no channel was registered for the key, Resolve returns
// without effect.
//
// After delivering the result, the registered channel is removed from
// the demultiplexer and closed. Resolve must be called at most once per key.
func (d *Demultiplexer[K, R]) Resolve(id K, v R, err error) {
	d.mu.Lock()
	ch, ok := d.wait[id]
	if ok {
		delete(d.wait, id)
	}
	d.mu.Unlock()
	if ok {
		ch <- Result[R]{v: v, err: err}
		close(ch)
	}
}

// Pending returns a slice of all keys that currently have registered
// channels waiting for results. The returned keys represent operations
// that have been registered via Create but not yet resolved via Resolve.
func (d *Demultiplexer[K, R]) Pending() []K {
	d.mu.Lock()
	defer d.mu.Unlock()

	keys := make([]K, 0, len(d.wait))
	for k := range d.wait {
		keys = append(keys, k)
	}

	return keys
}

type Result[R any] struct {
	v   R
	err error
}

func NewResult[R any](v R, err error) Result[R] {
	return Result[R]{
		v: v,
		err: err,
	}
}

func (r *Result[R]) Value() R {
	return r.v
}

func (r *Result[R]) Err() error {
	return r.err
}
