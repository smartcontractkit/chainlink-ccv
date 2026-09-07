// Package lazy provides a small, concurrency-safe memoization primitive that
// derives a value on first use and caches it thereafter.
//
// Unlike sync.Once, a failed derivation is NOT cached: each use re-attempts the
// derivation until one succeeds, so callers self-heal once an underlying
// dependency (e.g. an RPC) recovers. This makes Lazy a good fit for deferring
// on-chain or config reads out of constructors and into query time.
package lazy

import (
	"context"
	"sync"
)

// Lazy derives a value of type V on first successful use and caches it.
//
// The derivation is guarded by a mutex and performed at most once (on the first
// call that succeeds). Thread-safe.
type Lazy[V any] struct {
	derive func(ctx context.Context) (V, error)

	mu          sync.Mutex
	value       V
	derivedOnce bool
}

// New builds a Lazy that derives its value via derive. derive must not be nil.
func New[V any](derive func(ctx context.Context) (V, error)) *Lazy[V] {
	return &Lazy[V]{derive: derive}
}

// Value returns the derived value, deriving it on the first successful call. On
// a transient derivation failure it returns the error and does not cache it, so
// a later call retries.
func (l *Lazy[V]) Value(ctx context.Context) (V, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.derivedOnce {
		v, err := l.derive(ctx)
		if err != nil {
			var zero V
			return zero, err
		}
		l.value = v
		l.derivedOnce = true
	}
	return l.value, nil
}

// Derived reports whether a derivation has succeeded. Used mostly in tests.
func (l *Lazy[V]) Derived() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.derivedOnce
}
