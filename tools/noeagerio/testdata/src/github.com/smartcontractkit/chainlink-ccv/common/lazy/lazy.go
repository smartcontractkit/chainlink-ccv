// Package lazy mirrors github.com/smartcontractkit/chainlink-ccv/common/lazy
// for analyzer tests: New only registers the derivation for query time.
package lazy

import "context"

type Lazy[V any] struct {
	derive func(ctx context.Context) (V, error)
}

func New[V any](derive func(ctx context.Context) (V, error)) *Lazy[V] {
	return &Lazy[V]{derive: derive}
}

func (l *Lazy[V]) Value(ctx context.Context) (V, error) {
	return l.derive(ctx)
}
