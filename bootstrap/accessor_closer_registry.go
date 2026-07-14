package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// AccessorCloserRegistry wraps a chainaccess.Registry and tracks every Accessor handed out.
// Close releases the accessors and terminal resources owned by the wrapped registry.
//
// Callers must invoke Close after factory.Stop (or its equivalent) returns,
// so the factory's coordinator drains its readers first.
type AccessorCloserRegistry struct {
	lggr  logger.Logger
	inner chainaccess.Registry

	mu        sync.Mutex
	accessors []chainaccess.Accessor
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

// NewAccessorCloserRegistry wraps inner so every successful GetAccessor result is tracked.
func NewAccessorCloserRegistry(lggr logger.Logger, inner chainaccess.Registry) *AccessorCloserRegistry {
	return &AccessorCloserRegistry{lggr: lggr, inner: inner}
}

// GetAccessor delegates to the inner Registry and tracks the returned Accessor.
func (t *AccessorCloserRegistry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("accessor registry is closed")
	}
	a, err := t.inner.GetAccessor(ctx, chainSelector)
	if err != nil {
		return nil, err
	}
	t.accessors = append(t.accessors, a)
	return a, nil
}

// Close releases tracked accessors and then forwards terminal cleanup to the wrapped registry.
// It is idempotent and prevents new accessors from being obtained.
func (t *AccessorCloserRegistry) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		accessorErr := t.closeAccessors()
		t.mu.Unlock()

		var registryErr error
		if closer, ok := t.inner.(io.Closer); ok {
			registryErr = closer.Close()
		}
		t.closeErr = errors.Join(accessorErr, registryErr)
	})
	return t.closeErr
}

// closeAccessors closes the current tracked set. t.mu must be held by the caller.
func (t *AccessorCloserRegistry) closeAccessors() error {
	accessors := t.accessors
	t.accessors = nil

	if len(accessors) == 0 {
		return nil
	}

	var errs []error
	for i, a := range accessors {
		if err := a.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close accessor[%d]: %w", i, err))
		}
	}

	if err := errors.Join(errs...); err != nil {
		t.lggr.Warnw("some accessors failed to close", "error", err)
		return err
	}

	t.lggr.Infow("closed accessors", "count", len(accessors))
	return nil
}
