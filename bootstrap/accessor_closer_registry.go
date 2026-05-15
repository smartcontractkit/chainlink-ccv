package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// AccessorCloserRegistry wraps a chainaccess.Registry, tracks every Accessor handed
// out, and closes them all via CloseAll at shutdown.
//
// Callers must invoke CloseAll after factory.Stop (or its equivalent) returns,
// so the factory's coordinator drains its readers first.
type AccessorCloserRegistry struct {
	lggr  logger.Logger
	inner chainaccess.Registry

	mu        sync.Mutex
	accessors []chainaccess.Accessor
}

// NewAccessorCloserRegistry wraps inner so every successful GetAccessor result is tracked.
func NewAccessorCloserRegistry(lggr logger.Logger, inner chainaccess.Registry) *AccessorCloserRegistry {
	return &AccessorCloserRegistry{lggr: lggr, inner: inner}
}

// GetAccessor delegates to the inner Registry and tracks the returned Accessor.
func (t *AccessorCloserRegistry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, err := t.inner.GetAccessor(ctx, chainSelector)
	if err != nil {
		return nil, err
	}
	t.accessors = append(t.accessors, a)
	return a, nil
}

// CloseAll closes every Accessor handed out since construction or the last successful CloseAll.
// A second CloseAll with no intervening GetAccessor returns nil.
func (t *AccessorCloserRegistry) CloseAll() error {
	t.mu.Lock()
	defer t.mu.Unlock()

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
