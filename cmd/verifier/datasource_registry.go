package verifier

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// dataSourceSetter is implemented by Accessors whose chain services need a database, which for
// EVM means the LogPoller.
type dataSourceSetter interface {
	SetDataSource(ctx context.Context, ds sqlutil.DataSource) error
}

// dataSourceRegistry wraps a Registry and hands the verifier's application-storage pool to every
// accessor that wants one, inside GetAccessor, before the caller can use the accessor.
type dataSourceRegistry struct {
	lggr  logger.Logger
	inner chainaccess.Registry
	ds    sqlutil.DataSource
}

func newDataSourceRegistry(lggr logger.Logger, inner chainaccess.Registry, ds sqlutil.DataSource) *dataSourceRegistry {
	return &dataSourceRegistry{lggr: lggr, inner: inner, ds: ds}
}

func (r *dataSourceRegistry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (chainaccess.Accessor, error) {
	accessor, err := r.inner.GetAccessor(ctx, chainSelector)
	if err != nil {
		return nil, err
	}

	setter, ok := accessor.(dataSourceSetter)
	if !ok {
		r.lggr.Debugw("Accessor takes no data source; no chain services need one",
			"chainSelector", chainSelector)
		return accessor, nil
	}

	// Called even when ds is nil: only the accessor knows whether its chain needs a database, and
	// a chain configured for the poller without one must fail rather than lose it silently.
	if err := setter.SetDataSource(ctx, r.ds); err != nil {
		if closeErr := accessor.Close(); closeErr != nil {
			r.lggr.Warnw("Failed to close accessor after data source setup failed",
				"chainSelector", chainSelector, "error", closeErr)
		}
		return nil, fmt.Errorf("failed to inject data source for chain %d: %w", chainSelector, err)
	}
	return accessor, nil
}
