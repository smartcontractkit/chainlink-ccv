package evm

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// newLogPollerSourceReader builds the chain's LogPoller on the EVM database and its reader, which takes
// the database lease and starts the LogPoller in its background load. The caller holds sourceMu.
func (a *accessor) newLogPollerSourceReader() (chainaccess.SourceReader, error) {
	if a.verifierID == "" {
		return nil, fmt.Errorf("log_poller_enabled for chain %d needs the committee verifier's verifier_id", a.chainSelector)
	}
	lpRuntime, ok := a.runtime.(logPollerRuntime)
	if !ok {
		return nil, fmt.Errorf("EVM chain runtime for chain %d cannot host a LogPoller", a.chainSelector)
	}
	// The lazy connect has its own timeout, and LogPoller.Start does not keep its ctx.
	ctx := context.Background()
	db, err := a.evmDB(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect the EVM database for chain %d: %w", a.chainSelector, err)
	}
	if db == nil {
		return nil, fmt.Errorf("log_poller_enabled for chain %d needs the EVM database ([db] in the EVM secrets file)", a.chainSelector)
	}
	if a.lease == nil {
		return nil, fmt.Errorf("log_poller_enabled for chain %d needs the EVM database lease", a.chainSelector)
	}
	lp, err := lpRuntime.LogPoller(ctx, db)
	if err != nil {
		return nil, err
	}
	cfg := NewLogPollerConfig(lp, a.verifierID)
	lease := a.lease
	cfg.Start = func(ctx context.Context, onHeld func(error)) error {
		if err := lease.Acquire(ctx, onHeld); err != nil {
			return err
		}
		return lpRuntime.StartLogPoller(ctx)
	}
	return NewLogPollerSourceReader(ctx, *a.sourceParams, cfg)
}
