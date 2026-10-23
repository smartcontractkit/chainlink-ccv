package evm

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// newLogPollerSourceReader starts the chain's LogPoller on the EVM database and builds its reader.
// The caller holds sourceMu.
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
	lp, err := lpRuntime.LogPoller(ctx, db)
	if err != nil {
		return nil, err
	}
	return NewLogPollerSourceReader(ctx, *a.sourceParams, NewLogPollerConfig(lp, a.verifierID))
}
