package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/logpollerdb"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// filterCleanupTimeout caps the best-effort removal of a verifier's unused LogPoller filters.
const filterCleanupTimeout = 10 * time.Second

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
	return NewLogPollerSourceReader(ctx, *a.sourceParams, NewLogPollerConfig(lp, a.newORM(lpRuntime, db), a.verifierID))
}

// newORM is the chain's own LogPoller ORM on the EVM database, which it never closes.
func (a *accessor) newORM(rt logPollerRuntime, db *sql.DB) logpoller.ORM {
	return logpoller.NewORM(rt.EVMChainID(), logpollerdb.NewDB(db), a.lggr)
}

// cleanUnusedFilters removes the verifier's LogPoller filters on every configured chain, once per
// process and only with the LogPoller off. Failures are only logged.
func (f *factory) cleanUnusedFilters() {
	f.cleanupOnce.Do(func() {
		if f.logPollerEnabled || f.db == nil || f.verifierID == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), filterCleanupTimeout)
		defer cancel()
		if err := f.deleteVerifierFilters(ctx); err != nil {
			f.lggr.Warnw("Failed to clean up the verifier's unused LogPoller filters, continuing", "verifierID", f.verifierID, "error", err)
		}
	})
}

// deleteVerifierFilters deletes the verifier's filters on each configured chain through its ORM.
func (f *factory) deleteVerifierFilters(ctx context.Context) error {
	db, err := f.db.Value(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range f.chainIDs {
		orm := logpoller.NewORM(id, logpollerdb.NewDB(db), f.lggr)
		if err := cleanVerifierFilters(ctx, orm, f.verifierID); err != nil {
			errs = append(errs, fmt.Errorf("EVM chain %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}
