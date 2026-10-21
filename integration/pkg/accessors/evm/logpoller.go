package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/logpollerdb"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// The accessor's LogPoller-only behavior: the reader dependencies that select the LogPoller reader and
// the cleanup of the verifier's filters when the LogPoller is off.
var (
	_ chainaccess.SourceReaderDepsSetter   = (*accessor)(nil)
	_ chainaccess.UnusedSourceStateCleaner = (*accessor)(nil)
)

// SetSourceReaderDeps builds and starts the chain's LogPoller on the EVM database, which makes
// the first SourceReader call return the LogPoller reader. It does no network I/O and must come
// before SourceReader: a reader that is already built is never swapped.
func (a *accessor) SetSourceReaderDeps(deps chainaccess.SourceReaderDeps) error {
	verifierID := deps.VerifierID
	if a == nil {
		return errors.New("EVM accessor is nil")
	}
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()

	if a.sourceParams == nil {
		return fmt.Errorf("chain %d has no source reader configured", a.chainSelector)
	}
	if verifierID == "" {
		return fmt.Errorf("source reader dependencies for chain %d need a verifier ID", a.chainSelector)
	}
	if a.logPoller != nil {
		if verifierID == a.lpVerifierID {
			return nil
		}
		return fmt.Errorf("source reader dependencies for chain %d are already set to different values", a.chainSelector)
	}
	if a.sourceBuilt {
		return fmt.Errorf("source reader for chain %d is already built, set its dependencies before reading it", a.chainSelector)
	}
	lpRuntime, ok := a.runtime.(logPollerRuntime)
	if !ok {
		return fmt.Errorf("EVM chain runtime for chain %d cannot host a LogPoller", a.chainSelector)
	}

	// The LogPoller must not outlive the accessor, so its start context ends in Close.
	ctx, cancel := context.WithCancel(context.Background())
	db, err := a.evmDB(ctx)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to connect the EVM database for chain %d: %w", a.chainSelector, err)
	}
	if db == nil {
		cancel()
		return fmt.Errorf("source reader dependencies for chain %d need the EVM database ([db] in the EVM secrets file)", a.chainSelector)
	}
	lp, err := lpRuntime.LogPoller(ctx, db)
	if err != nil {
		cancel()
		return err
	}
	a.cancelLifetime = cancel
	a.logPoller = lp
	a.lpVerifierID = verifierID
	return nil
}

// newORM is the chain's own LogPoller ORM on the EVM database, which it never closes.
func (a *accessor) newORM(rt logPollerRuntime, db *sql.DB) logpoller.ORM {
	return logpoller.NewORM(rt.EVMChainID(), logpollerdb.NewDB(db), a.lggr)
}

// CleanUnusedSourceState deletes this verifier's stored log poller filters for the accessor's chain. The
// verifier calls it when it starts without the LogPoller. Filters of chains no longer configured are not
// reached: a graceful stop already unregisters them, so only a crash can leave one behind.
func (a *accessor) CleanUnusedSourceState(ctx context.Context, deps chainaccess.SourceReaderDeps) error {
	if a == nil || a.sourceParams == nil {
		return nil
	}
	lpRuntime, ok := a.runtime.(logPollerRuntime)
	if !ok {
		return nil
	}
	db, err := a.evmDB(ctx)
	if err != nil || db == nil {
		return err
	}
	// Only the LogPoller path creates the schema, so a verifier that never enabled it has no filters.
	exists, err := logPollerSchemaExists(ctx, db)
	if err != nil || !exists {
		return err
	}
	return cleanVerifierFilters(ctx, a.newORM(lpRuntime, db), deps.VerifierID)
}
