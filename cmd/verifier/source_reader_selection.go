package verifier

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// sourceStateCleanupTimeout caps one chain's flag-off source state cleanup, which is best effort and must
// not use up the chain's startup budget when the database is slow.
const sourceStateCleanupTimeout = 10 * time.Second

// chainReader is one chain's source reader, before instrumentation, with what was resolved from it.
type chainReader struct {
	reader chainaccess.SourceReader
	// finalityReporter is nil for the RPC reader and for chains whose finality check is disabled.
	finalityReporter chainaccess.FinalityViolationReporter
	// healthReporter is nil for the RPC reader, which has no health signal of its own.
	healthReporter chainaccess.SourceHealthReporter
}

// selectChainReader gets the chain's accessor and its source reader. With the LogPoller on it sets the
// accessor's reader dependencies first, so the reader comes from the LogPoller, and a chain whose
// setter fails is skipped instead of falling back to the RPC reader. With it off, the accessor removes
// this verifier's leftover filters first, as a warning that never skips the chain. Each failure is logged here
// and returned so the caller skips the chain.
func selectChainReader(
	ctx context.Context,
	lggr logger.Logger,
	registry chainaccess.AccessorFactory,
	selector protocol.ChainSelector,
	logPollerOn bool,
	db *sql.DB,
	verifierID string,
	finalityCheckDisabled bool,
) (*chainReader, error) {
	//nolint:noeagerio // accessor construction dials the chain; it runs concurrently per chain with a bounded ctx, and failures are skipped, not fatal
	accessor, err := registry.GetAccessor(ctx, selector)
	if err != nil {
		lggr.Errorw("Failed to get accessor, skipping chain", "error", err, "selector", selector)
		return nil, err
	}

	if !logPollerOn {
		cleanUnusedSourceState(ctx, lggr, accessor, selector, chainaccess.SourceReaderDeps{DB: db, VerifierID: verifierID})
	}

	logPollerReader := false
	if logPollerOn {
		setter, ok := accessor.(chainaccess.SourceReaderDepsSetter)
		switch {
		case !ok:
			lggr.Warnw("Accessor cannot read through a LogPoller, using the RPC source reader", "selector", selector)
		default:
			if err := setter.SetSourceReaderDeps(chainaccess.SourceReaderDeps{DB: db, VerifierID: verifierID}); err != nil {
				lggr.Errorw("Failed to set source reader deps, skipping chain", "selector", selector, "error", err)
				return nil, fmt.Errorf("failed to set source reader deps for chain %d: %w", selector, err)
			}
			logPollerReader = true
		}
	}

	reader, err := accessor.SourceReader()
	if err != nil {
		lggr.Errorw("Failed to get source reader, skipping chain", "selector", selector, "error", err)
		return nil, err
	}

	result := &chainReader{reader: reader}
	readerKind := "rpc"
	if logPollerReader {
		readerKind = "logpoller"
		// A LogPoller reader's headers have no parent hash, so the header-based checker cannot be used
		// for it. The assertion runs on the raw reader because instrumentation hides its capabilities.
		if !finalityCheckDisabled {
			reporter, ok := reader.(chainaccess.FinalityViolationReporter)
			if !ok {
				err := fmt.Errorf("LogPoller source reader for chain %d does not report finality violations", selector)
				lggr.Errorw("Missing finality reporter, skipping chain", "selector", selector, "error", err)
				return nil, err
			}
			result.finalityReporter = reporter
		}
		// Health is needed even when the finality check is disabled: a LogPoller can go unhealthy after loading.
		healthReporter, ok := reader.(chainaccess.SourceHealthReporter)
		if !ok {
			err := fmt.Errorf("LogPoller source reader for chain %d does not report health", selector)
			lggr.Errorw("Missing health reporter, skipping chain", "selector", selector, "error", err)
			return nil, err
		}
		result.healthReporter = healthReporter
	}
	lggr.Infow("Source reader selected", "reader", readerKind, "chainSelector", selector)
	return result, nil
}

// cleanUnusedSourceState has the accessor remove what this verifier's database-backed source reader left
// in the database on an earlier run, since nothing reads it now. It skips an accessor without the
// capability and a missing database, and only warns on failure: leftover state must never stop the
// chain from starting.
func cleanUnusedSourceState(
	ctx context.Context,
	lggr logger.Logger,
	accessor chainaccess.Accessor,
	selector protocol.ChainSelector,
	deps chainaccess.SourceReaderDeps,
) {
	cleaner, ok := accessor.(chainaccess.UnusedSourceStateCleaner)
	if !ok || deps.DB == nil {
		return
	}
	cleanCtx, cancel := context.WithTimeout(ctx, sourceStateCleanupTimeout)
	defer cancel()
	if err := cleaner.CleanUnusedSourceState(cleanCtx, deps); err != nil {
		lggr.Warnw("Failed to clean up the unused source reader's state, continuing", "selector", selector, "verifierID", deps.VerifierID, "error", err)
	}
}
