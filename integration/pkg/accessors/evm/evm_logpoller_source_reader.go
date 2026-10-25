package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/smartcontractkit/chainlink-common/pkg/services"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	_ chainaccess.SourceReader                          = (*LogPollerSourceReader)(nil)
	_ chainaccess.CriticalSourceInvariantCallbackSetter = (*LogPollerSourceReader)(nil)
	_ chainaccess.SourceLoader                          = (*LogPollerSourceReader)(nil)
	_ chainaccess.FinalityViolationReporter             = (*LogPollerSourceReader)(nil)
	_ chainaccess.SourceHealthReporter                  = (*LogPollerSourceReader)(nil)
)

// DefaultMessageSentLogRetention is how long the log poller keeps CCIPMessageSent logs. It must
// exceed the longest expected verifier outage, or logs the verifier has not read yet are pruned.
const DefaultMessageSentLogRetention = 30 * 24 * time.Hour

// ErrLogPollerBehind is returned when a read reaches past the log poller's last processed block, so
// the caller retries instead of treating the unscanned range as scanned.
var ErrLogPollerBehind = errors.New("log poller has not reached the requested block")

// ErrLogPollerNotReady is returned by reads until the log poller filter is registered and replayed.
var ErrLogPollerNotReady = fmt.Errorf("%w: log poller filter not loaded", chainaccess.ErrSourceNotReady)

// CheckpointAboveFinalizedError fails the load while the verifier's checkpoint is above the chain's
// finalized block, as after a testnet reset. The load retries until finality reaches the checkpoint.
type CheckpointAboveFinalizedError struct {
	Checkpoint, Finalized uint64
}

func (e CheckpointAboveFinalizedError) Error() string {
	return fmt.Sprintf("checkpoint block %d is above the chain's finalized block %d", e.Checkpoint, e.Finalized)
}

const logPollerOpTimeout = 10 * time.Second

const (
	defaultLogPollerInitBackoff    = time.Second
	defaultMaxLogPollerInitBackoff = time.Minute
)

// LogPollerConfig wires a LogPollerSourceReader to the Chainlink node's log poller.
type LogPollerConfig struct {
	LogPoller  logpoller.LogPoller
	VerifierID string
	Retention  time.Duration
	// Start takes the EVM database lease and starts LogPoller, calling onHeld while the lease is held.
	// Nil means the LogPoller is already running, as in CL mode, where the node holds its own lease.
	Start func(ctx context.Context, onHeld func(error)) error
}

// NewLogPollerConfig is the one place both deployment paths build a reader config, so the
// in-node and standalone verifiers cannot drift on retention.
func NewLogPollerConfig(lp logpoller.LogPoller, verifierID string) *LogPollerConfig {
	return &LogPollerConfig{
		LogPoller:  lp,
		VerifierID: verifierID,
		Retention:  DefaultMessageSentLogRetention,
	}
}

// LogPollerEnabled reports whether the node's LogPoller feature is on for a chain. It decides both
// which source reader the verifier builds and whether it uses the log poller's finality signal.
func LogPollerEnabled(lp logpoller.LogPoller) bool {
	return lp != nil && lp != logpoller.LogPollerDisabled
}

// LogPollerSourceReader reads CCIPMessageSent logs from the node's log poller instead of eth_getLogs.
type LogPollerSourceReader struct {
	sourceReaderCore

	lp         logpoller.LogPoller
	cfg        *LogPollerConfig
	filterName string
	// ready is set once the filter is registered and the log poller replayed. It never goes back.
	ready atomic.Bool
	// loadStarted is set by LoadFrom. Before it, block reads come from the head tracker, so the start
	// block of a verifier with no checkpoint never depends on what the log poller has stored.
	loadStarted atomic.Bool
	// loadErr is the last failed load attempt, so Loaded can say why the reader is not ready.
	loadErr atomic.Pointer[error]
	// finalityBlocked is set when the startup replay hit a finality violation. The reader then counts as
	// loaded so recovery can run on it, and only a reset-reader prepare clears it.
	finalityBlocked atomic.Bool
	// initBackoff and maxInitBackoff bound the retry of a failed load; zero uses the defaults.
	initBackoff, maxInitBackoff time.Duration
	stopCh                      services.StopChan
	wg                          sync.WaitGroup
	// mu orders LoadFrom against Close so the startup goroutine never starts after Close.
	mu      sync.Mutex
	started bool
	closed  bool
}

// NewLogPollerSourceReader returns a source reader that reads logs from cfg's log poller. It starts
// nothing: LoadFrom starts the load, and reads fail with ErrLogPollerNotReady until it finishes.
func NewLogPollerSourceReader(ctx context.Context, p SourceReaderParams, cfg *LogPollerConfig) (chainaccess.SourceReader, error) {
	if cfg == nil {
		return nil, errors.New("log poller config is not set")
	}
	var errs []error
	if !LogPollerEnabled(cfg.LogPoller) {
		errs = append(errs, errors.New("log poller is not enabled"))
	}
	if cfg.VerifierID == "" {
		errs = append(errs, errors.New("log poller verifierID is not set"))
	}
	core, err := newSourceReaderCore(p)
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	r := &LogPollerSourceReader{
		sourceReaderCore: core,
		lp:               cfg.LogPoller,
		cfg:              cfg,
		filterName:       logpoller.FilterName("ccv-verifier", cfg.VerifierID, core.onRampAddress.Hex()),
		stopCh:           make(services.StopChan),
	}
	return r, nil
}

// FinalityViolated reports whether the reader's log poller has detected a finality violation. The reader's
// own block keeps the signal after the log poller clears its flag, which a later successful poll does.
func (r *LogPollerSourceReader) FinalityViolated() bool {
	return r.finalityBlocked.Load() || errors.Is(r.lp.Healthy(), commontypes.ErrFinalityViolated)
}

// Healthy returns the log poller's health without finality violations, which are reported only through
// FinalityViolated so a violation is not counted twice.
func (r *LogPollerSourceReader) Healthy() error {
	err := r.lp.Healthy()
	if errors.Is(err, commontypes.ErrFinalityViolated) {
		return nil
	}
	return err
}

// LoadFrom starts loading the log poller from startBlock, the first block the verifier reads. Only the
// first call before Close counts.
func (r *LogPollerSourceReader) LoadFrom(startBlock uint64) {
	// Set even on a closed reader, so its block reads never fall back to the head tracker.
	r.loadStarted.Store(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.closed {
		return
	}
	r.started = true
	r.wg.Go(func() { r.initLogPoller(startBlock) })
}

// Loaded returns nil once the log poller is loaded and, until then, the last failed attempt wrapped with
// ErrLogPollerNotReady, so a startup that keeps failing shows its cause in the verifier's health.
func (r *LogPollerSourceReader) Loaded() error {
	if r.ready.Load() {
		return nil
	}
	if errp := r.loadErr.Load(); errp != nil {
		return fmt.Errorf("%w: %w", ErrLogPollerNotReady, *errp)
	}
	return ErrLogPollerNotReady
}

// reportWaiting makes Loaded explain a load that is waiting, such as one waiting for the lease.
func (r *LogPollerSourceReader) reportWaiting(err error) {
	r.loadErr.Store(&err)
}

// serveErr returns why reads cannot be served from the log poller, or nil when they can.
func (r *LogPollerSourceReader) serveErr() error {
	if err := r.Loaded(); err != nil {
		return err
	}
	// The startup replay hit a finality violation, so nothing read from the log poller is safe.
	if r.finalityBlocked.Load() {
		return fmt.Errorf("chain %d: %w", r.chainSelector, commontypes.ErrFinalityViolated)
	}
	return nil
}

// initLogPoller retries loading the log poller from the start block with backoff until it succeeds or
// the reader closes.
func (r *LogPollerSourceReader) initLogPoller(from uint64) {
	ctx, cancel := r.stopCh.NewCtx()
	defer cancel()
	backoff, maxBackoff := r.retryBackoffs()
	for {
		err := r.loadLogPoller(ctx, from)
		if err == nil {
			r.ready.Store(true)
			r.lggr.Infow("Log poller ready, reading CCIPMessageSent logs from it", "filter", r.filterName)
			return
		}
		if errors.Is(err, commontypes.ErrFinalityViolated) {
			// Retrying would replay again over data the log poller declared unsafe.
			r.finalityBlocked.Store(true)
			r.ready.Store(true)
			r.lggr.Errorw("Log poller startup hit a finality violation, not retrying", "chainSelector", r.chainSelector, "filter", r.filterName, "error", err)
			return
		}
		// An attempt cut short by Close is not a cause worth reporting.
		if ctx.Err() == nil {
			r.loadErr.Store(&err)
		}
		r.lggr.Warnw("Log poller startup failed, retrying", "filter", r.filterName, "retryIn", backoff, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// retryBackoffs returns the initial and maximum retry delay of a failed load.
func (r *LogPollerSourceReader) retryBackoffs() (initial, maxBackoff time.Duration) {
	initial, maxBackoff = r.initBackoff, r.maxInitBackoff
	if initial <= 0 {
		initial = defaultLogPollerInitBackoff
	}
	if maxBackoff <= 0 {
		maxBackoff = defaultMaxLogPollerInitBackoff
	}
	return initial, max(initial, maxBackoff)
}

// loadLogPoller takes the lease and starts the log poller, then registers the filter, anchors an
// empty log poller, and replays from fromBlock. It never deletes log poller data; stale blocks are
// removed explicitly with remove-blocks.
func (r *LogPollerSourceReader) loadLogPoller(ctx context.Context, fromBlock uint64) error {
	if fromBlock > math.MaxInt64 {
		return fmt.Errorf("replay block %d is out of range for the log poller", fromBlock)
	}
	// Every step below writes to the database, so the lease comes first; Replay also needs the poll loop.
	if r.cfg.Start != nil {
		if err := r.cfg.Start(ctx, r.reportWaiting); err != nil {
			return err
		}
		// The lease is held now, so Loaded no longer reports waiting for it.
		r.loadErr.Store(nil)
	}
	if err := r.registerLogPollerFilter(ctx); err != nil {
		return err
	}
	if err := r.checkStartBlockFinalized(ctx, fromBlock); err != nil {
		return err
	}
	if err := r.anchorLogPoller(ctx, fromBlock); err != nil {
		return err
	}
	return r.replayLogPoller(ctx, fromBlock)
}

// checkStartBlockFinalized fails while the checkpoint, the block before fromBlock, is above the chain's
// finalized block. The anchor needs a finalized checkpoint, and a reader loaded there could not serve.
func (r *LogPollerSourceReader) checkStartBlockFinalized(ctx context.Context, fromBlock uint64) error {
	_, finalized, err := r.headTrackerBlocks(ctx)
	if err != nil {
		return err
	}
	if fromBlock > finalized.Number+1 {
		return CheckpointAboveFinalizedError{Checkpoint: fromBlock - 1, Finalized: finalized.Number}
	}
	return nil
}

// anchorLogPoller saves the block before fromBlock as the log poller's last processed block when it has
// none. An empty log poller starts its next poll at the chain's finalized block, so without an anchor a
// failed replay would leave the blocks from fromBlock up to there unindexed while the reader reads them.
func (r *LogPollerSourceReader) anchorLogPoller(ctx context.Context, fromBlock uint64) error {
	_, err := r.lp.LatestBlock(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get log poller latest block: %w", err)
	}
	if fromBlock < 2 {
		return nil // No block before it to anchor on; the replay covers the chain from genesis.
	}
	skipCtx, cancel := context.WithTimeout(ctx, logPollerOpTimeout)
	defer cancel()
	// fromBlock-1 is the finalized checkpoint, so SkipToBlock accepts it as the anchor.
	if err := r.lp.SkipToBlock(skipCtx, int64(fromBlock)); err != nil { // #nosec G115 -- range checked by loadLogPoller
		return fmt.Errorf("failed to anchor log poller at block %d: %w", fromBlock-1, err)
	}
	return nil
}

// registerLogPollerFilter registers the CCIPMessageSent filter with the log poller.
func (r *LogPollerSourceReader) registerLogPollerFilter(ctx context.Context) error {
	regCtx, cancel := context.WithTimeout(ctx, logPollerOpTimeout)
	defer cancel()
	if err := r.lp.RegisterFilter(regCtx, logpoller.Filter{
		Name:      r.filterName,
		Addresses: []common.Address{r.onRampAddress},
		EventSigs: []common.Hash{common.HexToHash(r.ccipMessageSentTopic)},
		Retention: r.cfg.Retention,
	}); err != nil {
		return fmt.Errorf("failed to register log poller filter %s: %w", r.filterName, err)
	}
	return nil
}

// replayLogPoller replays the log poller from fromBlock and waits for the part up to its stored finalized
// block; Replay hands the rest to the poll loop.
func (r *LogPollerSourceReader) replayLogPoller(ctx context.Context, fromBlock uint64) error {
	latest, _, err := r.headTrackerBlocks(ctx)
	if err != nil {
		return err
	}
	if fromBlock > latest.Number {
		// The checkpoint is the finalized head and the next block is not mined yet: the log poller indexes it as it arrives.
		return nil
	}
	if err := r.lp.Replay(ctx, int64(max(fromBlock, 1))); err != nil { // #nosec G115 -- range checked by loadLogPoller
		return fmt.Errorf("log poller replay from block %d failed: %w", fromBlock, err)
	}
	// Replay hands the blocks past its stored finalized block to the poll loop and drops that part's
	// errors, so a violation found there only shows in Healthy().
	if err := r.lp.Healthy(); errors.Is(err, commontypes.ErrFinalityViolated) {
		return fmt.Errorf("log poller replay from block %d: %w", fromBlock, err)
	}
	return nil
}

// Close stops loading the log poller and unregisters this reader's filter. On a restart the next start
// registers it again and replays from the checkpoint.
func (r *LogPollerSourceReader) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	close(r.stopCh)
	r.mu.Unlock()

	r.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), logPollerOpTimeout)
	defer cancel()
	if err := r.lp.UnregisterFilter(ctx, r.filterName); err != nil {
		r.lggr.Warnw("Failed to unregister log poller filter", "filter", r.filterName, "error", err)
	}
	return nil
}

// FetchMessageSentEvents returns MessageSentEvents in the given block range.
// A toBlock of 0 queries up to the last block the log poller has processed.
func (r *LogPollerSourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock uint64) ([]protocol.MessageSentEvent, error) {
	if err := r.serveErr(); err != nil {
		return nil, err
	}
	logs, err := r.logPollerLogs(ctx, fromBlock, toBlock)
	if err != nil {
		return nil, err
	}
	return r.parseMessageSentLogs(ctx, logs), nil
}

// logPollerLogs reads CCIPMessageSent logs in the given block range from the log poller.
func (r *LogPollerSourceReader) logPollerLogs(ctx context.Context, fromBlock, toBlock uint64) ([]types.Log, error) {
	if toBlock != 0 && fromBlock > toBlock {
		return nil, fmt.Errorf("invalid block range: from block %d is after to block %d", fromBlock, toBlock)
	}
	processed, err := r.logPollerBlock(ctx)
	if err != nil {
		return nil, err
	}
	end := toBlock
	if end == 0 {
		end = processed
	}
	if fromBlock > processed || end > processed {
		return nil, fmt.Errorf("%w: blocks %d-%d, log poller at %d", ErrLogPollerBehind, fromBlock, end, processed)
	}

	lpLogs, err := r.lp.LogsWithSigs(ctx, int64(fromBlock), int64(end), // #nosec G115 -- block numbers fit in int64
		[]common.Hash{common.HexToHash(r.ccipMessageSentTopic)}, r.onRampAddress)
	if err != nil {
		r.lggr.Warnw("Failed to query log poller", "error", err)
		return nil, err
	}

	logs := make([]types.Log, 0, len(lpLogs))
	for i := range lpLogs {
		l := lpLogs[i].ToGethLog()
		// ToGethLog drops the block timestamp, which parseMessageSentLogs reports as the source-block time.
		if ts := lpLogs[i].BlockTimestamp; !ts.IsZero() {
			l.BlockTimestamp = uint64(ts.Unix()) // #nosec G115 -- chain timestamps are positive
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// logPollerLatestBlock returns the last block the log poller has processed, with the finalized and safe
// block numbers it saved with it. The log poller reads those from the chain's head tracker when it polls,
// so they are the head tracker's blocks as of the last block it indexed.
func (r *LogPollerSourceReader) logPollerLatestBlock(ctx context.Context) (logpoller.Block, error) {
	b, err := r.lp.LatestBlock(ctx)
	if err != nil {
		return logpoller.Block{}, fmt.Errorf("failed to get log poller latest block: %w", err)
	}
	if b.BlockNumber < 0 || b.FinalizedBlockNumber < 0 || b.SafeBlockNumber < 0 {
		return logpoller.Block{}, fmt.Errorf("log poller block numbers cannot be negative: %d, %d, %d",
			b.BlockNumber, b.FinalizedBlockNumber, b.SafeBlockNumber)
	}
	return b, nil
}

// logPollerBlock returns the last block the log poller has processed.
func (r *LogPollerSourceReader) logPollerBlock(ctx context.Context) (uint64, error) {
	b, err := r.logPollerLatestBlock(ctx)
	return uint64(b.BlockNumber), err // #nosec G115 -- checked non-negative by logPollerLatestBlock
}

// LatestAndFinalizedBlock returns the log poller's last processed block and the finalized block saved with
// it, so the verifier never advances past logs the log poller has not indexed. Before LoadFrom it returns
// the head tracker's blocks, which the verifier derives its start block from when it has no checkpoint.
func (r *LogPollerSourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	if !r.loadStarted.Load() {
		return r.headTrackerBlocks(ctx)
	}
	if err := r.serveErr(); err != nil {
		return nil, nil, err
	}
	b, err := r.logPollerLatestBlock(ctx)
	if err != nil {
		return nil, nil, err
	}
	finalized, err = r.logPollerHeaderAt(ctx, b.FinalizedBlockNumber)
	if err != nil {
		return nil, nil, err
	}
	return logPollerHeader(b), finalized, nil
}

// LatestSafeBlock returns the safe block the log poller saved with its last processed block, or the head
// tracker's before LoadFrom.
func (r *LogPollerSourceReader) LatestSafeBlock(ctx context.Context) (*protocol.BlockHeader, error) {
	if !r.loadStarted.Load() {
		return r.headTrackerSafeBlock(ctx)
	}
	if err := r.serveErr(); err != nil {
		return nil, err
	}
	b, err := r.logPollerLatestBlock(ctx)
	if err != nil {
		return nil, err
	}
	return r.logPollerHeaderAt(ctx, b.SafeBlockNumber)
}

// logPollerHeaderAt returns the header of block n from the log poller's own blocks, which falls back to
// RPC only for a block it has not stored.
func (r *LogPollerSourceReader) logPollerHeaderAt(ctx context.Context, n int64) (*protocol.BlockHeader, error) {
	blocks, err := r.lp.GetBlocksRange(ctx, []uint64{uint64(n)}) // #nosec G115 -- checked non-negative by logPollerLatestBlock
	if err != nil {
		return nil, fmt.Errorf("failed to get log poller block %d: %w", n, err)
	}
	if len(blocks) != 1 || blocks[0].BlockNumber != n {
		return nil, fmt.Errorf("log poller block %d not found", n)
	}
	return logPollerHeader(blocks[0]), nil
}

// logPollerHeader converts a log poller block to a header. The log poller does not store parent hashes,
// so ParentHash is zero; only the header-based finality checker reads it, and log poller chains use the
// log poller's finality signal instead.
func logPollerHeader(b logpoller.Block) *protocol.BlockHeader {
	return &protocol.BlockHeader{
		Number:    uint64(b.BlockNumber), // #nosec G115 -- callers check it is non-negative
		Hash:      protocol.Bytes32(b.BlockHash),
		Timestamp: b.BlockTimestamp,
	}
}
