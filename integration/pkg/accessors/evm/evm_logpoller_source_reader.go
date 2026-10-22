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
)

// DefaultMessageSentLogRetention is how long the log poller keeps CCIPMessageSent logs. It must
// exceed the longest expected verifier outage, or logs the verifier has not read yet are pruned.
const DefaultMessageSentLogRetention = 30 * 24 * time.Hour

// ErrLogPollerBehind is returned when a read reaches past the log poller's last processed block, so
// the caller retries instead of treating the unscanned range as scanned.
var ErrLogPollerBehind = errors.New("log poller has not reached the requested block")

// ErrLogPollerNotReady is returned by reads until the log poller filter is registered and replayed.
var ErrLogPollerNotReady = fmt.Errorf("%w: log poller filter not loaded", chainaccess.ErrSourceNotReady)

const (
	logPollerInitBackoff    = time.Second
	maxLogPollerInitBackoff = time.Minute
	logPollerOpTimeout      = 10 * time.Second
)

// LogPollerConfig wires a LogPollerSourceReader to the Chainlink node's log poller.
type LogPollerConfig struct {
	LogPoller  logpoller.LogPoller
	VerifierID string
	Retention  time.Duration
}

// LogPollerEnabled reports whether the node's LogPoller feature is on for a chain. It decides both
// which source reader the verifier builds and whether it uses the log poller's finality signal.
func LogPollerEnabled(lp logpoller.LogPoller) bool {
	return lp != nil && lp != logpoller.LogPollerDisabled
}

// logPollerFinality reports the finality violations the node's log poller detects.
type logPollerFinality struct {
	lp logpoller.LogPoller
}

// NewLogPollerFinality returns the log poller's finality signal, or nil when the log poller is disabled.
func NewLogPollerFinality(lp logpoller.LogPoller) chainaccess.FinalityViolationReporter {
	if !LogPollerEnabled(lp) {
		return nil
	}
	return logPollerFinality{lp: lp}
}

func (f logPollerFinality) FinalityViolated() bool {
	return errors.Is(f.lp.Healthy(), commontypes.ErrFinalityViolated)
}

// LogPollerSourceReader reads CCIPMessageSent logs from the node's log poller instead of eth_getLogs.
type LogPollerSourceReader struct {
	sourceReaderCore

	lp         logpoller.LogPoller
	cfg        *LogPollerConfig
	filterName string
	// ready is set once the filter is registered and the log poller replayed.
	ready  atomic.Bool
	stopCh services.StopChan
	wg     sync.WaitGroup
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

// LoadFrom starts loading the log poller from startBlock, the first block the verifier reads. Only the
// first call before Close counts.
func (r *LogPollerSourceReader) LoadFrom(startBlock uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.closed {
		return
	}
	r.started = true
	r.wg.Go(func() { r.initLogPoller(startBlock) })
}

// Loaded returns nil once the log poller is loaded and ErrLogPollerNotReady until then, so a startup that
// keeps failing shows in the verifier's health.
func (r *LogPollerSourceReader) Loaded() error {
	if r.ready.Load() {
		return nil
	}
	return ErrLogPollerNotReady
}

// initLogPoller retries loading the log poller from the start block with backoff until it succeeds or
// the reader closes.
func (r *LogPollerSourceReader) initLogPoller(from uint64) {
	ctx, cancel := r.stopCh.NewCtx()
	defer cancel()
	backoff := logPollerInitBackoff
	for {
		err := r.loadLogPoller(ctx, from)
		if err == nil {
			r.ready.Store(true)
			r.lggr.Infow("Log poller ready, reading CCIPMessageSent logs from it", "filter", r.filterName)
			return
		}
		r.lggr.Warnw("Log poller startup failed, retrying", "filter", r.filterName, "retryIn", backoff, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxLogPollerInitBackoff)
	}
}

// loadLogPoller registers the filter, anchors an empty log poller, and replays from fromBlock.
// It never deletes log poller data; stale blocks are removed explicitly with remove-blocks.
func (r *LogPollerSourceReader) loadLogPoller(ctx context.Context, fromBlock uint64) error {
	if fromBlock > math.MaxInt64 {
		return fmt.Errorf("replay block %d is out of range for the log poller", fromBlock)
	}
	if err := r.registerLogPollerFilter(ctx); err != nil {
		return err
	}
	if err := r.anchorLogPoller(ctx, fromBlock); err != nil {
		return err
	}
	return r.replayLogPoller(ctx, fromBlock)
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

// replayLogPoller replays the log poller from fromBlock up to its latest finalized block and waits for it.
func (r *LogPollerSourceReader) replayLogPoller(ctx context.Context, fromBlock uint64) error {
	latest, _, err := r.headTrackerBlocks(ctx)
	if err != nil {
		return err
	}
	if fromBlock > latest.Number {
		return nil // Not mined yet: the log poller indexes it as it arrives.
	}
	// A finality violation here is declared on the log poller itself, so Healthy() reports it.
	if err := r.lp.Replay(ctx, int64(max(fromBlock, 1))); err != nil { // #nosec G115 -- range checked by loadLogPoller
		return fmt.Errorf("log poller replay from block %d failed: %w", fromBlock, err)
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
// A toBlock of 0 queries up to the last block the log poller has processed. After a critical
// invariant violation the reader is disabled and every call fails with chainaccess.ErrSourceReaderDisabled.
func (r *LogPollerSourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock uint64) ([]protocol.MessageSentEvent, error) {
	if err := r.disabledErr(); err != nil {
		return nil, err
	}
	if !r.ready.Load() {
		return nil, ErrLogPollerNotReady
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
// it, so the verifier never advances past logs the log poller has not indexed.
func (r *LogPollerSourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
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

// LatestSafeBlock returns the safe block the log poller saved with its last processed block.
func (r *LogPollerSourceReader) LatestSafeBlock(ctx context.Context) (*protocol.BlockHeader, error) {
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
