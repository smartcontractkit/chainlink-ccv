package evm

import (
	"context"
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
	// FilterRegistered reports whether the node has already stored the named log poller filter.
	FilterRegistered func(ctx context.Context, name string) (bool, error)
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
	if cfg.FilterRegistered == nil {
		errs = append(errs, errors.New("log poller filter lookup is not set"))
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

// logPollerLoad is fixed on the first attempt, so a retry does not mistake this reader's own
// registration for a pre-existing filter.
type logPollerLoad struct {
	fromBlock     uint64
	filterExisted bool
}

// initLogPoller retries loading the log poller from the start block with backoff until it succeeds or
// the reader closes.
func (r *LogPollerSourceReader) initLogPoller(from uint64) {
	ctx, cancel := r.stopCh.NewCtx()
	defer cancel()
	var load *logPollerLoad
	backoff := logPollerInitBackoff
	for {
		var err error
		if load == nil {
			load, err = r.planLogPollerLoad(ctx, from)
		}
		if err == nil {
			err = r.loadLogPoller(ctx, *load)
		}
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

func (r *LogPollerSourceReader) planLogPollerLoad(ctx context.Context, from uint64) (*logPollerLoad, error) {
	existed, err := r.cfg.FilterRegistered(ctx, r.filterName)
	if err != nil {
		return nil, fmt.Errorf("failed to check log poller filter %s: %w", r.filterName, err)
	}
	return &logPollerLoad{fromBlock: from, filterExisted: existed}, nil
}

// loadLogPoller registers the filter and replays the log poller from the start block. A pre-existing
// filter first has the log poller's logs and blocks from the start block deleted, so they are re-fetched.
func (r *LogPollerSourceReader) loadLogPoller(ctx context.Context, load logPollerLoad) error {
	if load.fromBlock > math.MaxInt64 {
		return fmt.Errorf("replay block %d is out of range for the log poller", load.fromBlock)
	}
	if err := r.registerLogPollerFilter(ctx); err != nil {
		return err
	}
	if load.filterExisted {
		if err := r.lp.DeleteLogsAndBlocksAfter(ctx, int64(load.fromBlock)); err != nil { // #nosec G115 -- range checked above
			return fmt.Errorf("failed to delete log poller data from block %d: %w", load.fromBlock, err)
		}
	}
	return r.replayLogPoller(ctx, load.fromBlock)
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
// A toBlock of 0 queries up to the last block the log poller has processed.
func (r *LogPollerSourceReader) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock uint64) ([]protocol.MessageSentEvent, error) {
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

// logPollerBlocks returns the last block the log poller has processed and the finalized and safe
// blocks it saved with it. Only the finalized and safe blocks are certain to be on the canonical
// chain: the processed block can still be on a fork the log poller has not reorged away from.
func (r *LogPollerSourceReader) logPollerBlocks(ctx context.Context) (processed, finalized, safe uint64, err error) {
	b, err := r.lp.LatestBlock(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to get log poller latest block: %w", err)
	}
	if b.BlockNumber < 0 || b.FinalizedBlockNumber < 0 || b.SafeBlockNumber < 0 {
		return 0, 0, 0, fmt.Errorf("log poller block numbers cannot be negative: %d, %d, %d",
			b.BlockNumber, b.FinalizedBlockNumber, b.SafeBlockNumber)
	}
	return uint64(b.BlockNumber), uint64(b.FinalizedBlockNumber), uint64(b.SafeBlockNumber), nil
}

// logPollerBlock returns the last block the log poller has processed.
func (r *LogPollerSourceReader) logPollerBlock(ctx context.Context) (uint64, error) {
	processed, _, _, err := r.logPollerBlocks(ctx)
	return processed, err
}

// LatestAndFinalizedBlock returns the head tracker's latest and finalized block headers, so the verifier
// never advances past logs the log poller has not indexed. Latest is capped at the log poller's last
// processed block and finalized at its own finalized block, which a pending reorg cannot change.
func (r *LogPollerSourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	latest, finalized, err = r.headTrackerBlocks(ctx)
	if err != nil {
		return nil, nil, err
	}

	processed, lpFinalized, _, err := r.logPollerBlocks(ctx)
	if err != nil {
		return nil, nil, err
	}
	if processed < latest.Number || lpFinalized < finalized.Number {
		r.lggr.Debugw("Log poller is behind the head tracker, capping blocks", "logPollerBlock", processed,
			"logPollerFinalized", lpFinalized, "latest", latest.Number, "finalized", finalized.Number)
	}
	if processed < latest.Number {
		if latest, err = r.headerAt(ctx, processed); err != nil {
			return nil, nil, err
		}
	}
	if lpFinalized < finalized.Number {
		if finalized, err = r.headerAt(ctx, lpFinalized); err != nil {
			return nil, nil, err
		}
	}
	return latest, finalized, nil
}

// LatestSafeBlock returns the head tracker's safe block header, not above the safe block the log
// poller saved. Returns nil without an error when the chain does not support the safe tag.
func (r *LogPollerSourceReader) LatestSafeBlock(ctx context.Context) (*protocol.BlockHeader, error) {
	safe, err := r.headTrackerSafeBlock(ctx)
	if err != nil || safe == nil {
		return safe, err
	}

	_, _, lpSafe, err := r.logPollerBlocks(ctx)
	if err != nil {
		return nil, err
	}
	if lpSafe >= safe.Number {
		return safe, nil
	}
	return r.headerAt(ctx, lpSafe)
}

// headerAt returns the header of block n.
func (r *LogPollerSourceReader) headerAt(ctx context.Context, n uint64) (*protocol.BlockHeader, error) {
	headers, err := r.GetBlocksHeaders(ctx, []uint64{n})
	if err != nil {
		return nil, err
	}
	h, ok := headers[n]
	if !ok {
		return nil, fmt.Errorf("header for block %d not found", n)
	}
	return &h, nil
}
