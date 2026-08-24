package chainstatus

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// DefaultFlushInterval is how frequently the batcher writes buffered chain statuses.
	DefaultFlushInterval = 30 * time.Second
	// closeFlushTimeout bounds the final flush that runs during Close.
	closeFlushTimeout = 10 * time.Second
)

var (
	_ protocol.ChainStatusManager = (*Batcher)(nil)
	_ protocol.HealthReporter     = (*Batcher)(nil)
)

// Batcher is a decorator that collects chain statuses in memory and
// writes them to the wrapped manager on a timer.
//
// Chain status is latest-value data, so the batcher keeps only the newest value
// for each chain. A status with Disabled set to true is written immediately,
// because the verifier must stop the chain without a delay.
type Batcher struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr          logger.Logger
	manager       protocol.ChainStatusManager
	flushInterval time.Duration

	// mu guards pending. Hold it only for map operations, never across a call
	// to the wrapped manager.
	mu      sync.Mutex
	pending map[protocol.ChainSelector]protocol.ChainStatusInfo
	// disabledChains records the chains that this batcher has disabled. A disable is
	// one-way: a later checkpoint write must not clear it. Only an operator re-enables
	// a chain, through PostgresChainStatusStore.SetDisabled.
	disabledChains map[protocol.ChainSelector]bool

	// flushMu serializes flushes. The ticker goroutine and a caller goroutine
	// that writes a disabled status can flush at the same time. Without this
	// lock, an older batch can reach the database after a newer one and undo it.
	flushMu sync.Mutex
}

// copyStatus makes a deep copy of a chain status. ChainStatusInfo holds a
// *big.Int, so the caller and the batcher must not share that pointer.
func copyStatus(status protocol.ChainStatusInfo) protocol.ChainStatusInfo {
	out := status
	if status.FinalizedBlockHeight != nil {
		out.FinalizedBlockHeight = new(big.Int).Set(status.FinalizedBlockHeight)
	}
	return out
}

// NewChainStatusBatcher creates a new ChainStatusBatcher around the given manager.
func NewChainStatusBatcher(
	lggr logger.Logger,
	manager protocol.ChainStatusManager,
	flushInterval time.Duration,
) (*Batcher, error) {
	if lggr == nil {
		return nil, errors.New("logger is required")
	}
	if manager == nil {
		return nil, errors.New("chain status manager is required")
	}
	if flushInterval <= 0 {
		return nil, errors.New("flush interval must be positive")
	}

	return &Batcher{
		lggr:           logger.With(lggr, "component", "ChainStatusBatcher"),
		manager:        manager,
		flushInterval:  flushInterval,
		pending:        make(map[protocol.ChainSelector]protocol.ChainStatusInfo),
		disabledChains: make(map[protocol.ChainSelector]bool),
		stopCh:         make(chan struct{}),
	}, nil
}

// Start starts the background flush loop.
func (s *Batcher) Start(context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run()
		})
		return nil
	})
}

// Close stops the flush loop and writes the statuses that remain in the buffer.
func (s *Batcher) Close() error {
	return s.StopOnce(s.Name(), func() error {
		close(s.stopCh)
		s.wg.Wait()

		ctx, cancel := context.WithTimeout(context.Background(), closeFlushTimeout)
		defer cancel()

		if err := s.flush(ctx); err != nil {
			s.lggr.Errorw("Failed to flush chain statuses on close", "error", err)
			return err
		}
		return nil
	})
}

// Name returns the service name.
func (s *Batcher) Name() string {
	return "verifier.ChainStatusBatcher"
}

// HealthReport returns a health report for the batcher.
func (s *Batcher) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

func (s *Batcher) run() {
	ctx, cancel := s.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.lggr.Infow("ChainStatusBatcher close signal received, shutting down")
			return

		case <-ticker.C:
			if err := s.flush(ctx); err != nil {
				s.lggr.Errorw("Failed to flush chain statuses", "error", err)
			}
		}
	}
}

// WriteChainStatuses buffers the given statuses.
//
// A disabled status is safety-critical, so it is not batched with anything else:
// it is written on its own, at once, and its error is returned to the caller. A
// database error caused by another chain's buffered row must not stop a chain from
// being disabled after a finality violation.
func (s *Batcher) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	if len(statuses) == 0 {
		return nil
	}

	var disabled []protocol.ChainStatusInfo

	s.mu.Lock()
	for _, status := range statuses {
		// A chain disabled after a finality violation must stay disabled. The source
		// reader sends Disabled as false on every checkpoint, so a checkpoint that is
		// buffered or retried after the disable would otherwise re-enable the chain.
		if s.disabledChains[status.ChainSelector] && !status.Disabled {
			s.lggr.Warnw("Dropped chain status that would re-enable a disabled chain",
				"chainSelector", status.ChainSelector.String())
			continue
		}
		if status.Disabled {
			s.disabledChains[status.ChainSelector] = true
			// Drop any buffered status for this chain: a later flush of it would
			// undo the disable.
			delete(s.pending, status.ChainSelector)
			disabled = append(disabled, copyStatus(status))
			continue
		}
		s.pending[status.ChainSelector] = copyStatus(status)
	}
	s.mu.Unlock()

	if len(disabled) == 0 {
		return nil
	}

	// Hold flushMu so this write keeps its order against the ticker flushes.
	s.flushMu.Lock()
	err := s.manager.WriteChainStatuses(ctx, disabled)
	s.flushMu.Unlock()

	if err != nil {
		// Buffer them so the ticker retries. The sticky flag keeps the chain disabled
		// in memory in the meantime.
		s.mu.Lock()
		for _, status := range disabled {
			if _, ok := s.pending[status.ChainSelector]; !ok {
				s.pending[status.ChainSelector] = status
			}
		}
		s.mu.Unlock()
		return fmt.Errorf("failed to write disabled chain statuses: %w", err)
	}

	// The rest is best effort. The ticker retries it, and a failure here must not
	// change the result of the disable write above.
	if flushErr := s.flush(ctx); flushErr != nil {
		s.lggr.Errorw("Failed to flush buffered chain statuses after a disable", "error", flushErr)
	}
	return nil
}

// ReadChainStatuses passes the read through to the wrapped manager.
func (s *Batcher) ReadChainStatuses(
	ctx context.Context,
	chainSelectors []protocol.ChainSelector,
) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	return s.manager.ReadChainStatuses(ctx, chainSelectors)
}

// flush drains the buffer and writes it to the wrapped manager. On failure, the
// drained statuses go back into the buffer, so the next tick retries them.
func (s *Batcher) flush(ctx context.Context) error {
	// Serialize flushes so batches reach the wrapped manager in drain order.
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	s.mu.Lock()
	drained := s.pending
	s.pending = make(map[protocol.ChainSelector]protocol.ChainStatusInfo)
	s.mu.Unlock()

	if len(drained) == 0 {
		return nil
	}

	batch := make([]protocol.ChainStatusInfo, 0, len(drained))
	for _, status := range drained {
		batch = append(batch, copyStatus(status))
	}

	if err := s.manager.WriteChainStatuses(ctx, batch); err != nil {
		s.restore(drained)
		return err
	}

	s.lggr.Debugw("Flushed chain statuses", "count", len(batch))
	return nil
}

// restore puts the given statuses back into the buffer. A chain that already has
// a newer value in the buffer keeps that newer value.
func (s *Batcher) restore(drained map[protocol.ChainSelector]protocol.ChainStatusInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for selector, status := range drained {
		if s.disabledChains[selector] && !status.Disabled {
			continue
		}
		if _, ok := s.pending[selector]; !ok {
			s.pending[selector] = status
		}
	}
}
