package chainstatus

import (
	"context"
	"errors"
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
	_ protocol.ChainStatusManager = (*ChainStatusBatcher)(nil)
	_ protocol.HealthReporter     = (*ChainStatusBatcher)(nil)
)

// ChainStatusBatcher is a decorator that collects chain statuses in memory and
// writes them to the wrapped manager on a timer.
//
// Chain status is latest-value data, so the batcher keeps only the newest value
// for each chain. A status with Disabled set to true is written immediately,
// because the verifier must stop the chain without a delay.
type ChainStatusBatcher struct {
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
) (*ChainStatusBatcher, error) {
	if lggr == nil {
		return nil, errors.New("logger is required")
	}
	if manager == nil {
		return nil, errors.New("chain status manager is required")
	}
	if flushInterval <= 0 {
		return nil, errors.New("flush interval must be positive")
	}

	return &ChainStatusBatcher{
		lggr:          logger.With(lggr, "component", "ChainStatusBatcher"),
		manager:       manager,
		flushInterval: flushInterval,
		pending:       make(map[protocol.ChainSelector]protocol.ChainStatusInfo),
		stopCh:        make(chan struct{}),
	}, nil
}

// Start starts the background flush loop.
func (s *ChainStatusBatcher) Start(context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run()
		})
		return nil
	})
}

// Close stops the flush loop and writes the statuses that remain in the buffer.
func (s *ChainStatusBatcher) Close() error {
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
func (s *ChainStatusBatcher) Name() string {
	return "verifier.ChainStatusBatcher"
}

// HealthReport returns a health report for the batcher.
func (s *ChainStatusBatcher) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

func (s *ChainStatusBatcher) run() {
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

// WriteChainStatuses buffers the given statuses. If any status is disabled, the
// batcher writes the full buffer immediately and returns the write error.
func (s *ChainStatusBatcher) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	if len(statuses) == 0 {
		return nil
	}

	immediate := false

	s.mu.Lock()
	for _, status := range statuses {
		s.pending[status.ChainSelector] = copyStatus(status)
		if status.Disabled {
			immediate = true
		}
	}
	s.mu.Unlock()

	if immediate {
		return s.flush(ctx)
	}
	return nil
}

// ReadChainStatuses passes the read through to the wrapped manager.
func (s *ChainStatusBatcher) ReadChainStatuses(
	ctx context.Context,
	chainSelectors []protocol.ChainSelector,
) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	return s.manager.ReadChainStatuses(ctx, chainSelectors)
}

// flush drains the buffer and writes it to the wrapped manager. On failure, the
// drained statuses go back into the buffer, so the next tick retries them.
func (s *ChainStatusBatcher) flush(ctx context.Context) error {
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
func (s *ChainStatusBatcher) restore(drained map[protocol.ChainSelector]protocol.ChainStatusInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for selector, status := range drained {
		if _, ok := s.pending[selector]; !ok {
			s.pending[selector] = status
		}
	}
}
