package cursechecker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	DEFAULT_POLL_INTERVAL = 2 * time.Second
	// DEFAULT_RPC_TIMEOUT is the maximum time allowed for a single chain's RMN query.
	// This prevents a hanging RPC call from blocking all chains' polling.
	DEFAULT_RPC_TIMEOUT = 5 * time.Second
)

// GlobalCurseSubject is the constant from RMN specification representing a global curse.
// If this subject is present in cursed subjects, all lanes involving this chain are cursed.
var GlobalCurseSubject = [16]byte{0: 0x01, 15: 0x01}

// ChainCurseState holds curse state for one chain's RMN Remote.
type ChainCurseState struct {
	CursedRemoteChains map[protocol.ChainSelector]bool
	HasGlobalCurse     bool
}

// PollerService monitors RMN Remote contracts for curse status.
// It polls configured RMN readers at regular intervals and maintains curse state.
type PollerService struct {
	services.StateMachine
	stopCh           services.StopChan
	wg               sync.WaitGroup
	rmnReaders       map[protocol.ChainSelector]chainaccess.RMNCurseReader
	chainCurseStates map[protocol.ChainSelector]*ChainCurseState
	mutex            sync.RWMutex
	pollInterval     time.Duration
	curseRPCTimeout  time.Duration
	lggr             logger.Logger
	metrics          common.CurseCheckerMetrics
	running          atomic.Bool
}

// NewCurseDetectorService creates a new curse detector service.
//
// Parameters:
//   - rmnReaders: Map of chain selectors to RMN curse readers
//     For verifier: source chain selectors -> SourceReaders (with source RMN Remotes)
//     For executor: dest chain selectors -> DestinationReaders (with dest RMN Remotes)
//   - pollInterval: How often to poll RMN Remotes (default: DEFAULT_POLL_INTERVAL if <= 0)
//   - curseRPCTimeout: Timeout for each chain's RPC call (default: DEFAULT_RPC_TIMEOUT if <= 0)
func NewCurseDetectorService(
	rmnReaders map[protocol.ChainSelector]chainaccess.RMNCurseReader,
	pollInterval time.Duration,
	curseRPCTimeout time.Duration,
	lggr logger.Logger,
	metrics common.CurseCheckerMetrics,
) (common.CurseCheckerService, error) {
	if len(rmnReaders) == 0 {
		return nil, fmt.Errorf("at least one RMN reader required")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if pollInterval <= 0 {
		pollInterval = DEFAULT_POLL_INTERVAL
	}
	if curseRPCTimeout <= 0 {
		curseRPCTimeout = DEFAULT_RPC_TIMEOUT
	}

	return &PollerService{
		rmnReaders:       rmnReaders,
		chainCurseStates: make(map[protocol.ChainSelector]*ChainCurseState),
		pollInterval:     pollInterval,
		curseRPCTimeout:  curseRPCTimeout,
		lggr:             lggr,
		metrics:          metrics,
		stopCh:           make(chan struct{}),
	}, nil
}

// Start begins polling RMN Remote contracts for curse updates.
func (s *PollerService) Start(ctx context.Context) error {
	return s.StartOnce("cursechecker.PollerService", func() error {
		// Initial poll
		s.pollAllChains(ctx)

		s.running.Store(true)
		s.wg.Go(func() {
			s.pollLoop()
		})

		s.lggr.Infow("Curse detector service started",
			"pollInterval", s.pollInterval,
			"chainCount", len(s.rmnReaders))

		return nil
	})
}

// Close stops the curse detector and waits for background goroutines to finish.
func (s *PollerService) Close() error {
	return s.StopOnce("cursechecker.PollerService", func() error {
		s.lggr.Infow("Curse detector service stopping")

		// Signal the background goroutine to stop and wait for it to exit.
		close(s.stopCh)
		s.wg.Wait()

		// Update running state to reflect in healthcheck and readiness.
		s.running.Store(false)

		s.lggr.Infow("Curse detector service stopped")

		return nil
	})
}

// IsRemoteChainCursed checks if remoteChain is cursed according to localChain's RMN Remote.
// Returns true if:
//   - remoteChain appears in localChain's cursed subjects, OR
//   - localChain has a global curse
func (s *PollerService) IsRemoteChainCursed(_ context.Context, localChain, remoteChain protocol.ChainSelector) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	state := s.chainCurseStates[localChain]
	if state == nil {
		return false
	}

	// Match RMN contract logic: contains(remoteChain) || contains(GLOBAL_CURSE)
	return state.CursedRemoteChains[remoteChain] || state.HasGlobalCurse
}

// pollLoop runs the periodic polling loop for curse updates.
func (s *PollerService) pollLoop() {
	ctx, cancel := s.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pollAllChains(ctx)
		}
	}
}

// pollAllChains queries all configured RMN Remotes concurrently and updates curse state.
func (s *PollerService) pollAllChains(ctx context.Context) {
	var wg sync.WaitGroup

	for chainSelector, reader := range s.rmnReaders {
		wg.Add(1)
		go func(chain protocol.ChainSelector, r chainaccess.RMNCurseReader) {
			defer wg.Done()

			// Create a timeout context to prevent hanging RPC calls from blocking all chains
			timeoutCtx, cancel := context.WithTimeout(ctx, s.curseRPCTimeout)
			defer cancel()

			subjects, err := r.GetRMNCursedSubjects(timeoutCtx)
			if err != nil {
				s.lggr.Errorw("Failed to get cursed subjects",
					"chain", chain,
					"error", err)
				return
			}

			state := &ChainCurseState{
				CursedRemoteChains: make(map[protocol.ChainSelector]bool),
				HasGlobalCurse:     false,
			}

			for _, subject := range subjects {
				if subject == GlobalCurseSubject {
					state.HasGlobalCurse = true
					s.lggr.Warnw("Global curse detected",
						"chain", chain)
				} else {
					// Extract chain selector from last 8 bytes (big-endian)
					remoteChain := protocol.ChainSelector(
						binary.BigEndian.Uint64(subject[8:]))
					state.CursedRemoteChains[remoteChain] = true
				}
			}
			s.mutex.Lock()
			s.updateMetrics(ctx, chain, s.chainCurseStates[chain], state)
			s.chainCurseStates[chain] = state
			s.mutex.Unlock()

			s.lggr.Debugw("Updated curse state",
				"chain", chain,
				"globalCurse", state.HasGlobalCurse,
				"cursedRemoteChains", len(state.CursedRemoteChains))
		}(chainSelector, reader)
	}

	wg.Wait()
}

func (s *PollerService) updateMetrics(ctx context.Context, localChain protocol.ChainSelector, oldState, newState *ChainCurseState) {
	if newState == nil {
		return
	}
	s.metrics.SetLocalChainGlobalCursed(ctx, localChain, newState.HasGlobalCurse)
	for remoteSelector, cursed := range newState.CursedRemoteChains {
		s.metrics.SetRemoteChainCursed(ctx, localChain, remoteSelector, cursed)
	}
	if oldState == nil {
		return
	}
	// Unset metric if chain is no longer cursed
	for remoteSelector, oldCursed := range oldState.CursedRemoteChains {
		_, ok := newState.CursedRemoteChains[remoteSelector]
		if oldCursed && !ok {
			s.metrics.SetRemoteChainCursed(ctx, localChain, remoteSelector, false)
		}
	}
}

// Ready returns nil if the service is ready, or an error otherwise.
func (s *PollerService) Ready() error {
	if !s.running.Load() {
		return errors.New("curse detector service not running")
	}

	return nil
}

// HealthReport returns a full health report of the service.
func (s *PollerService) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()

	return report
}

// Name returns the fully qualified name of the service.
func (s *PollerService) Name() string {
	return "cursechecker.PollerService"
}

func ChainSelectorToBytes16(chainSel protocol.ChainSelector) [16]byte {
	var result [16]byte
	// Convert the uint64 to bytes and place it in the last 8 bytes of the array

	binary.BigEndian.PutUint64(result[8:], uint64(chainSel))
	return result
}
