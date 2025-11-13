package cursedetector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	DEFAULT_POLL_INTERVAL = 2 * time.Second
)

// GlobalCurseSubject is the constant from RMN specification representing a global curse.
// If this subject is present in cursed subjects, all lanes involving this chain are cursed.
var GlobalCurseSubject = [16]byte{0: 0x01, 15: 0x01}

// ChainCurseState holds curse state for one chain's RMN Remote.
type ChainCurseState struct {
	CursedRemoteChains map[protocol.ChainSelector]bool
	HasGlobalCurse     bool
}

// Service monitors RMN Remote contracts for curse status.
// It polls configured RMN readers at regular intervals and maintains curse state.
type Service struct {
	services.StateMachine
	rmnReaders       map[protocol.ChainSelector]chainaccess.RMNCurseReader
	chainCurseStates map[protocol.ChainSelector]*ChainCurseState
	mutex            sync.RWMutex
	pollInterval     time.Duration
	lggr             logger.Logger
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	running          atomic.Bool
}

// NewCurseDetectorService creates a new curse detector service.
//
// Parameters:
//   - rmnReaders: Map of chain selectors to RMN curse readers
//     For verifier: source chain selectors -> SourceReaders (with source RMN Remotes)
//     For executor: dest chain selectors -> DestinationReaders (with dest RMN Remotes)
//   - pollInterval: How often to poll RMN Remotes (default: DEFAULT_POLL_INTERVAL if <= 0)
func NewCurseDetectorService(
	rmnReaders map[protocol.ChainSelector]chainaccess.RMNCurseReader,
	pollInterval time.Duration,
	lggr logger.Logger,
) (CurseDetector, error) {
	if len(rmnReaders) == 0 {
		return nil, fmt.Errorf("at least one RMN reader required")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if pollInterval <= 0 {
		pollInterval = DEFAULT_POLL_INTERVAL
	}

	return &Service{
		rmnReaders:       rmnReaders,
		chainCurseStates: make(map[protocol.ChainSelector]*ChainCurseState),
		pollInterval:     pollInterval,
		lggr:             lggr,
	}, nil
}

// Start begins polling RMN Remote contracts for curse updates.
func (s *Service) Start(ctx context.Context) error {
	return s.StartOnce("cursedetector.Service", func() error {
		c, cancel := context.WithCancel(ctx)
		s.cancel = cancel

		// Initial poll
		s.pollAllChains(c)

		s.running.Store(true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.pollLoop(c)
		}()

		s.lggr.Infow("Curse detector service started",
			"pollInterval", s.pollInterval,
			"chainCount", len(s.rmnReaders))

		return nil
	})
}

// Close stops the curse detector and waits for background goroutines to finish.
func (s *Service) Close() error {
	return s.StopOnce("cursedetector.Service", func() error {
		s.lggr.Infow("Curse detector service stopping")

		// Cancel the background goroutine and wait for it to exit.
		if s.cancel != nil {
			s.cancel()
		}
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
func (s *Service) IsRemoteChainCursed(localChain, remoteChain protocol.ChainSelector) bool {
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
func (s *Service) pollLoop(ctx context.Context) {
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
func (s *Service) pollAllChains(ctx context.Context) {
	var wg sync.WaitGroup

	for chainSelector, reader := range s.rmnReaders {
		wg.Add(1)
		go func(chain protocol.ChainSelector, r chainaccess.RMNCurseReader) {
			defer wg.Done()

			subjects, err := r.GetRMNCursedSubjects(ctx)
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

func chainSelectorToBytes16(chainSel protocol.ChainSelector) [16]byte {
	var result [16]byte
	// Convert the uint64 to bytes and place it in the last 8 bytes of the array
	binary.BigEndian.PutUint64(result[8:], uint64(chainSel))
	return result
}

// Ready returns nil if the service is ready, or an error otherwise.
func (s *Service) Ready() error {
	if !s.running.Load() {
		return errors.New("curse detector service not running")
	}

	return nil
}

// HealthReport returns a full health report of the service.
func (s *Service) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()

	return report
}

// Name returns the fully qualified name of the service.
func (s *Service) Name() string {
	return "cursedetector.Service"
}
