package cursedetector

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// GlobalCurseSubject is the constant from RMN specification representing a global curse.
// If this subject is present in cursed subjects, all lanes involving this chain are cursed.
var GlobalCurseSubject = protocol.Bytes16{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
}

// ChainCurseState holds curse state for one chain's RMN Remote.
type ChainCurseState struct {
	CursedRemoteChains map[protocol.ChainSelector]bool
	HasGlobalCurse     bool
}

// Service monitors RMN Remote contracts for curse status.
// It polls configured RMN readers at regular intervals and maintains curse state.
type Service struct {
	rmnReaders       map[protocol.ChainSelector]RMNCurseReader
	chainCurseStates map[protocol.ChainSelector]*ChainCurseState
	mutex            sync.RWMutex
	pollInterval     time.Duration
	lggr             logger.Logger
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// NewCurseDetectorService creates a new curse detector service.
//
// Parameters:
//   - rmnReaders: Map of chain selectors to RMN curse readers
//     For verifier: source chain selectors -> SourceReaders (with source RMN Remotes)
//     For executor: dest chain selectors -> DestinationReaders (with dest RMN Remotes)
//   - pollInterval: How often to poll RMN Remotes (default: 2s if <= 0)
func NewCurseDetectorService(
	rmnReaders map[protocol.ChainSelector]RMNCurseReader,
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
		pollInterval = 2 * time.Second // Default
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
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// Initial poll
	s.PollAllChains(ctx)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pollLoop(ctx)
	}()

	s.lggr.Infow("Curse detector service started",
		"pollInterval", s.pollInterval,
		"chainCount", len(s.rmnReaders))

	return nil
}

// Close stops the curse detector and waits for background goroutines to finish.
func (s *Service) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	s.lggr.Infow("Curse detector service stopped")
	return nil
}

// IsRemoteChainCursed checks if remoteChain is cursed according to localChain's RMN Remote.
// Returns true if:
//   - remoteChain appears in localChain's cursed subjects, OR
//   - localChain has a global curse
//
// Thread-safe: uses read lock for concurrent access.
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
			s.PollAllChains(ctx)
		}
	}
}

// PollAllChains queries all configured RMN Remotes and updates curse state.
// Exported for testing - allows tests to trigger synchronous updates without waiting for poll interval.
func (s *Service) PollAllChains(ctx context.Context) {
	for chainSelector, reader := range s.rmnReaders {
		subjects, err := reader.GetRMNCursedSubjects(ctx)
		if err != nil {
			s.lggr.Errorw("Failed to get cursed subjects",
				"chain", chainSelector,
				"error", err)
			continue
		}

		state := &ChainCurseState{
			CursedRemoteChains: make(map[protocol.ChainSelector]bool),
			HasGlobalCurse:     false,
		}

		for _, subject := range subjects {
			if subject == GlobalCurseSubject {
				state.HasGlobalCurse = true
				s.lggr.Warnw("Global curse detected",
					"chain", chainSelector)
			} else {
				// Extract chain selector from last 8 bytes (big-endian)
				remoteChain := protocol.ChainSelector(
					binary.BigEndian.Uint64(subject[8:]))
				state.CursedRemoteChains[remoteChain] = true
			}
		}

		s.mutex.Lock()
		s.chainCurseStates[chainSelector] = state
		s.mutex.Unlock()

		s.lggr.Debugw("Updated curse state",
			"chain", chainSelector,
			"globalCurse", state.HasGlobalCurse,
			"cursedRemoteChains", len(state.CursedRemoteChains))
	}
}
