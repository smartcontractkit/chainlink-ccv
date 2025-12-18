package verifier

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/smartcontractkit/chainlink-ccv/common"
	cursecheckerimpl "github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

type sourceState struct {
	readerService *SourceReaderService
	readyTasksCh  <-chan batcher.BatchResult[VerificationTask]
	chainSelector protocol.ChainSelector
}

func (s *sourceState) Close() error {
	if s == nil {
		return nil
	}
	if s.readerService != nil {
		return s.readerService.Stop()
	}
	return nil
}

type Coordinator struct {
	services.StateMachine

	cancel context.CancelFunc

	verifier       Verifier
	storage        protocol.CCVNodeDataWriter
	lggr           logger.Logger
	monitoring     Monitoring
	messageTracker MessageLatencyTracker
	config         CoordinatorConfig

	// Per-chain state
	sourceStates map[protocol.ChainSelector]*sourceState

	// Dependencies
	sourceReaders      map[protocol.ChainSelector]chainaccess.SourceReader
	chainStatusManager protocol.ChainStatusManager

	// Curse detector is created & owned by coordinator
	curseDetector common.CurseCheckerService

	// 2nd step processor: task verifier
	taskVerifierProcessor *TaskVerifierProcessor
	// 3rd step processor: storage writer
	storageWriterProcessor *StorageWriterProcessor
	storageBatcher         *batcher.Batcher[protocol.VerifierNodeResult]
}

type Option func(*Coordinator)

func WithCurseDetector(detector common.CurseCheckerService) Option {
	return func(vc *Coordinator) {
		vc.curseDetector = detector
	}
}

func NewCoordinator(
	lggr logger.Logger,
	verifier Verifier,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
	messageTracker MessageLatencyTracker,
	monitoring Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	opts ...Option,
) (*Coordinator, error) {
	vc := &Coordinator{
		lggr:               lggr,
		verifier:           verifier,
		sourceReaders:      sourceReaders,
		chainStatusManager: chainStatusManager,
		storage:            storage,
		config:             config,
		messageTracker:     messageTracker,
		monitoring:         monitoring,
		sourceStates:       make(map[protocol.ChainSelector]*sourceState),
	}

	for _, opt := range opts {
		opt(vc)
	}

	if err := vc.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	return vc, nil
}

func (vc *Coordinator) validateConfig() error {
	if vc.verifier == nil {
		return errors.New("verifier is required")
	}
	if vc.storage == nil {
		return errors.New("storage is required")
	}
	if vc.lggr == nil {
		return errors.New("logger is required")
	}
	if vc.config.SourceConfigs == nil {
		return errors.New("source configs are required")
	}

	return nil
}

func (vc *Coordinator) Start(_ context.Context) error {
	return vc.StartOnce(vc.Name(), func() error {
		vc.lggr.Infow("Starting verifier coordinator")

		c, cancel := context.WithCancel(context.Background())
		vc.cancel = cancel

		statusMap := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
		if vc.chainStatusManager != nil {
			allSelectors := make([]protocol.ChainSelector, 0, len(vc.sourceReaders))
			for selector := range vc.sourceReaders {
				allSelectors = append(allSelectors, selector)
			}

			var err error
			statusMap, err = vc.chainStatusManager.ReadChainStatuses(c, allSelectors)
			if err != nil {
				vc.lggr.Errorw("Failed to read chain statuses, proceeding with all chains",
					"error", err)
			}
		}

		enabledSourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
		for chainSelector, sourceReader := range vc.sourceReaders {
			if sourceReader == nil {
				continue
			}
			vc.lggr.Infow("Chain Status",
				"chainSelector", chainSelector,
				"status", statusMap[chainSelector])

			// Skip disabled chains
			if chainStatus, ok := statusMap[chainSelector]; ok && chainStatus.Disabled {
				vc.lggr.Warnw("Chain is disabled in aggregator DB, skipping initialization",
					"chain", chainSelector,
					"blockHeight", chainStatus.FinalizedBlockHeight)
				continue
			}

			_, ok := vc.config.SourceConfigs[chainSelector]
			if !ok {
				vc.lggr.Warnw("No source config for chain selector, skipping",
					"chainSelector", chainSelector)
				continue
			}

			enabledSourceReaders[chainSelector] = sourceReader
		}

		if len(enabledSourceReaders) == 0 {
			return errors.New("no enabled/initialized chain sources, nothing to coordinate")
		}

		if err := vc.startCurseDetector(c, enabledSourceReaders); err != nil {
			return fmt.Errorf("failed to start curse detector: %w", err)
		}

		for chainSelector := range enabledSourceReaders {
			sourceReader := enabledSourceReaders[chainSelector]
			sourceCfg := vc.config.SourceConfigs[chainSelector]

			filter := chainaccess.NewReceiptIssuerFilter(
				sourceCfg.VerifierAddress,
				sourceCfg.DefaultExecutorAddress,
			)

			vc.lggr.Infow("PollInterval: ", "chainSelector", chainSelector, "interval", sourceCfg.PollInterval)
			readerLogger := logger.With(vc.lggr, "component", "SourceReader", "chainID", chainSelector)
			srs, err := NewSourceReaderService(
				sourceReader,
				chainSelector,
				vc.chainStatusManager,
				readerLogger,
				sourceCfg.PollInterval,
				vc.curseDetector,
				filter,
				vc.monitoring.Metrics(),
			)
			if err != nil {
				vc.lggr.Errorw("Failed to create SourceReaderService",
					"chainSelector", chainSelector,
					"error", err)
				continue
			}

			if err = srs.Start(c); err != nil {
				vc.lggr.Errorw("Failed to start SourceReaderService",
					"chainSelector", chainSelector,
					"error", err)
				continue
			}

			state := &sourceState{
				readerService: srs,
				readyTasksCh:  srs.ReadyTasksChannel(),
				chainSelector: chainSelector,
			}
			vc.sourceStates[chainSelector] = state
		}

		storageWriterProcessor, storageBatcher, err := NewStorageBatcherProcessor(
			c,
			vc.lggr,
			vc.config.VerifierID,
			vc.messageTracker,
			vc.storage,
			vc.config,
		)
		if err != nil {
			return fmt.Errorf("failed to create or/and start storage batcher storageWriterProcessor: %w", err)
		}
		vc.storageWriterProcessor = storageWriterProcessor
		vc.storageBatcher = storageBatcher

		taskVerifierProcessor, err := NewTaskVerifierProcessor(
			c,
			vc.lggr,
			vc.config.VerifierID,
			vc.verifier,
			vc.monitoring,
			vc.sourceStates,
			storageBatcher,
		)
		if err != nil {
			return fmt.Errorf("failed to create or/and start task verifier service: %w", err)
		}
		vc.taskVerifierProcessor = taskVerifierProcessor

		vc.lggr.Infow("Coordinator started successfully")
		return nil
	})
}

// Close stops the verification coordinator processing.
func (vc *Coordinator) Close() error {
	return vc.StopOnce(vc.Name(), func() error {
		// Signal all goroutines to stop processing new work.
		// This will also trigger the batcher to flush remaining items.
		vc.cancel()

		if err := vc.taskVerifierProcessor.Close(); err != nil {
			vc.lggr.Errorw("Error closing task verifier processor", "error", err)
		}

		// Wait for storage batcher goroutine to finish flushing
		if vc.storageBatcher != nil {
			if err := vc.storageBatcher.Close(); err != nil {
				vc.lggr.Errorw("Error closing storage batcher", "error", err)
			}
		}

		// Stop curse detector
		if vc.curseDetector != nil {
			if err := vc.curseDetector.Close(); err != nil {
				vc.lggr.Errorw("Error closing curse detector", "error", err)
			}
		}

		// Stop per-chain pipelines (includes underlying readers and reorg detectors)
		for chainSelector, state := range vc.sourceStates {
			if err := state.Close(); err != nil {
				vc.lggr.Errorw("Error closing source state",
					"chainSelector", chainSelector,
					"error", err)
			}
		}

		if err := vc.storageBatcher.Close(); err != nil {
			vc.lggr.Errorw("Error closing storage batcher", "error", err)
		}

		vc.lggr.Infow("Verifier coordinator stopped")
		return nil
	})
}

// -----------------------------------------------------------------------------
// Curse detector wiring (kept in coordinator as requested)
// -----------------------------------------------------------------------------

// startCurseDetector creates, configures, and starts a curse detector service from RMN readers.
// Uses CursePollInterval from config, defaulting to 2s if not set.
func (vc *Coordinator) startCurseDetector(
	ctx context.Context,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
) error {
	if len(sourceReaders) == 0 {
		vc.lggr.Infow("No RMN readers provided; curse detector will not be started")
		return nil
	}
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	for chainSelector, sourceReader := range sourceReaders {
		rmnReaders[chainSelector] = sourceReader
	}

	if vc.curseDetector != nil {
		vc.lggr.Infow("Curse detector already injected; skipping creation from RMN readers")
		return nil
	}

	// if a curse detector service is already set, use it; otherwise create a new one
	curseDetectorSvc := vc.curseDetector
	if curseDetectorSvc == nil {
		cd, err := cursecheckerimpl.NewCurseDetectorService(
			rmnReaders,
			vc.config.CursePollInterval,
			vc.lggr,
		)
		if err != nil {
			vc.lggr.Errorw("Failed to create curse detector service", "error", err)
			return fmt.Errorf("failed to create curse detector: %w", err)
		}
		curseDetectorSvc = cd
	}

	if err := curseDetectorSvc.Start(ctx); err != nil {
		vc.lggr.Errorw("Failed to start curse detector", "error", err)
		return fmt.Errorf("failed to start curse detector: %w", err)
	}

	vc.curseDetector = curseDetectorSvc
	vc.lggr.Infow("Curse detector started", "chainCount", len(rmnReaders))

	return nil
}

// Name returns the fully qualified name of the coordinator.
func (vc *Coordinator) Name() string {
	return fmt.Sprintf("verifier.Coordinator[%s]", vc.config.VerifierID)
}

// HealthReport returns a full health report of the coordinator and its dependencies.
func (vc *Coordinator) HealthReport() map[string]error {
	report := make(map[string]error)
	report[vc.Name()] = vc.Ready()
	if vc.taskVerifierProcessor != nil {
		tvp := vc.taskVerifierProcessor.HealthReport()
		maps.Copy(report, tvp)
	}
	if vc.storageWriterProcessor != nil {
		swp := vc.storageWriterProcessor.HealthReport()
		maps.Copy(report, swp)
	}
	return report
}

var (
	_ services.Service        = (*Coordinator)(nil)
	_ protocol.HealthReporter = (*Coordinator)(nil)
)
