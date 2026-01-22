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
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

type Coordinator struct {
	services.StateMachine
	cancel context.CancelFunc

	lggr       logger.Logger
	verifierID string

	// All services/processors dependencies maintained by coordinator
	// Curse detector is created & owned by coordinator (optional)
	curseDetector common.CurseCheckerService
	// 1st step processor: source readers (per-chain)
	sourceReadersServices map[protocol.ChainSelector]*SourceReaderService
	// 2nd step processor: task verifier
	taskVerifierProcessor *TaskVerifierProcessor
	// 3rd step processor: storage writer
	storageWriterProcessor *StorageWriterProcessor
}

func NewCoordinator(
	ctx context.Context,
	lggr logger.Logger,
	verifier Verifier,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
	messageTracker MessageLatencyTracker,
	monitoring Monitoring,
	chainStatusManager protocol.ChainStatusManager,
) (*Coordinator, error) {
	return NewCoordinatorWithDetector(
		ctx,
		lggr,
		verifier,
		sourceReaders,
		storage,
		config,
		messageTracker,
		monitoring,
		chainStatusManager,
		nil,
	)
}

func NewCoordinatorWithDetector(
	ctx context.Context,
	lggr logger.Logger,
	verifier Verifier,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
	messageTracker MessageLatencyTracker,
	monitoring Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	detector common.CurseCheckerService,
) (*Coordinator, error) {
	enabledSourceReaders, err := filterOnlyEnabledSourceReaders(ctx, lggr, config, sourceReaders, chainStatusManager)
	if err != nil {
		return nil, fmt.Errorf("failed to filter enabled source readers: %w", err)
	}
	if len(enabledSourceReaders) == 0 {
		return nil, errors.New("no enabled/initialized chain sources, nothing to coordinate")
	}

	curseDetector, err := createCurseDetector(lggr, config, detector, enabledSourceReaders)
	if err != nil {
		return nil, fmt.Errorf("failed to create curse detector: %w", err)
	}

	// Create shared writingTracker (single instance shared by SRS, TVP, and SWP)
	writingTracker := NewPendingWritingTracker(lggr)

	sourceReaderServices := createSourceReaders(
		ctx, lggr, config, chainStatusManager, curseDetector, monitoring, enabledSourceReaders, writingTracker,
	)

	storageWriterProcessor, storageBatcher, err := NewStorageBatcherProcessor(
		ctx, lggr, config.VerifierID, messageTracker, storage, config, writingTracker, chainStatusManager,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create or/and start storage batcher storageWriterProcessor: %w", err)
	}

	taskVerifierProcessor, err := NewTaskVerifierProcessor(
		lggr, config.VerifierID, verifier, monitoring, sourceReaderServices, storageBatcher, writingTracker,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create or/and start task verifier service: %w", err)
	}

	return &Coordinator{
		lggr:                   lggr,
		sourceReadersServices:  sourceReaderServices,
		curseDetector:          curseDetector,
		storageWriterProcessor: storageWriterProcessor,
		taskVerifierProcessor:  taskVerifierProcessor,
	}, nil
}

func (vc *Coordinator) Start(_ context.Context) error {
	return vc.StartOnce(vc.Name(), func() error {
		vc.lggr.Infow("Starting verifier coordinator")

		ctx, cancel := context.WithCancel(context.Background())
		vc.cancel = cancel

		// Curse detector is optional so only start if it's set
		if vc.curseDetector != nil {
			if err := vc.curseDetector.Start(ctx); err != nil {
				vc.lggr.Errorw("Failed to start curse detector", "error", err)
				return fmt.Errorf("failed to start curse detector: %w", err)
			}
		}

		// Start consumers before producers to ensure channel sends don't block at startup.

		// Start storage writer processor (consumes from taskVerifierProcessor)
		if err := vc.storageWriterProcessor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start storage writer processor: %w", err)
		}

		// Start task verifier processor (consumes from SRS, produces to storage writer)
		if err := vc.taskVerifierProcessor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start task verifier processor: %w", err)
		}

		// Start source readers (producers) - now consumers are ready to drain
		for _, srs := range vc.sourceReadersServices {
			if err := srs.Start(ctx); err != nil {
				vc.lggr.Errorw("Failed to start SourceReaderService",
					"chainSelector", srs.chainSelector,
					"error", err)
				return fmt.Errorf("failed to start SourceReaderService for chain %s: %w", srs.chainSelector, err)
			}
		}

		vc.lggr.Infow("Coordinator started successfully")
		return nil
	})
}

func createSourceReaders(ctx context.Context, lggr logger.Logger, config CoordinatorConfig, chainStatusManager protocol.ChainStatusManager, curseDetector common.CurseCheckerService, monitoring Monitoring, enabledSourceReaders map[protocol.ChainSelector]chainaccess.SourceReader, writingTracker *PendingWritingTracker) map[protocol.ChainSelector]*SourceReaderService {
	sourceReaderServices := make(map[protocol.ChainSelector]*SourceReaderService)
	for chainSelector := range enabledSourceReaders {
		sourceReader := enabledSourceReaders[chainSelector]
		sourceCfg := config.SourceConfigs[chainSelector]

		filter := chainaccess.NewReceiptIssuerFilter(
			sourceCfg.VerifierAddress,
			sourceCfg.DefaultExecutorAddress,
		)

		lggr.Infow("PollInterval: ", "chainSelector", chainSelector, "interval", sourceCfg.PollInterval)
		readerLogger := logger.With(lggr, "component", "SourceReader", "chainID", chainSelector)
		srs, err := NewSourceReaderService(
			ctx,
			sourceReader,
			chainSelector,
			chainStatusManager,
			readerLogger,
			sourceCfg,
			curseDetector,
			filter,
			monitoring.Metrics(),
			writingTracker,
		)
		if err != nil {
			lggr.Errorw("Failed to create SourceReaderService",
				"chainSelector", chainSelector,
				"error", err)
			continue
		}
		sourceReaderServices[chainSelector] = srs
	}
	return sourceReaderServices
}

func filterOnlyEnabledSourceReaders(
	ctx context.Context,
	lggr logger.Logger,
	config CoordinatorConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	chainStatusManager protocol.ChainStatusManager,
) (map[protocol.ChainSelector]chainaccess.SourceReader, error) {
	allSelectors := make([]protocol.ChainSelector, 0, len(sourceReaders))
	for selector := range sourceReaders {
		allSelectors = append(allSelectors, selector)
	}

	statusMap, err := chainStatusManager.ReadChainStatuses(ctx, allSelectors)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain statuses from storage: %w", err)
	}

	enabledSourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for chainSelector, sourceReader := range sourceReaders {
		if sourceReader == nil {
			continue
		}
		lggr.Infow("Chain Status", "chainSelector", chainSelector, "status", statusMap[chainSelector])

		// Skip disabled chains
		if chainStatus, ok := statusMap[chainSelector]; ok && chainStatus.Disabled {
			lggr.Warnw(
				"Chain is disabled in aggregator DB, skipping initialization",
				"chain", chainSelector,
				"blockHeight", chainStatus.FinalizedBlockHeight,
			)
			continue
		}

		_, ok := config.SourceConfigs[chainSelector]
		if !ok {
			lggr.Warnw("No source config for chain selector, skipping", "chainSelector", chainSelector)
			continue
		}
		enabledSourceReaders[chainSelector] = sourceReader
	}
	return enabledSourceReaders, nil
}

// Close stops the verification coordinator processing.
func (vc *Coordinator) Close() error {
	return vc.StopOnce(vc.Name(), func() error {
		// Signal all goroutines to stop processing new work.
		// This will also trigger the batcher to flush remaining items.
		vc.cancel()

		errs := make([]error, 0)
		if vc.curseDetector != nil {
			if err := vc.curseDetector.Close(); err != nil {
				vc.lggr.Errorw("Failed to stop curse detector", "error", err)
				errs = append(errs, fmt.Errorf("failed to stop curse detector: %w", err))
			}
		}

		for _, srs := range vc.sourceReadersServices {
			if err := srs.Close(); err != nil {
				vc.lggr.Errorw("Failed to stop SourceReaderService", "chainSelector", srs.chainSelector, "error", err)
				errs = append(errs, fmt.Errorf("failed to stop SourceReaderService for chain %s: %w", srs.chainSelector, err))
			}
		}

		// Start task verifier processor - 2nd step processor
		if err := vc.taskVerifierProcessor.Close(); err != nil {
			vc.lggr.Errorw("Failed to stop verifier processor", "error", err)
			errs = append(errs, fmt.Errorf("failed to stop verifier processor: %w", err))
		}

		// Start storage writer processor - 3rd step processor
		if err := vc.storageWriterProcessor.Close(); err != nil {
			vc.lggr.Errorw("Failed to stop storage writer processor", "error", err)
			errs = append(errs, fmt.Errorf("failed to stop storage writer processor: %w", err))
		}

		vc.lggr.Infow("Verifier coordinator stopped")
		return errors.Join(errs...)
	})
}

// startCurseDetector creates, configures, and starts a curse detector service from RMN readers.
// Uses CursePollInterval from config, defaulting to 2s if not set.
func createCurseDetector(
	lggr logger.Logger,
	config CoordinatorConfig,
	curseDetector common.CurseCheckerService,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
) (common.CurseCheckerService, error) {
	if len(sourceReaders) == 0 {
		lggr.Infow("No RMN readers provided; curse detector will not be started")
		return nil, nil
	}
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	for chainSelector, sourceReader := range sourceReaders {
		rmnReaders[chainSelector] = sourceReader
	}

	// if a curse detector service is already set, use it; otherwise create a new one
	if curseDetector != nil {
		lggr.Infow("Curse detector already injected; skipping creation from RMN readers")
		return curseDetector, nil
	}

	newCurseDetector, err := cursecheckerimpl.NewCurseDetectorService(
		rmnReaders,
		config.CursePollInterval,
		lggr,
	)
	if err != nil {
		lggr.Errorw("Failed to create curse detector service", "error", err)
		return nil, fmt.Errorf("failed to create curse detector: %w", err)
	}
	return newCurseDetector, nil
}

// Name returns the fully qualified name of the coordinator.
func (vc *Coordinator) Name() string {
	return fmt.Sprintf("verifier.Coordinator[%s]", vc.verifierID)
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
