package verifier

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	cursecheckerimpl "github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const (
	// TaskVerifierJobsTableName is the name of the table storing verification tasks.
	TaskVerifierJobsTableName = "ccv_task_verifier_jobs"
	// StorageWriterJobsTableName is the name of the table storing verification results for storage writing.
	StorageWriterJobsTableName = "ccv_storage_writer_jobs"

	// taskQueueRetryDuration is how long verification tasks are retried before giving up.
	taskQueueRetryDuration = 7 * 24 * time.Hour // 7 days
	// taskQueueLockDuration is how long a task can remain in 'processing' before being reclaimed.
	taskQueueLockDuration = 2 * time.Minute
	// resultQueueRetryDuration is how long verification results are retried before giving up.
	resultQueueRetryDuration = 7 * 24 * time.Hour // 7 days
	// resultQueueLockDuration is how long a job can remain in 'processing' before being reclaimed.
	resultQueueLockDuration = 1 * time.Minute
)

type Coordinator struct {
	services.StateMachine
	cancel context.CancelFunc

	lggr       logger.Logger
	verifierID string

	curseDetector common.CurseCheckerService
	// 1st step processor: source readers (per-chain)
	sourceReaderServices map[protocol.ChainSelector]services.Service
	// 2nd step processor: task verifier
	taskVerifierProcessor services.Service
	// 3rd step processor: storage writer
	storageWriterProcessor services.Service
	// Heartbeat reporter: periodically sends chain statuses to aggregator
	heartbeatReporter *HeartbeatReporter
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
	heartbeatClient heartbeatclient.HeartbeatSender,
	ds sqlutil.DataSource,
) (*Coordinator, error) {
	if ds == nil {
		return nil, errors.New("db is required; in-memory implementations are no longer supported")
	}
	return NewCoordinatorWithDetector(
		ctx, lggr, verifier, sourceReaders, storage, config,
		messageTracker, monitoring, chainStatusManager, nil, heartbeatClient, ds,
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
	heartbeatClient heartbeatclient.HeartbeatSender,
	ds sqlutil.DataSource,
) (*Coordinator, error) {
	if ds == nil {
		return nil, errors.New("db is required; in-memory implementations are no longer supported")
	}

	lggr = logger.With(lggr, "verifierID", config.VerifierID)

	var err error
	enabledSourceReaders, err := filterOnlyEnabledSourceReaders(ctx, lggr, config, sourceReaders, chainStatusManager)
	if err != nil {
		return nil, fmt.Errorf("failed to filter enabled source readers: %w", err)
	}
	if len(enabledSourceReaders) == 0 {
		return nil, errors.New("no enabled/initialized chain sources, nothing to coordinate")
	}

	curseDetector, err := createCurseDetector(lggr, config, detector, enabledSourceReaders, monitoring.Metrics())
	if err != nil {
		return nil, fmt.Errorf("failed to create curse detector: %w", err)
	}

	writingTracker := NewPendingWritingTracker(lggr)

	// Create DB-backed processors
	dbSRS, taskVerifierProcessor, storageWriterProcessor, durableErr := createDurableProcessors(
		ctx, lggr, ds, config, verifier, monitoring, enabledSourceReaders, chainStatusManager, curseDetector, messageTracker, storage, writingTracker,
	)
	if durableErr != nil {
		return nil, err
	}

	sourceReaderServices := make(map[protocol.ChainSelector]services.Service)
	for chainSelector, srs := range dbSRS {
		sourceReaderServices[chainSelector] = srs
	}

	var heartbeatReporter *HeartbeatReporter
	if heartbeatClient != nil && config.HeartbeatInterval > 0 {
		allSelectors := make([]protocol.ChainSelector, 0, len(sourceReaders))
		for selector := range sourceReaders {
			allSelectors = append(allSelectors, selector)
		}
		heartbeatReporter, err = NewHeartbeatReporter(
			logger.With(lggr, "component", "HeartbeatReporter"),
			chainStatusManager, heartbeatClient, allSelectors, config.VerifierID, config.HeartbeatInterval,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create heartbeat reporter: %w", err)
		}
	}

	return &Coordinator{
		lggr:                   lggr,
		verifierID:             config.VerifierID,
		sourceReaderServices:   sourceReaderServices,
		curseDetector:          curseDetector,
		taskVerifierProcessor:  taskVerifierProcessor,
		storageWriterProcessor: storageWriterProcessor,
		heartbeatReporter:      heartbeatReporter,
	}, nil
}

// createDurableProcessors creates DB-backed source readers and processors using database-backed queues.
// All three pipeline stages communicate via the database: SRS → ccv_task_verifier_jobs → TVP → ccv_storage_writer_jobs → SWP.
func createDurableProcessors(
	ctx context.Context,
	lggr logger.Logger,
	ds sqlutil.DataSource,
	config CoordinatorConfig,
	verifier Verifier,
	monitoring Monitoring,
	enabledSourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	chainStatusManager protocol.ChainStatusManager,
	curseDetector common.CurseCheckerService,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	writingTracker *PendingWritingTracker,
) (map[protocol.ChainSelector]*SourceReaderServiceDB, services.Service, services.Service, error) {
	taskQueue, err := jobqueue.NewPostgresJobQueue[VerificationTask](
		ds,
		jobqueue.QueueConfig{
			Name:          TaskVerifierJobsTableName,
			OwnerID:       config.VerifierID,
			RetryDuration: taskQueueRetryDuration,
			LockDuration:  taskQueueLockDuration,
		},
		logger.With(lggr, "component", "task_queue"),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create task queue: %w", err)
	}

	resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
		ds,
		jobqueue.QueueConfig{
			Name:          StorageWriterJobsTableName,
			OwnerID:       config.VerifierID,
			RetryDuration: resultQueueRetryDuration,
			LockDuration:  resultQueueLockDuration,
		},
		logger.With(lggr, "component", "result_queue"),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create result queue: %w", err)
	}

	// DB-backed source readers publish ready tasks directly to the task queue
	sourceReadersDB, err := createSourceReadersDB(
		ctx, lggr, config, chainStatusManager, curseDetector, monitoring, enabledSourceReaders, writingTracker, taskQueue,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create DB source reader services: %w", err)
	}

	taskVerifierProcessor, err := NewTaskVerifierProcessorDB(
		lggr, config.VerifierID, verifier, monitoring, taskQueue, resultQueue, writingTracker, config.StorageBatchSize,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create task verifier processor DB: %w", err)
	}

	storageWriterProcessor, err := NewStorageWriterProcessor(
		ctx, lggr, config.VerifierID, messageTracker, storage, resultQueue, config, writingTracker, chainStatusManager,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create storage writer processor DB: %w", err)
	}

	return sourceReadersDB, taskVerifierProcessor, storageWriterProcessor, nil
}

func (vc *Coordinator) Start(_ context.Context) error {
	return vc.StartOnce(vc.Name(), func() error {
		vc.lggr.Infow("Starting verifier coordinator")

		ctx, cancel := context.WithCancel(context.Background())
		vc.cancel = cancel

		if vc.curseDetector != nil {
			if err := vc.curseDetector.Start(ctx); err != nil {
				return fmt.Errorf("failed to start curse detector: %w", err)
			}
		}

		// Start consumers before producers
		if err := vc.storageWriterProcessor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start storage writer processor: %w", err)
		}
		if err := vc.taskVerifierProcessor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start task verifier processor: %w", err)
		}

		// Start source readers (in-memory or DB-backed depending on configuration)
		for chainSelector, srs := range vc.sourceReaderServices {
			if err := srs.Start(ctx); err != nil {
				return fmt.Errorf("failed to start source reader service for chain %s: %w", chainSelector, err)
			}
		}

		if vc.heartbeatReporter != nil {
			if err := vc.heartbeatReporter.Start(ctx); err != nil {
				return fmt.Errorf("failed to start heartbeat reporter: %w", err)
			}
		}

		vc.lggr.Infow("Coordinator started successfully")
		return nil
	})
}

func createSourceReadersDB(
	ctx context.Context,
	lggr logger.Logger,
	config CoordinatorConfig,
	chainStatusManager protocol.ChainStatusManager,
	curseDetector common.CurseCheckerService,
	monitoring Monitoring,
	enabledSourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	writingTracker *PendingWritingTracker,
	taskQueue jobqueue.JobQueue[VerificationTask],
) (map[protocol.ChainSelector]*SourceReaderServiceDB, error) {
	sourceReaderServices := make(map[protocol.ChainSelector]*SourceReaderServiceDB)
	for chainSelector, sourceReader := range enabledSourceReaders {
		sourceCfg := config.SourceConfigs[chainSelector]
		filter := chainaccess.NewReceiptIssuerFilter(sourceCfg.VerifierAddress, sourceCfg.DefaultExecutorAddress)
		lggr.Infow("PollInterval: ", "chainSelector", chainSelector, "interval", sourceCfg.PollInterval)
		srs, err := NewSourceReaderServiceDB(
			ctx, sourceReader, chainSelector, chainStatusManager,
			logger.With(lggr, "component", "SourceReaderDB", "chainID", chainSelector),
			sourceCfg, curseDetector, filter, monitoring.Metrics(), writingTracker, taskQueue,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create SourceReaderServiceDB for chain %s: %w", chainSelector, err)
		}
		sourceReaderServices[chainSelector] = srs
	}
	return sourceReaderServices, nil
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
		if chainStatus, ok := statusMap[chainSelector]; ok && chainStatus.Disabled {
			lggr.Warnw("Chain is disabled, skipping", "chain", chainSelector, "blockHeight", chainStatus.FinalizedBlockHeight)
			continue
		}
		if _, ok := config.SourceConfigs[chainSelector]; !ok {
			lggr.Warnw("No source config for chain selector, skipping", "chainSelector", chainSelector)
			continue
		}
		enabledSourceReaders[chainSelector] = sourceReader
	}
	return enabledSourceReaders, nil
}

func (vc *Coordinator) Close() error {
	return vc.StopOnce(vc.Name(), func() error {
		vc.cancel()

		errs := make([]error, 0)

		if vc.heartbeatReporter != nil {
			if err := vc.heartbeatReporter.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop heartbeat reporter: %w", err))
			}
		}

		if vc.curseDetector != nil {
			if err := vc.curseDetector.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop curse detector: %w", err))
			}
		}

		for chainSelector, srs := range vc.sourceReaderServices {
			if err := srs.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop source reader service for chain %s: %w", chainSelector, err))
			}
		}

		if err := vc.taskVerifierProcessor.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop verifier processor: %w", err))
		}

		if err := vc.storageWriterProcessor.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop storage writer processor: %w", err))
		}

		vc.lggr.Infow("Verifier coordinator stopped")
		return errors.Join(errs...)
	})
}

func createCurseDetector(
	lggr logger.Logger,
	config CoordinatorConfig,
	curseDetector common.CurseCheckerService,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	metrics MetricLabeler,
) (common.CurseCheckerService, error) {
	if len(sourceReaders) == 0 {
		lggr.Infow("No RMN readers provided; curse detector will not be started")
		return nil, nil
	}
	if curseDetector != nil {
		lggr.Infow("Curse detector already injected; skipping creation from RMN readers")
		return curseDetector, nil
	}
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	for chainSelector, sourceReader := range sourceReaders {
		rmnReaders[chainSelector] = sourceReader
	}
	newCurseDetector, err := cursecheckerimpl.NewCurseDetectorService(
		rmnReaders, config.CursePollInterval, config.CurseRPCTimeout, lggr,
		metrics,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create curse detector: %w", err)
	}
	return newCurseDetector, nil
}

func (vc *Coordinator) Name() string {
	return fmt.Sprintf("verifier.Coordinator[%s]", vc.verifierID)
}

func (vc *Coordinator) HealthReport() map[string]error {
	report := make(map[string]error)
	report[vc.Name()] = vc.Ready()
	if vc.taskVerifierProcessor != nil {
		maps.Copy(report, vc.taskVerifierProcessor.HealthReport())
	}
	if vc.storageWriterProcessor != nil {
		maps.Copy(report, vc.storageWriterProcessor.HealthReport())
	}
	return report
}

var (
	_ services.Service        = (*Coordinator)(nil)
	_ protocol.HealthReporter = (*Coordinator)(nil)
)
