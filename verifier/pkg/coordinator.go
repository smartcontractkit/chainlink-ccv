package verifier

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	cursecheckerimpl "github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/heartbeat"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/storagewriter"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/taskverifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const (

	// taskQueueRetryDuration is how long verification tasks are retried before giving up.
	taskQueueRetryDuration = 7 * 24 * time.Hour // 7 days
	// taskQueueLockDuration is how long a task can remain in 'processing' before being reclaimed.
	// The consumer sweeps for stale locks on its own timer, so the worst-case reclaim is
	// this value plus taskverifier's stale reclaim interval.
	taskQueueLockDuration = 2 * time.Minute
	// resultQueueRetryDuration is how long verification results are retried before giving up.
	resultQueueRetryDuration = 7 * 24 * time.Hour // 7 days
	// resultQueueLockDuration is how long a job can remain in 'processing' before being reclaimed.
	// The consumer sweeps for stale locks on its own timer, so the worst-case reclaim is
	// this value plus storagewriter's stale reclaim interval.
	resultQueueLockDuration = 1 * time.Minute
	// queueObservabilityInterval is how often queue size metrics are logged and recorded.
	//
	// Each tick runs one COUNT(*) per queue. Once the consumers stopped polling, this
	// became the largest remaining source of idle database work, so the interval is set
	// for the cost of the query rather than for metric resolution. Queue depth changes
	// slowly enough that a minute still shows a backlog forming.
	queueObservabilityInterval = 60 * time.Second
)

type Coordinator struct {
	services.StateMachine

	lggr       logger.Logger
	verifierID string

	initFn func(ctx context.Context) error

	curseDetector          common.CurseCheckerService
	chainStatusBatcher     *chainstatus.Batcher
	sourceReaderServices   map[protocol.ChainSelector]services.Service
	taskVerifierProcessor  services.Service
	storageWriterProcessor services.Service
	heartbeatReporter      *heartbeat.Reporter

	// Observability wrappers for queues
	taskQueueObserver   services.Service
	resultQueueObserver services.Service

	monitoring commonmetrics.ServiceMetrics

	messageRulesSvc common.MessageRulesCheckerService
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
	heartbeatClient heartbeatclient.HeartbeatSender,
	messageRulesSvc common.MessageRulesCheckerService,
	ds sqlutil.DataSource,
) (*Coordinator, error) {
	if ds == nil {
		return nil, errors.New("db is required; in-memory implementations are no longer supported")
	}
	return NewCoordinatorWithDetector(
		lggr, verifier, sourceReaders, storage, config,
		messageTracker, monitoring, chainStatusManager, nil, heartbeatClient, messageRulesSvc, ds,
	)
}

func NewCoordinatorWithDetector(
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
	messageRulesSvc common.MessageRulesCheckerService,
	ds sqlutil.DataSource,
) (*Coordinator, error) {
	if ds == nil {
		return nil, errors.New("db is required; in-memory implementations are no longer supported")
	}
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	lggr = logger.With(lggr, "verifierID", config.VerifierID)
	vc := &Coordinator{
		lggr:            lggr,
		verifierID:      config.VerifierID,
		monitoring:      monitoring,
		messageRulesSvc: messageRulesSvc,
	}
	vc.initFn = func(ctx context.Context) error {
		// Batch the chain status writes. The source readers write a status on every
		// checkpoint advance, which is one database transaction per advance per chain.
		// A disabled status still goes to the database immediately.
		flushInterval := config.ChainStatusFlushInterval
		if flushInterval <= 0 {
			flushInterval = chainstatus.DefaultFlushInterval
		}
		flushThreshold := config.ChainStatusFlushThreshold
		if flushThreshold <= 0 {
			flushThreshold = chainstatus.DefaultFlushThreshold
		}
		batcher, err := chainstatus.NewChainStatusBatcher(lggr, chainStatusManager, flushInterval, flushThreshold)
		if err != nil {
			return fmt.Errorf("failed to create chain status batcher: %w", err)
		}
		vc.chainStatusBatcher = batcher
		batchedChainStatusManager := protocol.ChainStatusManager(batcher)

		enabledSourceReaders, err := filterOnlyEnabledSourceReaders(ctx, lggr, config, sourceReaders, batchedChainStatusManager)
		if err != nil {
			return fmt.Errorf("failed to filter enabled source readers: %w", err)
		}
		if len(enabledSourceReaders) == 0 {
			return errors.New("no enabled/initialized chain sources, nothing to coordinate")
		}
		curseDetector, err := createCurseDetector(lggr, config, detector, enabledSourceReaders, monitoring.Metrics())
		if err != nil {
			return fmt.Errorf("failed to create curse detector: %w", err)
		}
		vc.curseDetector = curseDetector

		messageRulesChecker := common.MessageRulesChecker(common.AllowAllMessagesChecker{})
		if vc.messageRulesSvc != nil {
			messageRulesChecker = vc.messageRulesSvc
		}

		processors, err := createDurableProcessors(
			lggr, ds, config, verifier, monitoring, enabledSourceReaders, batchedChainStatusManager, vc.curseDetector, messageTracker, storage, messageRulesChecker,
		)
		if err != nil {
			return fmt.Errorf("failed to create durable processors: %w", err)
		}
		vc.taskVerifierProcessor = processors.taskVerifierProcessor
		vc.storageWriterProcessor = processors.storageWriterProcessor
		vc.taskQueueObserver = processors.taskQueueObserver
		vc.resultQueueObserver = processors.resultQueueObserver
		vc.sourceReaderServices = make(map[protocol.ChainSelector]services.Service)
		for chainSelector, srs := range processors.sourceReaderServices {
			vc.sourceReaderServices[chainSelector] = srs
		}
		if heartbeatClient != nil && config.HeartbeatInterval > 0 {
			allSelectors := make([]protocol.ChainSelector, 0, len(sourceReaders))
			for selector := range sourceReaders {
				allSelectors = append(allSelectors, selector)
			}
			heartbeatReporter, err := heartbeat.NewReporter(
				logger.With(lggr, "component", "HeartbeatReporter"),
				batchedChainStatusManager, heartbeatClient, allSelectors, config.VerifierID, config.HeartbeatInterval,
			)
			if err != nil {
				return fmt.Errorf("failed to create heartbeat reporter: %w", err)
			}
			vc.heartbeatReporter = heartbeatReporter
		}
		return nil
	}
	return vc, nil
}

// durableProcessors holds all services created by createDurableProcessors.
type durableProcessors struct {
	sourceReaderServices   map[protocol.ChainSelector]*sourcereader.Service
	taskVerifierProcessor  services.Service
	storageWriterProcessor services.Service
	taskQueueObserver      services.Service
	resultQueueObserver    services.Service
}

// createDurableProcessors creates DB-backed source readers and processors using database-backed queues.
// All three pipeline stages communicate via the database: SRS → ccv_task_verifier_jobs → TVP → ccv_storage_writer_jobs → SWP.
func createDurableProcessors(
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
	messageRulesChecker common.MessageRulesChecker,
) (*durableProcessors, error) {
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
		return nil, fmt.Errorf("failed to create task queue: %w", err)
	}

	// Wrap task queue with observability decorator
	taskQueueObserver, err := jobqueue.NewObservabilityDecorator(
		taskQueue,
		logger.With(lggr, "component", "task_queue_observer"),
		queueObservabilityInterval,
		monitoring.Metrics().RecordTaskVerificationQueueSize,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task queue observer: %w", err)
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
		return nil, fmt.Errorf("failed to create result queue: %w", err)
	}

	// Wrap result queue with observability decorator
	resultQueueObserver, err := jobqueue.NewObservabilityDecorator(
		resultQueue,
		logger.With(lggr, "component", "result_queue_observer"),
		queueObservabilityInterval,
		monitoring.Metrics().RecordStorageWriteQueueSize,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create result queue observer: %w", err)
	}

	sourceReadersDB, err := createSourceReadersDB(
		lggr, config, chainStatusManager, curseDetector, monitoring, enabledSourceReaders, taskQueueObserver, messageRulesChecker,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DB source reader services: %w", err)
	}

	taskVerifierProcessor, err := taskverifier.NewProcessor(
		lggr, config.VerifierID, verifier, monitoring, messageTracker, taskQueueObserver, resultQueueObserver, config.StorageBatchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task verifier processor DB: %w", err)
	}

	storageWriterProcessor, err := storagewriter.NewProcessor(
		lggr, config.VerifierID, monitoring, messageTracker, storage, resultQueueObserver, config,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage writer processor DB: %w", err)
	}

	return &durableProcessors{
		sourceReaderServices:   sourceReadersDB,
		taskVerifierProcessor:  taskVerifierProcessor,
		storageWriterProcessor: storageWriterProcessor,
		taskQueueObserver:      taskQueueObserver,
		resultQueueObserver:    resultQueueObserver,
	}, nil
}

func (vc *Coordinator) Start(ctx context.Context) error {
	return vc.StartOnce(vc.Name(), func() error {
		vc.lggr.Infow("Starting verifier coordinator")

		if vc.initFn != nil {
			if err := vc.initFn(ctx); err != nil {
				return err
			}
		}

		if vc.chainStatusBatcher != nil {
			if err := vc.chainStatusBatcher.Start(ctx); err != nil {
				return fmt.Errorf("failed to start chain status batcher: %w", err)
			}
		}

		if vc.messageRulesSvc != nil {
			if err := vc.messageRulesSvc.Start(ctx); err != nil {
				return fmt.Errorf("failed to start message rules service: %w", err)
			}
		}

		if vc.curseDetector != nil {
			if err := vc.curseDetector.Start(ctx); err != nil {
				return fmt.Errorf("failed to start curse detector: %w", err)
			}
		}

		// Start observability decorators for queues
		if vc.taskQueueObserver != nil {
			if err := vc.taskQueueObserver.Start(ctx); err != nil {
				return fmt.Errorf("failed to start task queue observer: %w", err)
			}
		}

		if vc.resultQueueObserver != nil {
			if err := vc.resultQueueObserver.Start(ctx); err != nil {
				return fmt.Errorf("failed to start result queue observer: %w", err)
			}
		}

		if vc.storageWriterProcessor != nil {
			if err := vc.storageWriterProcessor.Start(ctx); err != nil {
				return fmt.Errorf("failed to start storage writer processor: %w", err)
			}
		}
		if vc.taskVerifierProcessor != nil {
			if err := vc.taskVerifierProcessor.Start(ctx); err != nil {
				return fmt.Errorf("failed to start task verifier processor: %w", err)
			}
		}

		if vc.sourceReaderServices != nil {
			for chainSelector, srs := range vc.sourceReaderServices {
				if err := srs.Start(ctx); err != nil {
					return fmt.Errorf("failed to start source reader service for chain %s: %w", chainSelector, err)
				}
			}
		}

		if vc.heartbeatReporter != nil {
			if err := vc.heartbeatReporter.Start(ctx); err != nil {
				return fmt.Errorf("failed to start heartbeat reporter: %w", err)
			}
		}

		vc.lggr.Infow("Coordinator started successfully")
		vc.monitoring.RecordServiceStarted(ctx)

		return nil
	})
}

func createSourceReadersDB(
	lggr logger.Logger,
	config CoordinatorConfig,
	chainStatusManager protocol.ChainStatusManager,
	curseDetector common.CurseCheckerService,
	monitoring Monitoring,
	enabledSourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	taskQueue jobqueue.JobQueue[VerificationTask],
	messageRulesChecker common.MessageRulesChecker,
) (map[protocol.ChainSelector]*sourcereader.Service, error) {
	sourceReaderServices := make(map[protocol.ChainSelector]*sourcereader.Service)
	for chainSelector, sourceReader := range enabledSourceReaders {
		sourceCfg := config.SourceConfigs[chainSelector]
		filter := chainaccess.NewReceiptIssuerFilter(sourceCfg.VerifierAddress, sourceCfg.DefaultExecutorAddress)
		lggr.Infow("PollInterval: ", "chainSelector", chainSelector, "interval", sourceCfg.PollInterval)
		srs, err := sourcereader.NewService(
			config.VerifierID, sourceReader, chainSelector, chainStatusManager,
			logger.With(lggr, "component", "SourceReaderDB", "chainID", chainSelector),
			sourceCfg, curseDetector, filter, monitoring, taskQueue, messageRulesChecker,
		)
		if err != nil {
			lggr.Errorw("failed to create Service for chain, skipping this chain", "chainSelector", chainSelector, "error", err)
			continue
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

		if vc.sourceReaderServices != nil {
			for chainSelector, srs := range vc.sourceReaderServices {
				if err := srs.Close(); err != nil {
					errs = append(errs, fmt.Errorf("failed to stop source reader service for chain %s: %w", chainSelector, err))
				}
			}
		}

		if vc.messageRulesSvc != nil {
			if err := vc.messageRulesSvc.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop message rules service: %w", err))
			}
		}

		if vc.taskVerifierProcessor != nil {
			if err := vc.taskVerifierProcessor.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop verifier processor: %w", err))
			}
		}

		if vc.storageWriterProcessor != nil {
			if err := vc.storageWriterProcessor.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop storage writer processor: %w", err))
			}
		}

		// Stop observability decorators after all processors that use them
		if vc.resultQueueObserver != nil {
			if err := vc.resultQueueObserver.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop result queue observer: %w", err))
			}
		}

		if vc.taskQueueObserver != nil {
			if err := vc.taskQueueObserver.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop task queue observer: %w", err))
			}
		}

		// Close the batcher last. Every service that writes a chain status has
		// stopped by now, so the final flush loses nothing.
		if vc.chainStatusBatcher != nil {
			if err := vc.chainStatusBatcher.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop chain status batcher: %w", err))
			}
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
	if vc.messageRulesSvc != nil {
		if hr, ok := vc.messageRulesSvc.(protocol.HealthReporter); ok {
			maps.Copy(report, hr.HealthReport())
		}
	}
	if vc.taskVerifierProcessor != nil {
		maps.Copy(report, vc.taskVerifierProcessor.HealthReport())
	}
	if vc.storageWriterProcessor != nil {
		maps.Copy(report, vc.storageWriterProcessor.HealthReport())
	}
	if vc.sourceReaderServices != nil {
		for _, srs := range vc.sourceReaderServices {
			if hr, ok := srs.(protocol.HealthReporter); ok {
				maps.Copy(report, hr.HealthReport())
			}
		}
	}
	return report
}

var (
	_ services.Service        = (*Coordinator)(nil)
	_ protocol.HealthReporter = (*Coordinator)(nil)
)
