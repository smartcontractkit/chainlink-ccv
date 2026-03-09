package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	adapter "github.com/smartcontractkit/chainlink-ccv/executor/pkg/adapter"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	indexerPollingInterval           = 1 * time.Second
	indexerGarbageCollectionInterval = 1 * time.Hour
	messageContextWindow             = 9 * time.Hour
)

// ExecutorChainComponents holds chain-specific components created by the callback.
type ExecutorChainComponents struct {
	ContractTransmitters map[protocol.ChainSelector]chainaccess.ContractTransmitter
	DestinationReaders   map[protocol.ChainSelector]chainaccess.DestinationReader
	RMNCurseReaders      map[protocol.ChainSelector]chainaccess.RMNCurseReader
}

// CreateExecutorComponentsFunc is a function that creates chain-specific executor components.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
type CreateExecutorComponentsFunc[T any] func(
	ctx context.Context,
	lggr logger.Logger,
	blockchainInfos map[string]*T,
	cfg executor.Configuration,
) (*ExecutorChainComponents, error)

// factory is a ServiceFactory implementation that creates an executor service.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
// NOTE: this factory supports only a single chain family at a time.
type factory[T any] struct {
	lggr        logger.Logger
	coordinator *executor.Coordinator
	profiler    *pyroscope.Profiler
	server      *http.Server

	createComponentsFunc CreateExecutorComponentsFunc[T]
	chainFamily          string
}

// NewServiceFactory creates a new ServiceFactory for the executor service.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
func NewServiceFactory[T any](chainFamily string, createComponentsFunc CreateExecutorComponentsFunc[T]) bootstrap.ServiceFactory[executor.JobSpec] {
	return &factory[T]{
		createComponentsFunc: createComponentsFunc,
		chainFamily:          chainFamily,
	}
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory[T]) Start(ctx context.Context, spec executor.JobSpec, deps bootstrap.ServiceDeps) error {
	lggr := logger.Sugared(logger.Named(deps.Logger, "Executor"))
	f.lggr = lggr

	lggr.Infow("Starting executor service", "spec", spec)

	executorConfig, blockchainInfos, err := executor.LoadConfigWithBlockchainInfos[T](spec)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	lggr.Infow("Using blockchain information from config", "chainCount", len(blockchainInfos))

	profiler, err := StartPyroscope(lggr, executorConfig.PyroscopeURL, "executor")
	if err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
		return fmt.Errorf("failed to start pyroscope: %w", err)
	}
	f.profiler = profiler

	executorMonitoring := SetupMonitoring(lggr, executorConfig.Monitoring)

	components, err := f.createComponentsFunc(ctx, lggr, blockchainInfos, *executorConfig)
	if err != nil {
		lggr.Errorw("Failed to create executor chain components", "error", err)
		return fmt.Errorf("failed to create executor chain components: %w", err)
	}

	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        lggr,
		Metrics:     executorMonitoring.Metrics(),
		RmnReaders:  components.RMNCurseReaders,
		CacheExpiry: executorConfig.ReaderCacheExpiry,
	})

	httpClient := &http.Client{Timeout: 30 * time.Second}
	verifierResultReader, err := adapter.NewIndexerReaderAdapter(
		executorConfig.IndexerAddress,
		httpClient,
		executorMonitoring,
		lggr,
	)
	if err != nil {
		lggr.Errorw("Failed to create indexer adapter", "error", err)
		return fmt.Errorf("failed to create indexer adapter: %w", err)
	}

	execPool := make(map[protocol.ChainSelector][]string)
	execIntervals := make(map[protocol.ChainSelector]time.Duration)
	defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress)

	for strSel, chainConfig := range executorConfig.ChainConfiguration {
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		execPool[protocol.ChainSelector(selector)] = chainConfig.ExecutorPool
		execIntervals[protocol.ChainSelector(selector)] = chainConfig.ExecutionInterval
		defaultExecutorAddresses[protocol.ChainSelector(selector)], err = protocol.NewUnknownAddressFromHex(chainConfig.DefaultExecutorAddress)
		if err != nil {
			lggr.Errorw("Invalid default executor address in configuration", "error", err, "chainSelector", strSel)
			continue
		}
	}

	ex := x.NewChainlinkExecutor(
		lggr,
		components.ContractTransmitters,
		components.DestinationReaders,
		curseChecker,
		verifierResultReader,
		executorMonitoring,
		defaultExecutorAddresses,
	)
	if err := ex.Validate(); err != nil {
		lggr.Errorw("Failed to validate chainlink executor", "error", err)
		return fmt.Errorf("failed to validate chainlink executor: %w", err)
	}

	le, err := leaderelector.NewHashBasedLeaderElector(
		lggr,
		execPool,
		executorConfig.ExecutorID,
		execIntervals,
	)
	if err != nil {
		lggr.Errorw("Failed to create leader elector", "error", err)
		return fmt.Errorf("failed to create leader elector: %w", err)
	}

	timeProvider := backofftimeprovider.NewBackoffNTPProvider(lggr, executorConfig.BackoffDuration, executorConfig.NtpServer)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:    verifierResultReader,
			InitialQueryTime: time.Now().Add(-1 * executorConfig.LookbackWindow),
			PollingInterval:  indexerPollingInterval,
			Backoff:          executorConfig.BackoffDuration,
			QueryLimit:       executorConfig.IndexerQueryLimit,
			ExpiryDuration:   messageContextWindow,
			CleanInterval:    indexerGarbageCollectionInterval,
			TimeProvider:     timeProvider,
		})

	coordinator, err := executor.NewCoordinator(
		lggr,
		ex,
		indexerStream,
		le,
		executorMonitoring,
		executorConfig.MaxRetryDuration,
		timeProvider,
		executorConfig.WorkerCount,
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator", "error", err)
		return fmt.Errorf("failed to create execution coordinator: %w", err)
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start execution coordinator", "error", err)
		return fmt.Errorf("failed to start execution coordinator: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("CCV Executor is running!")
		lggr.Infow("Executor ID", "executorID", executorConfig.ExecutorID)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		for serviceName, err := range coordinator.HealthReport() {
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				lggr.Infow("Unhealthy service", "service", serviceName, "error", err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	// TODO: listen port should be configurable.
	server := &http.Server{Addr: ":8101", Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		lggr.Infow("HTTP server starting", "port", "8101")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lggr.Errorw("HTTP server error", "error", err)
		}
	}()

	f.server = server
	f.coordinator = coordinator

	lggr.Infow("Executor service fully started and ready!")

	return nil
}

// Stop implements [bootstrap.ServiceFactory].
func (f *factory[T]) Stop(ctx context.Context) error {
	var allErrors error

	if f.server != nil {
		if err := f.server.Shutdown(ctx); err != nil {
			f.lggr.Errorw("HTTP server shutdown error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	if f.coordinator != nil {
		if err := f.coordinator.Close(); err != nil {
			f.lggr.Errorw("Coordinator stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	if f.profiler != nil {
		if err := f.profiler.Stop(); err != nil {
			f.lggr.Errorw("Pyroscope stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	f.server = nil
	f.coordinator = nil
	f.profiler = nil
	f.lggr = nil

	return allErrors
}
