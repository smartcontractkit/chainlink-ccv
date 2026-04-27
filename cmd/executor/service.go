package executor

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/executor"
	adapter "github.com/smartcontractkit/chainlink-ccv/executor/pkg/adapter"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/backofftimeprovider"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// indexerPollingInterval describes how frequently we ask indexer for new messages.
	// This should be kept at 1s for consistent behavior across all executors.
	indexerPollingInterval = 1 * time.Second
	// indexerGarbageCollectionInterval describes how frequently we garbage collect message duplicates from the indexer results.
	// if this is too short, we will assume a message is net new every time it is read from the indexer.
	indexerGarbageCollectionInterval = 1 * time.Hour
	// messageContextWindow is the time window we use to expire duplicate messages from the indexer.
	// this combines with indexerGarbageCollectionInterval to avoid memory leak in the streamer.
	// We store messages for messageContextWindow, cleaning up old messages every indexerGarbageCollectionInterval.
	messageContextWindow = 9 * time.Hour
)

// Factory is a bootstrap.ServiceFactory that starts the executor service.
type Factory struct {
	coordinator *executorsvc.Coordinator
	profiler    *pyroscope.Profiler
	lggr        logger.Logger
}

var _ bootstrap.ServiceFactory = (*Factory)(nil)

// NewFactory creates a new executor Factory.
func NewFactory() *Factory {
	return &Factory{}
}

func (f *Factory) Stop(_ context.Context) error {
	var err error
	if f.coordinator != nil {
		err = f.coordinator.Close()
	}
	if f.profiler != nil {
		_ = f.profiler.Stop()
	}
	return err
}

func (f *Factory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
	var rawConfig executorsvc.ConfigWithBlockchainInfo[any]
	if err := spec.GetAppConfig(&rawConfig); err != nil {
		return fmt.Errorf("failed to decode executor config: %w", err)
	}

	executorConfig, err := rawConfig.GetNormalizedConfig()
	if err != nil {
		return fmt.Errorf("failed to normalize executor config: %w", err)
	}

	f.lggr, err = logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	f.lggr = logger.Sugared(logger.Named(f.lggr, "executor"))

	f.profiler, err = StartPyroscope(f.lggr, executorConfig.PyroscopeURL, "executor")
	if err != nil {
		f.lggr.Errorw("Failed to start pyroscope", "error", err)
	}

	protocol.InitChainSelectorCache()

	f.lggr.Infow("Executor configuration", "config", executorConfig)

	executorMonitoring := SetupMonitoring(f.lggr, executorConfig.Monitoring)

	contractTransmitters := make(map[protocol.ChainSelector]chainaccess.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]chainaccess.DestinationReader)
	rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	enabledDestChains := make([]protocol.ChainSelector, 0)

	for strSel, chainConfig := range executorConfig.ChainConfiguration {
		selectorUint, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			f.lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		selector := protocol.ChainSelector(selectorUint)

		accessor, err := deps.Registry.GetAccessor(ctx, selector)
		if err != nil {
			f.lggr.Errorw("Failed to get accessor for chain", "error", err, "chainSelector", strSel)
			continue
		}

		dr, drErr := accessor.DestinationReader()
		if drErr != nil {
			f.lggr.Warnw("Skipping chain: missing DestinationReader", "chainSelector", strSel, "error", drErr)
			continue
		}

		var ct chainaccess.ContractTransmitter
		if deps.Keystore != nil && chainConfig.TransmitterKeyName != "" && chainConfig.TransmitterRPCURL != "" {
			ct, err = contracttransmitter.NewEVMContractTransmitterFromKeystore(
				ctx,
				f.lggr,
				selector,
				chainConfig.TransmitterRPCURL,
				deps.Keystore,
				chainConfig.TransmitterKeyName,
				common.HexToAddress(chainConfig.OffRampAddress),
			)
			if err != nil {
				f.lggr.Warnw("Failed to create keystore contract transmitter, falling back to accessor", "chainSelector", strSel, "error", err)
			}
		}
		if ct == nil {
			ct, err = accessor.ContractTransmitter()
			if err != nil {
				f.lggr.Warnw("Skipping chain: missing ContractTransmitter", "chainSelector", strSel, "error", err)
				continue
			}
		}

		destReaders[selector] = dr
		rmnReaders[selector] = dr
		contractTransmitters[selector] = ct
		enabledDestChains = append(enabledDestChains, selector)
	}

	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        f.lggr,
		Metrics:     executorMonitoring.Metrics(),
		RmnReaders:  rmnReaders,
		CacheExpiry: executorConfig.ReaderCacheExpiry,
	})

	httpClient := &http.Client{Timeout: 30 * time.Second}
	verifierResultReader, err := adapter.NewIndexerReaderAdapter(
		executorConfig.IndexerAddress,
		httpClient,
		executorMonitoring,
		f.lggr,
	)
	if err != nil {
		return fmt.Errorf("failed to create indexer adapter: %w", err)
	}

	execPool := make(map[protocol.ChainSelector][]string)
	execIntervals := make(map[protocol.ChainSelector]time.Duration)
	defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress)

	for strSel, chainConfig := range executorConfig.ChainConfiguration {
		selectorUint, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			f.lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}
		sel := protocol.ChainSelector(selectorUint)
		execPool[sel] = chainConfig.ExecutorPool
		execIntervals[sel] = chainConfig.ExecutionInterval
		defaultExecutorAddresses[sel], err = protocol.NewUnknownAddressFromHex(chainConfig.DefaultExecutorAddress)
		if err != nil {
			f.lggr.Errorw("Invalid default executor address in configuration", "error", err, "chainSelector", strSel)
			continue
		}
	}

	ex := x.NewChainlinkExecutor(f.lggr, contractTransmitters, destReaders, curseChecker, verifierResultReader, executorMonitoring, defaultExecutorAddresses)
	if err := ex.Validate(); err != nil {
		return fmt.Errorf("failed to validate chainlink executor: %w", err)
	}

	le, err := leaderelector.NewHashBasedLeaderElector(
		f.lggr,
		execPool,
		executorConfig.ExecutorID,
		execIntervals,
	)
	if err != nil {
		return fmt.Errorf("failed to create leader elector: %w", err)
	}

	timeProvider := backofftimeprovider.NewBackoffNTPProvider(f.lggr, executorConfig.BackoffDuration, executorConfig.NtpServer)

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		f.lggr,
		ccvstreamer.IndexerStorageConfig{
			IndexerClient:     verifierResultReader,
			InitialQueryTime:  time.Now().Add(-1 * executorConfig.LookbackWindow),
			PollingInterval:   indexerPollingInterval,
			Backoff:           executorConfig.BackoffDuration,
			QueryLimit:        executorConfig.IndexerQueryLimit,
			ExpiryDuration:    messageContextWindow,
			CleanInterval:     indexerGarbageCollectionInterval,
			TimeProvider:      timeProvider,
			EnabledDestChains: enabledDestChains,
		})

	f.coordinator, err = executorsvc.NewCoordinator(
		f.lggr,
		ex,
		indexerStream,
		le,
		executorMonitoring,
		executorConfig.MaxRetryDuration,
		timeProvider,
		executorConfig.WorkerCount,
	)
	if err != nil {
		return fmt.Errorf("failed to create execution coordinator: %w", err)
	}

	if err := f.coordinator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start execution coordinator: %w", err)
	}

	return nil
}
