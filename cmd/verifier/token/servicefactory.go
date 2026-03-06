package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/grafana/pyroscope-go"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	verifier2 "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/ccvstorage"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	tokenapi "github.com/smartcontractkit/chainlink-ccv/verifier/token/api"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// CreateAccessorFactoryFunc is a function that creates an accessor factory for a given chain family.
// The blockchain infos map is keyed by chain selector (as string); the callback may build a
// family-specific helper from it (e.g. blockchain.NewHelper for EVM).
type CreateAccessorFactoryFunc[T any] func(
	ctx context.Context,
	lggr logger.Logger,
	blockchainInfos map[string]*T,
	cfg token.Config,
) (chainaccess.AccessorFactory, error)

// chainSelectorsFromMap returns chain selectors parsed from the keys of a map keyed by selector string.
func chainSelectorsFromMap[T any](m map[string]*T) []protocol.ChainSelector {
	out := make([]protocol.ChainSelector, 0, len(m))
	for sel := range m {
		u, err := strconv.ParseUint(sel, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, protocol.ChainSelector(u))
	}
	return out
}

// factory is a ServiceFactory implementation that creates a token verifier service.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
// NOTE: this factory supports only a single chain family at a time.
// This is by design, since deployed CCIP apps will be built with a single chain family, but potentially
// supporting many chains from that same family.
type factory[T any] struct {
	lggr         logger.Logger
	server       *http.Server
	coordinators []*verifier.Coordinator
	profiler     *pyroscope.Profiler
	db           sqlutil.DataSource

	createAccessorFactoryFunc CreateAccessorFactoryFunc[T]
	chainFamily               string
}

// NewTokenVerifierServiceFactory creates a new ServiceFactory for the token verifier service.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
func NewTokenVerifierServiceFactory[T any](
	chainFamily string,
	createAccessorFactoryFunc CreateAccessorFactoryFunc[T],
) bootstrap.ServiceFactory[token.JobSpec] {
	return &factory[T]{
		createAccessorFactoryFunc: createAccessorFactoryFunc,
		chainFamily:               chainFamily,
	}
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory[T]) Start(ctx context.Context, spec token.JobSpec, deps bootstrap.ServiceDeps) error {
	lggr := logger.Sugared(logger.Named(deps.Logger, "TokenVerifier"))
	f.lggr = lggr

	lggr.Infow("Starting token verifier service", "spec", spec)

	config, blockchainInfos, err := token.LoadConfigWithBlockchainInfos[T](spec)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	lggr.Infow("Using blockchain information from config", "chainCount", len(blockchainInfos))

	profiler, err := verifier2.StartPyroscope(lggr, config.PyroscopeURL, "tokenVerifier")
	if err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
		return fmt.Errorf("failed to start pyroscope: %w", err)
	}
	f.profiler = profiler

	accessorFactory, err := f.createAccessorFactoryFunc(ctx, lggr, blockchainInfos, *config)
	if err != nil {
		lggr.Errorw("Failed to create accessor factory", "error", err)
		return fmt.Errorf("failed to create accessor factory: %w", err)
	}

	// Build source readers for all selectors that match this factory's chain family.
	chainSelectors := chainSelectorsFromMap(blockchainInfos)
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range chainSelectors {
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("Failed to get selector family", "error", err, "selector", selector)
			return fmt.Errorf("failed to get selector family: %w", err)
		}
		if family != f.chainFamily {
			lggr.Warnw("Skipping chain in provided config, doesn't match expected chain family",
				"selector", selector,
				"family", family,
				"expectedFamily", f.chainFamily,
			)
			continue
		}

		accessor, err := accessorFactory.GetAccessor(ctx, selector)
		if err != nil {
			lggr.Errorw("Failed to get accessor", "error", err, "selector", selector)
			return fmt.Errorf("failed to get accessor: %w", err)
		}
		reader := accessor.SourceReader()
		if reader == nil {
			lggr.Errorw("Failed to get source reader for chain", "selector", selector)
			return fmt.Errorf("failed to get source reader for chain selector %d", selector)
		}
		sourceReaders[selector] = reader
		lggr.Infow("🚀 Created source reader for chain", "chainSelector", selector)
	}

	verifierMonitoring := verifier2.SetupMonitoring(lggr, config.Monitoring)

	db, err := verifier2.ConnectToPostgresDB(lggr)
	if err != nil {
		lggr.Errorw("Failed to connect to Postgres database", "error", err)
		return fmt.Errorf("failed to connect to Postgres database: %w", err)
	}
	f.db = db

	postgresStorage := ccvstorage.NewPostgres(db, lggr)
	monitoredStorage := ccvstorage.NewMonitoredStorage(postgresStorage, verifierMonitoring.Metrics())

	// Build RMN Remote address map (string selector → UnknownAddress).
	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for sel, addrHex := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(addrHex)
		if err != nil {
			lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", sel)
			return fmt.Errorf("failed to create RMN Remote address for selector %s: %w", sel, err)
		}
		rmnRemoteAddresses[sel] = addr
	}

	// Build one coordinator per token verifier config entry.
	f.coordinators = make([]*verifier.Coordinator, 0, len(config.TokenVerifiers))
	for _, verifierConfig := range config.TokenVerifiers {
		chainStatusManager := chainstatus.NewPostgresChainStatusManager(db, lggr, verifierConfig.VerifierID)
		monitoredChainStatusManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, verifierMonitoring.Metrics())

		messageTracker := monitoring.NewMessageLatencyTracker(lggr, verifierConfig.VerifierID, verifierMonitoring)

		var coordinator *verifier.Coordinator
		if verifierConfig.IsCCTP() {
			coordinator, err = createCCTPCoordinator(
				ctx,
				verifierConfig.VerifierID,
				verifierConfig.CCTPConfig,
				lggr,
				sourceReaders,
				rmnRemoteAddresses,
				storage.NewAttestationCCVWriter(lggr, verifierConfig.CCTPConfig.ParsedVerifierResolvers, monitoredStorage),
				messageTracker,
				verifierMonitoring,
				monitoredChainStatusManager,
				db,
			)
		} else if verifierConfig.IsLombard() {
			coordinator, err = createLombardCoordinator(
				ctx,
				verifierConfig.VerifierID,
				verifierConfig.LombardConfig,
				lggr,
				sourceReaders,
				rmnRemoteAddresses,
				storage.NewAttestationCCVWriter(lggr, verifierConfig.LombardConfig.ParsedVerifierResolvers, monitoredStorage),
				messageTracker,
				verifierMonitoring,
				monitoredChainStatusManager,
				db,
			)
		} else {
			return fmt.Errorf("unknown verifier type for verifier ID %q", verifierConfig.VerifierID)
		}
		if err != nil {
			return fmt.Errorf("failed to create coordinator for verifier %q: %w", verifierConfig.VerifierID, err)
		}

		if err := coordinator.Start(ctx); err != nil {
			lggr.Errorw("Failed to start verification coordinator", "error", err, "verifierID", verifierConfig.VerifierID)
			return fmt.Errorf("failed to start verification coordinator %q: %w", verifierConfig.VerifierID, err)
		}
		lggr.Infow("✅ Verification coordinator started", "verifierID", verifierConfig.VerifierID)

		f.coordinators = append(f.coordinators, coordinator)
	}

	// Build health reporters from all coordinators.
	healthReporters := make([]protocol.HealthReporter, len(f.coordinators))
	for i, c := range f.coordinators {
		healthReporters[i] = c
	}

	ginRouter := tokenapi.NewHTTPAPI(lggr, storage.NewAttestationCCVReader(postgresStorage), healthReporters, verifierMonitoring)

	// TODO: listen port should be configurable.
	server := &http.Server{
		Addr:         ":8100",
		Handler:      ginRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		lggr.Infow("🌐 HTTP API server starting", "port", "8100")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lggr.Errorw("HTTP server error", "error", err)
		}
	}()
	f.server = server

	lggr.Infow("🎯 Token verifier service fully started and ready!")
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

	for _, c := range f.coordinators {
		if err := c.Close(); err != nil {
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

	if f.db != nil {
		if closer, ok := f.db.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				f.lggr.Errorw("Database close error", "error", err)
				allErrors = errors.Join(allErrors, err)
			}
		}
	}

	f.server = nil
	f.coordinators = nil
	f.profiler = nil
	f.db = nil
	f.lggr = nil

	return allErrors
}

func createCCTPCoordinator(
	_ context.Context,
	verifierID string,
	cctpConfig *cctp.CCTPConfig,
	lggr logger.Logger,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
	ccvStorage protocol.CCVNodeDataWriter,
	messageTracker verifier.MessageLatencyTracker,
	verifierMonitoring verifier.Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	db sqlutil.DataSource,
) (*verifier.Coordinator, error) {
	sourceConfigs := createSourceConfigs(cctpConfig.ParsedVerifierResolvers, rmnRemoteAddresses)

	attestationService, err := cctp.NewAttestationService(lggr, *cctpConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create CCTP attestation service: %w", err)
	}

	coordinator, err := verifier.NewCoordinator(
		lggr,
		cctp.NewVerifier(lggr, attestationService),
		sourceReaders,
		ccvStorage,
		verifier.CoordinatorConfig{
			VerifierID:          verifierID,
			SourceConfigs:       sourceConfigs,
			StorageBatchSize:    50,
			StorageBatchTimeout: 100 * time.Millisecond,
			StorageRetryDelay:   500 * time.Millisecond,
			CursePollInterval:   2 * time.Second,
		},
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		heartbeatclient.NewNoopHeartbeatClient(),
		db,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CCTP coordinator: %w", err)
	}
	return coordinator, nil
}

func createLombardCoordinator(
	_ context.Context,
	verifierID string,
	lombardConfig *lombard.LombardConfig,
	lggr logger.Logger,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
	ccvStorage protocol.CCVNodeDataWriter,
	messageTracker verifier.MessageLatencyTracker,
	verifierMonitoring verifier.Monitoring,
	chainStatusManager protocol.ChainStatusManager,
	db sqlutil.DataSource,
) (*verifier.Coordinator, error) {
	sourceConfigs := createSourceConfigs(lombardConfig.ParsedVerifierResolvers, rmnRemoteAddresses)

	attestationService, err := lombard.NewAttestationService(lggr, *lombardConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Lombard attestation service: %w", err)
	}

	lombardVerifier, err := lombard.NewVerifier(lggr, *lombardConfig, attestationService)
	if err != nil {
		return nil, fmt.Errorf("failed to create Lombard verifier: %w", err)
	}

	coordinator, err := verifier.NewCoordinator(
		lggr,
		lombardVerifier,
		sourceReaders,
		ccvStorage,
		verifier.CoordinatorConfig{
			VerifierID:          verifierID,
			SourceConfigs:       sourceConfigs,
			StorageBatchSize:    50,
			StorageBatchTimeout: 100 * time.Millisecond,
			StorageRetryDelay:   500 * time.Millisecond,
			CursePollInterval:   2 * time.Second,
		},
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		heartbeatclient.NewNoopHeartbeatClient(),
		db,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Lombard coordinator: %w", err)
	}
	return coordinator, nil
}

func createSourceConfigs(
	verifiers map[protocol.ChainSelector]protocol.UnknownAddress,
	rmnRemoteAddresses map[string]protocol.UnknownAddress,
) map[protocol.ChainSelector]verifier.SourceConfig {
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for selector, address := range verifiers {
		strSelector := strconv.FormatUint(uint64(selector), 10)
		sourceConfigs[selector] = verifier.SourceConfig{
			VerifierAddress:        address,
			DefaultExecutorAddress: nil,
			PollInterval:           1 * time.Second,
			ChainSelector:          selector,
			RMNRemoteAddress:       rmnRemoteAddresses[strSelector],
		}
	}
	return sourceConfigs
}
