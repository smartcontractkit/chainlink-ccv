package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grafana/pyroscope-go"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/common/health"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/storage"
	tokenapi "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/api"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// unifiedFactory is a ServiceFactory implementation that runs committee and token verifiers in
// one process, selected purely by the app config's [[verifiers]] entries.
type unifiedFactory struct {
	lggr         logger.Logger
	server       *http.Server
	coordinators []*verifier.Coordinator
	profiler     *pyroscope.Profiler
	committee    *committeeStack
	db           sqlutil.DataSource
	adminStop    func()
}

var _ bootstrap.ServiceFactoryValidator = (*unifiedFactory)(nil)

// NewUnifiedVerifierServiceFactory creates a new ServiceFactory for the unified verifier service.
// The factory loads the verifier secrets file itself in Start, so the binary's main.go stays
// free of secrets-loading boilerplate.
func NewUnifiedVerifierServiceFactory() bootstrap.ServiceFactory {
	return &unifiedFactory{}
}

// Validate implements [bootstrap.ServiceFactoryValidator].
func (f *unifiedFactory) Validate(spec bootstrap.JobSpec) error {
	var config UnifiedConfig
	if err := spec.GetAppConfig(&config); err != nil {
		return fmt.Errorf("failed to get app config: %w", err)
	}
	return config.Validate()
}

// buildSourceReaders constructs one base (uninstrumented) source reader per configured chain,
// concurrently with a per-chain timeout. Failures skip the chain and degrade /health instead of
// failing startup. The accessors map is kept for CCTP codec resolution.
func buildSourceReaders(
	ctx context.Context,
	lggr logger.Logger,
	registry chainaccess.Registry,
	onRampAddresses map[string]string,
	startupSkips *health.StartupSkips,
	verifierMonitoring verifier.Monitoring,
) (map[protocol.ChainSelector]chainaccess.SourceReader, map[protocol.ChainSelector]chainaccess.Accessor) {
	chainSelectors := chainaccess.Infos[string](onRampAddresses).GetAllChainSelectors()
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	accessors := make(map[protocol.ChainSelector]chainaccess.Accessor)
	var accessorsMu sync.Mutex
	var wg sync.WaitGroup
	for _, selector := range chainSelectors {
		wg.Go(func() {
			chainCtx, cancel := context.WithTimeout(ctx, accessorBuildTimeout)
			defer cancel()
			//nolint:noeagerio // accessor construction dials the chain; it runs concurrently per chain with a bounded ctx, and failures are skipped, not fatal
			accessor, err := registry.GetAccessor(chainCtx, selector)
			if err != nil {
				lggr.Errorw("Skipping chain, failed to get accessor for chain selector", "error", err, "chainSelector", selector)
				startupSkips.SkipChain(selector, err)
				verifierMonitoring.RecordChainHealthy(ctx, selector, false)
				return
			}
			reader, err := accessor.SourceReader()
			accessorsMu.Lock()
			accessors[selector] = accessor
			accessorsMu.Unlock()
			if err != nil {
				lggr.Warnw("Skipping chain, source reader not available", "chainSelector", selector, "error", err)
				startupSkips.SkipChain(selector, err)
				verifierMonitoring.RecordChainHealthy(ctx, selector, false)
				return
			}
			verifierMonitoring.RecordChainHealthy(ctx, selector, true)
			accessorsMu.Lock()
			sourceReaders[selector] = reader
			accessorsMu.Unlock()
			lggr.Infow("Created source reader for chain", "chainSelector", selector)
		})
	}
	wg.Wait()
	return sourceReaders, accessors
}

// Start implements [bootstrap.ServiceFactory].
func (f *unifiedFactory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
	var config UnifiedConfig
	if err := spec.GetAppConfig(&config); err != nil {
		return fmt.Errorf("failed to get app config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid unified verifier config: %w", err)
	}

	if config.HasCommittee() && deps.Keystore == nil {
		return fmt.Errorf(
			"committee verifier requires a keystore: ensure the [keystore] section in the secrets is set correctly" +
				", with any corresponding fields in [db] if backend is 'postgres'")
	}

	protocol.InitChainSelectorCache()

	f.lggr = deps.Logger
	lggr := f.lggr
	verifierMonitoring, err := monitoring.InitMonitoring("verifier")
	if err != nil {
		return fmt.Errorf("failed to init monitoring: %w", err)
	}

	if config.PyroscopeURL != "" {
		profiler, err := StartPyroscope(lggr, config.PyroscopeURL, "verifier")
		if err != nil {
			lggr.Errorw("Failed to start pyroscope", "error", err)
			return fmt.Errorf("failed to start pyroscope: %w", err)
		}
		f.profiler = profiler
	}

	// Load the unified verifier secrets file (DB URL, aggregator HMAC credentials, policy hook).
	// Owning this here keeps main.go free of boilerplate; an absent file falls back to env vars.
	secrets, err := vsecrets.LoadFromEnv(vsecrets.VerifierSecretsPathEnv, vsecrets.DefaultVerifierSecretsPath)
	if err != nil {
		lggr.Errorw("Failed to load verifier secrets", "error", err)
		return fmt.Errorf("failed to load verifier secrets: %w", err)
	}

	// Skipped chains/verifiers degrade the service on /health, which names each one.
	// The factory fails below when no verifier is usable.
	startupSkips := health.NewStartupSkips("verifier.StartupSkips")
	sourceReaders, accessors := buildSourceReaders(ctx, lggr, deps.Registry, config.OnRampAddresses, startupSkips, verifierMonitoring)

	// One DB connection serves every entry: chain status always, token storage when token
	// entries exist.
	//nolint:noeagerio // the service's own DB is a hard dependency: connect + migrate fail fast (bounded by the startup ctx) and JD/local restarts retry
	db, err := ConnectToPostgresDB(ctx, lggr, secrets)
	if err != nil {
		return fmt.Errorf("failed to connect to Postgres database: %w", err)
	}
	f.db = db

	postgresStorage := storage.NewPostgres(db, lggr)
	// Wrap storage with monitoring decorator to track query durations
	monitoredStorage := storage.NewMonitoredStorage(postgresStorage, verifierMonitoring.Metrics())
	chainStatusStore := chainstatus.NewPostgresChainStatusStore(db, lggr)

	for i := range config.Verifiers {
		entry := &config.Verifiers[i]
		switch {
		case entry.CommitteeEntryConfig != nil:
			if err := f.startCommitteeEntry(ctx, entry, config, deps.Keystore, sourceReaders, db, secrets, verifierMonitoring, startupSkips); err != nil {
				// Committee entry failures are deterministic config/environment errors: fail fast
				// like the committee factory, closing any coordinators already started.
				for _, c := range f.coordinators {
					if closeErr := c.Close(); closeErr != nil {
						lggr.Warnw("Failed to close coordinator during aborted startup", "error", closeErr)
					}
				}
				f.coordinators = nil
				return fmt.Errorf("failed to start committee verifier %q: %w", entry.VerifierID, err)
			}
		default:
			f.startTokenEntry(ctx, entry, config, sourceReaders, accessors, db, monitoredStorage, chainStatusStore, verifierMonitoring, startupSkips)
		}
	}
	if len(f.coordinators) == 0 {
		return fmt.Errorf("failed to start any verifier across %d configured", len(config.Verifiers))
	}

	listenPort := config.HTTPListenPort
	if listenPort == 0 {
		listenPort = defaultHTTPListenPort
	}

	var handler *gin.Engine
	if config.HasTokenVerifiers() {
		healthReporters := make([]protocol.HealthReporter, 0, len(f.coordinators)+1)
		for _, coordinator := range f.coordinators {
			healthReporters = append(healthReporters, coordinator)
		}
		healthReporters = append(healthReporters, startupSkips)
		handler = tokenapi.NewHTTPAPI(lggr, storage.NewCCVReader(postgresStorage), healthReporters, verifierMonitoring)
		if f.committee != nil {
			registerStatsRoute(handler, lggr, f.committee.fanOutWriter)
		}
	} else {
		// Committee-only: keep the committee-style router (/, /health, /stats).
		committeeVerifierID := ""
		for i := range config.Verifiers {
			if config.Verifiers[i].CommitteeEntryConfig != nil {
				committeeVerifierID = config.Verifiers[i].VerifierID
			}
		}
		router := gin.New()
		router.GET("/", func(c *gin.Context) {
			lggr.Infow("CCV Verifier is running!\n")
			lggr.Infow("Verifier ID: %s\n", committeeVerifierID)
		})
		healthManager := health.NewManager()
		for _, coordinator := range f.coordinators {
			healthManager.Register(coordinator)
		}
		healthManager.Register(startupSkips)
		health.RegisterOn(healthManager, router)
		registerStatsRoute(router, lggr, f.committee.fanOutWriter)
		handler = router
	}

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(listenPort),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		lggr.Infow("🌐 HTTP server starting", "port", listenPort)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lggr.Errorw("HTTP server error", "error", err)
		}
	}()
	f.server = server

	// The admin console serves in-process when its config file is present; it shares this
	// verifier's application database and secrets, and uses the committee entry's first
	// aggregator for freshness checks when one is configured.
	aggregatorAddress, aggregatorInsecure := "", false
	if f.committee != nil && len(f.committee.resolvedAggregators) > 0 {
		aggregatorAddress = f.committee.resolvedAggregators[0].Address
		aggregatorInsecure = f.committee.resolvedAggregators[0].InsecureConnection
	}
	adminStop, err := startAdminConsole(lggr, db, secrets, aggregatorAddress, aggregatorInsecure)
	if err != nil {
		return fmt.Errorf("failed to start admin console: %w", err)
	}
	f.adminStop = adminStop

	verifierMonitoring.RecordServiceStarted(ctx)

	lggr.Infow("🎯 Verifier service fully started and ready!")

	return nil
}

// startCommitteeEntry instruments the shared base readers for this entry and starts the
// committee stack on them.
func (f *unifiedFactory) startCommitteeEntry(
	ctx context.Context,
	entry *Entry,
	config UnifiedConfig,
	keystore keystore.Keystore,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	db sqlutil.DataSource,
	secrets *vsecrets.VerifierSecrets,
	verifierMonitoring verifier.Monitoring,
	startupSkips *health.StartupSkips,
) error {
	lggr := f.lggr
	committeeReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader, len(sourceReaders))
	for selector, reader := range sourceReaders {
		observedReader, err := instrumentSourceReader(reader, entry.VerifierID, selector, verifierMonitoring)
		if err != nil {
			lggr.Errorw("Failed to instrument source reader, skipping chain", "selector", selector, "error", err)
			startupSkips.SkipChain(selector, err)
			verifierMonitoring.RecordChainHealthy(ctx, selector, false)
			continue
		}
		committeeReaders[selector] = observedReader
	}

	commitCfg := entry.ToCommitConfig(config)
	commitCfg.VerifierID = entry.VerifierID
	stack, err := startCommitteeVerifier(ctx, lggr, commitCfg, committeeVerifierDeps{
		keystore:           keystore,
		sourceReaders:      committeeReaders,
		db:                 db,
		secrets:            secrets,
		verifierMonitoring: verifierMonitoring,
	})
	if err != nil {
		return err
	}
	f.committee = stack
	f.coordinators = append(f.coordinators, stack.coordinator)
	return nil
}

// startTokenEntry creates and starts one token (cctp/lombard) coordinator. A failure to stand
// up one verifier must not stop the remaining verifiers: log, skip, and record for /health;
// Start rejects the whole service only when no verifier is usable.
func (f *unifiedFactory) startTokenEntry(
	ctx context.Context,
	entry *Entry,
	config UnifiedConfig,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	accessors map[protocol.ChainSelector]chainaccess.Accessor,
	db sqlutil.DataSource,
	monitoredStorage storage.CCVStorage,
	chainStatusStore *chainstatus.PostgresChainStatusStore,
	verifierMonitoring verifier.Monitoring,
	startupSkips *health.StartupSkips,
) {
	lggr := f.lggr
	chainStatusManager := chainstatus.NewMonitoredChainStatusManager(
		chainstatus.NewPostgresChainStatusManager(chainStatusStore, entry.VerifierID), verifierMonitoring.Metrics())
	messageTracker := monitoring.NewMessageLatencyTracker(lggr, entry.VerifierID, verifierMonitoring)

	var coordinator *verifier.Coordinator
	var createErr error
	switch {
	case entry.IsLombard():
		coordinator, createErr = createLombardCoordinator(
			ctx,
			entry.VerifierID,
			entry.LombardConfig,
			config.DisableFinalityCheckers,
			lggr,
			sourceReaders,
			storage.NewCCVWriter(lggr, entry.LombardConfig.ParsedVerifierResolvers, monitoredStorage),
			messageTracker,
			verifierMonitoring,
			chainStatusManager,
			db,
		)
	case entry.IsCCTP():
		cctpCodecs, codecErr := cctpCodecsFor(accessors, entry.CCTPConfig)
		if codecErr != nil {
			lggr.Errorw("Skipping verifier, failed to build CCTP codecs", "verifierID", entry.VerifierID, "error", codecErr)
			startupSkips.Skip(fmt.Sprintf("Verifier[%s]", entry.VerifierID), codecErr)
			return
		}
		coordinator, createErr = createCCTPCoordinator(
			ctx,
			entry.VerifierID,
			entry.CCTPConfig,
			config.DisableFinalityCheckers,
			lggr,
			sourceReaders,
			cctpCodecs,
			storage.NewCCVWriter(lggr, entry.CCTPConfig.ParsedVerifierResolvers, monitoredStorage),
			messageTracker,
			verifierMonitoring,
			chainStatusManager,
			db,
		)
	default:
		// Unknown type is a deterministic config error rejected at Validate; reaching it here is a bug.
		lggr.Errorw("Skipping verifier, unknown type", "verifierID", entry.VerifierID, "type", entry.Type)
		startupSkips.Skip(fmt.Sprintf("Verifier[%s]", entry.VerifierID), fmt.Errorf("unknown verifier type %q", entry.Type))
		return
	}
	if createErr != nil {
		lggr.Errorw("Skipping verifier, failed to create verification coordinator",
			"verifierID", entry.VerifierID, "type", entry.Type, "error", createErr)
		startupSkips.Skip(fmt.Sprintf("Verifier[%s]", entry.VerifierID), createErr)
		return
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Skipping verifier, failed to start verification coordinator",
			"verifierID", entry.VerifierID, "type", entry.Type, "error", err)
		startupSkips.Skip(fmt.Sprintf("Verifier[%s]", entry.VerifierID), err)
		// The coordinator may have partially started subcomponents (batcher,
		// processors, source readers) before failing: close it so the skip
		// does not leak them for the life of the process.
		if closeErr := coordinator.Close(); closeErr != nil {
			lggr.Warnw("Failed to close skipped verification coordinator",
				"verifierID", entry.VerifierID, "error", closeErr)
		}
		return
	}
	f.coordinators = append(f.coordinators, coordinator)
}

// registerStatsRoute adds the committee writer's /stats endpoint to the router.
func registerStatsRoute(router *gin.Engine, lggr logger.Logger, fanOutWriter *storageaccess.FanOutWriter) {
	router.GET("/stats", func(c *gin.Context) {
		stats := fanOutWriter.GetStats()
		lggr.Infow("Storage Statistics:\n")
		for key, value := range stats {
			lggr.Infow("%s: %v\n", key, value)
		}
	})
}

func (f *unifiedFactory) MetricViews() []sdkmetric.View {
	return monitoring.MetricViews()
}

// Stop implements [bootstrap.ServiceFactory], mirroring the union of the committee and token
// factories' Stop.
func (f *unifiedFactory) Stop(ctx context.Context) error {
	var allErrors error
	// Stop is routinely called with an already-canceled context (process teardown, failed
	// Start). Shutdown would then return that context error immediately without draining
	// in-flight requests, so drop the caller's cancellation and bound the drain ourselves.
	if f.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpShutdownTimeout)
		err := f.server.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			f.lggr.Errorw("HTTP server shutdown error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	for _, coordinator := range f.coordinators {
		if err := coordinator.Close(); err != nil {
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

	if f.committee != nil {
		if err := f.committee.close(); err != nil {
			f.lggr.Errorw("Committee stack stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	if f.adminStop != nil {
		f.adminStop()
	}

	f.server = nil
	f.coordinators = nil
	f.profiler = nil
	f.committee = nil
	f.adminStop = nil
	f.lggr = nil
	f.db = nil

	return allErrors
}
