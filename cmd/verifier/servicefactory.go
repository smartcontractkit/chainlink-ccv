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
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// defaultHTTPListenPort is the port the verifier's HTTP server listens on when the job config
// does not set http_listen_port.
const defaultHTTPListenPort = 8100

// httpShutdownTimeout bounds the graceful drain of the HTTP server during Stop.
const (
	httpShutdownTimeout = 5 * time.Second
	// accessorBuildTimeout caps one chain's accessor construction (RPC dial +
	// chain services) during factory Start; the parent startup context may be
	// tighter and always wins.
	accessorBuildTimeout = 30 * time.Second
)

// factory is a ServiceFactory implementation that creates a committee verifier service.
type factory struct {
	lggr             logger.Logger
	server           *http.Server
	coordinator      *verifier.Coordinator
	profiler         *pyroscope.Profiler
	aggregatorWriter *storageaccess.FanOutWriter
	heartbeatClient  heartbeatclient.HeartbeatSender
	chainStatusDB    sqlutil.DataSource
	adminStop        func()
}

var _ bootstrap.ServiceFactoryValidator = (*factory)(nil)

// NewCommitteeVerifierServiceFactory creates a new ServiceFactory for the committee verifier service.
// The factory loads the verifier secrets file itself in Start, so each chain-family binary's main.go
// stays free of secrets-loading boilerplate.
func NewCommitteeVerifierServiceFactory() bootstrap.ServiceFactory {
	return &factory{}
}

func validateJobSpec(spec bootstrap.JobSpec) (commit.Config, error) {
	var config commit.Config
	if err := spec.GetAppConfig(&config); err != nil {
		return commit.Config{}, fmt.Errorf("failed to get app config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return commit.Config{}, err
	}
	return config, nil
}

func instrumentSourceReader(
	reader chainaccess.SourceReader,
	verifierID string,
	selector protocol.ChainSelector,
	verifierMonitoring verifier.Monitoring,
) (chainaccess.SourceReader, error) {
	if verifierMonitoring == nil {
		return nil, fmt.Errorf("cannot instrument source reader for chain %d: monitoring is nil", selector)
	}

	if setter, ok := reader.(chainaccess.CriticalSourceInvariantCallbackSetter); ok {
		chainMetrics := verifierMonitoring.Metrics().With(
			"chain_selector", selector.String(),
			"chain_name", selector.ChainName(),
		)
		setter.SetCriticalSourceInvariantCallback(func(ctx context.Context) {
			chainMetrics.IncrementCriticalSourceInvariantViolations(ctx)
		})
	}

	observedReader, err := sourcereader.NewObservedSourceReader(reader, verifierID, selector, verifierMonitoring)
	if err != nil {
		return nil, fmt.Errorf("failed to create observed source reader for chain %d: %w", selector, err)
	}
	return observedReader, nil
}

// Validate implements [bootstrap.ServiceFactoryValidator].
func (f *factory) Validate(spec bootstrap.JobSpec) error {
	_, err := validateJobSpec(spec)
	return err
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
	if deps.Keystore == nil {
		return fmt.Errorf(
			"committee verifier requires a keystore: ensure the [keystore] section in the secrets is set correctly" +
				", with any corresponding fields in [db] if backend is 'postgres'")
	}

	protocol.InitChainSelectorCache()

	config, err := validateJobSpec(spec)
	if err != nil {
		return err
	}

	f.lggr = deps.Logger
	verifierMonitoring, err := monitoring.InitMonitoring("committee_verifier")
	if err != nil {
		return fmt.Errorf("failed to init monitoring: %w", err)
	}

	lggr := f.lggr

	// Load the verifier secrets file (DB URL + aggregator HMAC credentials). Owning this here keeps
	// per-binary main.go free of boilerplate; an absent file falls back to environment variables.
	secrets, err := vsecrets.LoadFromEnv(vsecrets.CommitteeVerifierSecretsPathEnv, vsecrets.DefaultCommitteeVerifierSecretsPath)
	if err != nil {
		lggr.Errorw("Failed to load verifier secrets", "error", err)
		return fmt.Errorf("failed to load verifier secrets: %w", err)
	}

	if config.PyroscopeURL != "" {
		profiler, err := StartPyroscope(lggr, config.PyroscopeURL, "verifier")
		if err != nil {
			lggr.Errorw("Failed to start pyroscope", "error", err)
			return fmt.Errorf("failed to start pyroscope: %w", err)
		}
		f.profiler = profiler
	}

	// A failure to stand up one chain's reader (e.g. an unreachable RPC) must not stop the
	// remaining chains from starting. Log and skip, then only reject the whole coordinator if no
	// chain is usable. Chains are built concurrently with a per-chain timeout: accessor
	// construction dials the chain, so a slow (not failing) RPC must not serialize away the
	// shared startup budget.
	chainSelectors := chainaccess.Infos[string](config.OnRampAddresses).GetAllChainSelectors()
	// Skipped chains are reported on /health as degraded. The stack fails below when none is usable.
	startupSkips := health.NewStartupSkips("verifier.StartupSkips")
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	var readersMu sync.Mutex
	var wg sync.WaitGroup
	for _, selector := range chainSelectors {
		wg.Go(func() {
			chainCtx, cancel := context.WithTimeout(ctx, accessorBuildTimeout)
			defer cancel()
			//nolint:noeagerio // accessor construction dials the chain; it runs concurrently per chain with a bounded ctx, and failures are skipped, not fatal
			accessor, err := deps.Registry.GetAccessor(chainCtx, selector)
			if err != nil {
				lggr.Errorw("Failed to get accessor, skipping chain", "error", err, "selector", selector)
				startupSkips.SkipChain(selector, err)
				verifierMonitoring.RecordChainHealthy(ctx, selector, false)
				return
			}
			reader, err := accessor.SourceReader()
			if err != nil {
				lggr.Errorw("Failed to get source reader, skipping chain", "selector", selector, "error", err)
				startupSkips.SkipChain(selector, err)
				verifierMonitoring.RecordChainHealthy(ctx, selector, false)
				return
			}
			observedReader, err := instrumentSourceReader(reader, config.VerifierID, selector, verifierMonitoring)
			if err != nil {
				lggr.Errorw("Failed to instrument source reader, skipping chain", "selector", selector, "error", err)
				startupSkips.SkipChain(selector, err)
				verifierMonitoring.RecordChainHealthy(ctx, selector, false)
				return
			}
			verifierMonitoring.RecordChainHealthy(ctx, selector, true)
			readersMu.Lock()
			sourceReaders[selector] = observedReader
			readersMu.Unlock()
		})
	}
	wg.Wait()

	stack, err := startCommitteeVerifier(ctx, lggr, config, committeeVerifierDeps{
		keystore:           deps.Keystore,
		sourceReaders:      sourceReaders,
		secrets:            secrets,
		verifierMonitoring: verifierMonitoring,
	})
	if err != nil {
		return err
	}
	f.aggregatorWriter = stack.fanOutWriter
	f.heartbeatClient = stack.heartbeatClient
	f.chainStatusDB = stack.chainStatusDB
	f.coordinator = stack.coordinator

	verifierMonitoring.RecordServiceStarted(ctx)

	// Dedicated router per Start(): JD job replacement calls Start again after Stop, and a
	// fresh gin.New() avoids any route-registration state carrying over between starts.
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		lggr.Infow("CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", config.VerifierID)
	})

	healthManager := health.NewManager()
	healthManager.Register(stack.coordinator)
	healthManager.Register(startupSkips)
	health.RegisterOn(healthManager, router)

	router.GET("/stats", func(c *gin.Context) {
		stats := stack.fanOutWriter.GetStats()
		lggr.Infow("Storage Statistics:\n")
		for key, value := range stats {
			lggr.Infow("%s: %v\n", key, value)
		}
	})

	// Start HTTP server
	listenPort := config.HTTPListenPort
	if listenPort == 0 {
		listenPort = defaultHTTPListenPort
	}
	server := &http.Server{
		Addr:         ":" + strconv.Itoa(listenPort),
		Handler:      router,
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

	// The admin console serves in-process when its config file is present; it shares
	// this verifier's application database and secrets.
	aggregatorAddress, aggregatorInsecure := "", false
	if len(stack.resolvedAggregators) > 0 {
		aggregatorAddress = stack.resolvedAggregators[0].Address
		aggregatorInsecure = stack.resolvedAggregators[0].InsecureConnection
	}
	adminStop, err := startAdminConsole(lggr, stack.chainStatusDB, secrets, aggregatorAddress, aggregatorInsecure)
	if err != nil {
		return fmt.Errorf("failed to start admin console: %w", err)
	}
	f.adminStop = adminStop

	lggr.Infow("🎯 Verifier service fully started and ready!")

	return nil
}

func (f *factory) MetricViews() []sdkmetric.View {
	return monitoring.MetricViews()
}

// Stop implements [bootstrap.ServiceFactory].
func (f *factory) Stop(ctx context.Context) error {
	var allErrors error
	// Stop HTTP server. Stop is routinely called with an already-canceled context (process
	// teardown, failed Start). Shutdown would then return that context error immediately
	// without draining in-flight requests, so drop the caller's cancellation and bound the
	// drain ourselves.
	if f.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpShutdownTimeout)
		err := f.server.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			f.lggr.Errorw("HTTP server shutdown error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop verification coordinator
	if f.coordinator != nil {
		if err := f.coordinator.Close(); err != nil {
			f.lggr.Errorw("Coordinator stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop pyroscope
	if f.profiler != nil {
		if err := f.profiler.Stop(); err != nil {
			f.lggr.Errorw("Pyroscope stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop aggregator writer.
	if f.aggregatorWriter != nil {
		if err := f.aggregatorWriter.Close(); err != nil {
			f.lggr.Errorw("Aggregator writer stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop heartbeat client
	if f.heartbeatClient != nil {
		if err := f.heartbeatClient.Close(); err != nil {
			f.lggr.Errorw("Heartbeat client stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop the admin console
	if f.adminStop != nil {
		f.adminStop()
	}

	f.server = nil
	f.coordinator = nil
	f.profiler = nil
	f.aggregatorWriter = nil
	f.heartbeatClient = nil
	f.adminStop = nil
	f.lggr = nil
	f.chainStatusDB = nil

	return allErrors
}
