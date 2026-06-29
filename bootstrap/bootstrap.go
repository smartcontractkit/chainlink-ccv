package bootstrap

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap/zapcore"

	dbpkg "github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/common"
	jdclient "github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	jobstore "github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
	zaplog "github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// ConfigPathEnv is the env var holding the app config file path.
	ConfigPathEnv = "CONFIG_PATH"

	defaultStartupTimeout  = 10 * time.Second
	defaultShutdownTimeout = 10 * time.Second
)

// ServiceDeps are the dependencies passed to the services started by the bootstrapper.
type ServiceDeps struct {
	// Logger is a logger that can be used by the service.
	Logger logger.Logger

	// Keystore is an initialized keystore that can be used by the service.
	Keystore keystore.Keystore

	// Registry for chainaccess.Accessor objects.
	Registry chainaccess.Registry

	// Monitoring is the validated monitoring config resolved by the bootstrapper.
	Monitoring *monitoring.Config
}

// ResolveMonitoring returns the effective monitoring config for a service, preferring the
// operator-provided bootstrap config (fromBootstrap) over the deprecated app-config fallback.
//
// fromBootstrap is nil when the operator did not configure monitoring in the bootstrap config; in
// that case the (deprecated) app-config value is used. Presence (non-nil), not Enabled, is the
// discriminator: an operator who sets [monitoring] with Enabled=false is honored (monitoring off),
// not silently overridden by the app-config fallback. It logs which source won so operators can
// diagnose monitoring during the migration window in which both sources may be present.
//
// TODO(cleanup): remove once all deployments source monitoring from the bootstrap config; callers
// then read *deps.Monitoring directly.
func ResolveMonitoring(lggr logger.Logger, fromBootstrap *monitoring.Config, appConfigFallback monitoring.Config) monitoring.Config {
	if fromBootstrap != nil {
		lggr.Infow("Using monitoring config from bootstrap config")
		return *fromBootstrap
	}
	lggr.Infow("Using monitoring config from deprecated app config (no monitoring section in bootstrap config)")
	return appConfigFallback
}

// ServiceFactory is an interface implemented by the application that seeks to be bootstrapped.
type ServiceFactory interface {
	// Start starts the service with the parsed config received from JD.
	Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error
	// Stop stops the service.
	Stop(ctx context.Context) error
}

// A runner adapts a [ServiceFactory] to the [lifecycle.JobRunner] interface.
type runner struct {
	fac       ServiceFactory
	deps      ServiceDeps
	accCloser *AccessorCloserRegistry
}

var _ lifecycle.JobRunner = (*runner)(nil)

// StartJob implements [lifecycle.JobRunner].
// On Start failure, the deferred CloseAll is the only chance to release accessors.
func (r *runner) StartJob(ctx context.Context, config string) (startErr error) {
	r.deps.Logger.Infow("starting job")

	var spec JobSpec
	if _, err := toml.Decode(config, &spec); err != nil {
		return fmt.Errorf("bootstrap: failed to parse config: %w", err)
	}

	// Initialize registry, wrapping it so the keystore is injected into any
	// Accessor that implements KeystoreSetter.
	// Registry chain: NewRegistry > KeystoreRegistry (keystore injection) > AccessorCloserRegistry (accessor cleanup tracking).
	reg, err := chainaccess.NewRegistry(r.deps.Logger, spec.AppConfig)
	if err != nil {
		return fmt.Errorf("failed to create registry: %w", err)
	}
	r.accCloser = NewAccessorCloserRegistry(r.deps.Logger, NewKeystoreRegistry(r.deps.Logger, reg, r.deps.Keystore))
	r.deps.Registry = r.accCloser

	// safety net
	defer func() {
		if startErr != nil {
			if cErr := r.accCloser.CloseAll(); cErr != nil {
				r.deps.Logger.Warnw("close accessors after failed StartJob", "error", cErr)
			}
		}
	}()

	return r.fac.Start(ctx, spec, r.deps)
}

// StopJob implements [lifecycle.JobRunner].
// CloseAll runs after factory.Stop so the coordinator drains its readers before underlying services are released.
func (r *runner) StopJob(ctx context.Context) error {
	var errs []error
	if err := r.fac.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("stop service factory: %w", err))
	}
	if r.accCloser != nil {
		if err := r.accCloser.CloseAll(); err != nil {
			errs = append(errs, fmt.Errorf("close accessors: %w", err))
		}
	}
	return errors.Join(errs...)
}

// A Bootstrapper manages the lifecycle of a CCIP standalone application.
type Bootstrapper struct {
	lggr   logger.Logger
	config Config

	lifecycleManager *lifecycle.Manager
	infoServer       *infoServer

	// application
	fac  ServiceFactory
	name string

	// accCloser is set by startWithAppConfig; JD mode uses runner.accCloser instead.
	accCloser *AccessorCloserRegistry
}

// NewBootstrapper creates a new [Bootstrapper] from a fully-resolved [Config]. It does not load any
// files or environment variables — use ResolveConfig (which Run does) to produce cfg.
func NewBootstrapper(name string, lggr logger.Logger, fac ServiceFactory, opts ...Option) (*Bootstrapper, error) {
	config, err := ResolveConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve bootstrap config: %w", err)
	}
	return &Bootstrapper{name: name, lggr: lggr, fac: fac, config: config}, nil
}

// startWithAppConfig is a passthrough to the application's Start function.
func (b *Bootstrapper) startWithAppConfig(ctx context.Context) (startErr error) {
	b.lggr.Infow("Calling NewRegistry with app config")
	reg, err := chainaccess.NewRegistry(b.lggr, *b.config.AppConfig)
	if err != nil {
		return fmt.Errorf("failed to create registry: %w", err)
	}
	b.accCloser = NewAccessorCloserRegistry(b.lggr, reg)
	// safety net for partial-Start failure since Bootstrapper.Stop is not guaranteed
	defer func() {
		if startErr != nil {
			if cErr := b.accCloser.CloseAll(); cErr != nil {
				b.lggr.Warnw("close accessors after failed startWithAppConfig", "error", cErr)
			}
			b.accCloser = nil
		}
	}()

	js := JobSpec{
		Name:          "no-jd",
		ExternalJobID: "",
		SchemaVersion: 0,
		Type:          "",
		AppConfig:     *b.config.AppConfig,
	}

	return b.fac.Start(ctx, js, ServiceDeps{Registry: b.accCloser, Monitoring: b.config.Monitoring})
}

// startWithJDLifecycle initializes all components required for the JD lifecycle manager and starts it.
func (b *Bootstrapper) startWithJDLifecycle(ctx context.Context) (retErr error) {
	db, err := connectToDB(ctx, b.config.DB.URL)
	if err != nil {
		return fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = db.Close()
		}
	}()

	keyStore, csaSigner, err := initializeKeystore(ctx, b.lggr, db, b.config.Keystore)
	if err != nil {
		return fmt.Errorf("failed to initialize keystore: %w", err)
	}

	jdPublicKey, err := keys.DecodeEd25519PublicKey(b.config.JD.ServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get JD public key: %w", err)
	}
	jdClient := jdclient.New(csaSigner, jdPublicKey, b.config.JD.ServerWSRPCURL, b.lggr)
	defer func() {
		if retErr != nil {
			_ = jdClient.Close()
		}
	}()

	deps, err := newServiceDeps(keyStore, b.config.zapLevel(), b.name)
	if err != nil {
		return fmt.Errorf("failed to create service deps: %w", err)
	}
	deps.Monitoring = b.config.Monitoring

	jobRunner := &runner{fac: b.fac, deps: deps}
	lifecycleManager, err := lifecycle.NewManager(lifecycle.Config{
		JDClient: jdClient,
		JobStore: jobstore.NewPostgresStore(db),
		Runner:   jobRunner,
		Logger:   logger.Named(b.lggr, "LifecycleManager"),
	})
	if err != nil {
		return fmt.Errorf("failed to create lifecycle manager: %w", err)
	}

	if err := lifecycleManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start lifecycle manager: %w", err)
	}
	b.lifecycleManager = lifecycleManager

	infoServer := newInfoServer(b.lggr, keyStore, b.config.Server.ListenPort)
	if err := infoServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start info server: %w", err)
	}
	b.infoServer = infoServer

	return nil
}

// Start initializes the keystore, connects to JD, and starts the lifecycle manager.
func (b *Bootstrapper) Start(ctx context.Context) error {
	if b.config.AppConfig != nil {
		return b.startWithAppConfig(ctx)
	}
	return b.startWithJDLifecycle(ctx)
}

// Stop shuts down all active components.
//
// The two startup modes own mutually exclusive sets of objects, so stopping every
// non-nil field is sufficient to cover both without double-stopping anything:
//   - JD mode (lifecycleManager/infoServer set, appConfig nil): the lifecycle manager and info server are stopped.
//     Accessor cleanup is owned by runner.StopJob, invoked by the lifecycle manager.
//   - Static-config mode (appConfig set, lifecycleManager/infoServer nil): factory.Stop runs first, then accCloser.CloseAll
func (b *Bootstrapper) Stop(ctx context.Context) error {
	if b.lifecycleManager != nil {
		if err := b.lifecycleManager.Stop(); err != nil {
			return fmt.Errorf("failed to stop lifecycle manager: %w", err)
		}
	}
	if b.infoServer != nil {
		if err := b.infoServer.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop info server: %w", err)
		}
	}
	if b.config.AppConfig != nil {
		var errs []error
		if err := b.fac.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop service factory: %w", err))
		}
		if b.accCloser != nil {
			if err := b.accCloser.CloseAll(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close accessors: %w", err))
			}
			b.accCloser = nil
		}
		return errors.Join(errs...)
	}
	return nil
}

func connectToDB(ctx context.Context, connStr string) (*sqlx.DB, error) {
	db, err := sqlx.ConnectContext(ctx, "postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}
	if err := dbpkg.RunMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run bootstrapper database migrations: %w", err)
	}
	return db, nil
}

func newServiceDeps(keyStore keystore.Keystore, logLevel zapcore.Level, name string) (ServiceDeps, error) {
	lggr, err := logger.NewWith(zaplog.GetLogProfile(logLevel))
	if err != nil {
		return ServiceDeps{}, fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, name))
	return ServiceDeps{
		Logger:   lggr,
		Keystore: keyStore,
	}, nil
}

func initializeKeystore(ctx context.Context, lggr logger.Logger, db *sqlx.DB, config KeystoreConfig) (keystore.Keystore, crypto.Signer, error) {
	ks, err := keystore.LoadKeystore(ctx, keys.NewPGStorage(db, "default"), config.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load keystore: %w", err)
	}

	var csaKeyName string
	for _, k := range config.keys {
		if err := keys.EnsureKey(ctx, lggr, ks, k.name, k.purpose, k.keyType); err != nil {
			return nil, nil, fmt.Errorf("failed to ensure key %q (purpose=%q, type=%v): %w", k.name, k.purpose, k.keyType, err)
		}
		if k.purpose == "csa" {
			csaKeyName = k.name
		}
	}
	if csaKeyName == "" {
		return nil, nil, fmt.Errorf("no key with purpose %q declared; a CSA key is required for JD communication", "csa")
	}

	csaSigner, err := keys.NewCSASigner(ctx, ks, csaKeyName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get csa signer: %w", err)
	}

	return ks, csaSigner, nil
}

// Run resolves the config from options (deciding static vs JD mode), creates a bootstrapper,
// starts it, and blocks until SIGINT or SIGTERM is received.
func Run(
	name string,
	fac ServiceFactory,
	opts ...Option,
) error {
	lggr, err := logger.NewWith(zaplog.GetLogProfile(zapcore.InfoLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, "Bootstrapper"))
	lggr = common.WithService(lggr, name)

	bootstrapper, err := NewBootstrapper(name, lggr, fac, opts...)
	if err != nil {
		return fmt.Errorf("failed to create bootstrapper: %w", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), defaultStartupTimeout)
	defer startCancel()

	if err := bootstrapper.Start(startCtx); err != nil {
		return fmt.Errorf("failed to start bootstrapper: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	lggr.Infow("Received shutdown signal, stopping bootstrapper...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer shutdownCancel()

	if err := bootstrapper.Stop(shutdownCtx); err != nil {
		return fmt.Errorf("failed to stop bootstrapper: %w", err)
	}

	return nil
}
