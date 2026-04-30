package bootstrap

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap/zapcore"

	dbpkg "github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	jdclient "github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	jobstore "github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	ConfigPathEnv     = "BOOTSTRAPPER_CONFIG_PATH"
	DefaultConfigPath = "/etc/config.toml"

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
	Registry *chainaccess.Registry
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
	fac  ServiceFactory
	deps ServiceDeps
}

var _ lifecycle.JobRunner = (*runner)(nil)

// StartJob implements [lifecycle.JobRunner].
func (r *runner) StartJob(ctx context.Context, config string) error {
	r.deps.Logger.Infow("starting job")

	var spec JobSpec
	if _, err := toml.Decode(config, &spec); err != nil {
		return fmt.Errorf("bootstrap: failed to parse config: %w", err)
	}

	// Initialize registry.
	reg, err := chainaccess.NewRegistry(r.deps.Logger, spec.AppConfig)
	if err != nil {
		return fmt.Errorf("failed to create registry: %w", err)
	}
	r.deps.Registry = reg

	return r.fac.Start(ctx, spec, r.deps)
}

// StopJob implements [lifecycle.JobRunner].
func (r *runner) StopJob(ctx context.Context) error {
	return r.fac.Stop(ctx)
}

// A Bootstrapper manages the lifecycle of a CCIP standalone application.
type Bootstrapper struct {
	lggr logger.Logger

	// bootstrapper component configs
	configPath       string
	config           *Config
	lifecycleManager *lifecycle.Manager
	infoServer       *infoServer
	keys             []keyToInit

	// application
	appCfg *string
	fac    ServiceFactory
	name   string

	logLevel zapcore.Level
}

// NewBootstrapper creates a new [Bootstrapper] with the given config and service factory.
func NewBootstrapper(
	name string,
	lggr logger.Logger,
	fac ServiceFactory,
	opts ...Option,
) (*Bootstrapper, error) {
	b := &Bootstrapper{
		lggr:     lggr,
		fac:      fac,
		name:     name,
		logLevel: zapcore.InfoLevel,
	}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Backwards compatibility: if no keys are declared, initialize the original default set.
	// Deprecated: we should remove these once all apps and integrations define required keys.
	if len(b.keys) == 0 {
		b.keys = []keyToInit{
			{keys.DefaultCSAKeyName, "csa", keystore.Ed25519},
			{keys.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256},
			{keys.DefaultEdDSASigningKeyName, "signing", keystore.Ed25519},
		}
	}

	// If no configuration is provided, default to JD lifecycle manager with config loaded from the default path.
	if b.appCfg == nil && b.config == nil {
		b.config = &Config{}
	}

	// JD mode requires a CSA key for node authentication. Inject the default if the caller
	// did not explicitly declare one, so callers only need to list their application keys.
	if b.config != nil {
		hasCSA := false
		for _, k := range b.keys {
			if k.purpose == "csa" {
				hasCSA = true
				break
			}
		}
		if !hasCSA {
			b.keys = append([]keyToInit{{keys.DefaultCSAKeyName, "csa", keystore.Ed25519}}, b.keys...)
		}
	}

	if b.config != nil {
		// Use provided config path if set by an option.
		if b.configPath == "" {
			// If no config path is provided by an option, check the environment variable.
			b.configPath = os.Getenv(ConfigPathEnv)
			if b.configPath == "" {
				// If the environment variable is not set, use the default config path.
				b.configPath = DefaultConfigPath
			}
		}

		err := LoadAndValidateConfig(b.configPath, b.config)
		if err != nil {
			return nil, fmt.Errorf("failed to load bootstrap config (%s): %w", b.configPath, err)
		}

		// not logging config because it contains secrets.
		lggr.Infow("loaded bootstrap config")
	}

	return b, nil
}

// startWithAppConfig is a passthrough to the application's Start function.
func (b *Bootstrapper) startWithAppConfig(ctx context.Context) error {
	if b.appCfg == nil {
		return fmt.Errorf("bootstrapper has no app config")
	}

	b.lggr.Infow("Calling NewRegistry with app config")
	reg, err := chainaccess.NewRegistry(b.lggr, *b.appCfg)
	if err != nil {
		return fmt.Errorf("failed to create registry: %w", err)
	}

	js := JobSpec{
		Name:          "no-jd",
		ExternalJobID: "",
		SchemaVersion: 0,
		Type:          "",
		AppConfig:     *b.appCfg,
	}

	return b.fac.Start(ctx, js, ServiceDeps{Registry: reg})
}

// startWithJDLifecycle initializes all components required for the JD lifecycle manager and starts it.
func (b *Bootstrapper) startWithJDLifecycle(ctx context.Context) error {
	db, err := connectToDB(ctx, b.config.DB.URL)
	if err != nil {
		return fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}

	keyStore, csaSigner, err := initializeKeystore(ctx, b.lggr, db, b.config.Keystore.Password, b.keys)
	if err != nil {
		return fmt.Errorf("failed to initialize keystore: %w", err)
	}

	jdPublicKey, err := keys.DecodeEd25519PublicKey(b.config.JD.ServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get JD public key: %w", err)
	}
	jdClient := jdclient.New(csaSigner, jdPublicKey, b.config.JD.ServerWSRPCURL, b.lggr)

	deps, err := newServiceDeps(keyStore, b.logLevel, b.name)
	if err != nil {
		return fmt.Errorf("failed to create service deps: %w", err)
	}

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
	if b.config != nil {
		return b.startWithJDLifecycle(ctx)
	}
	if b.appCfg != nil {
		return b.startWithAppConfig(ctx)
	}

	return fmt.Errorf("no configuration provided: either JD config or app config must be provided")
}

// Stop shuts down all active components.
//
// The two startup modes own mutually exclusive sets of objects, so stopping every
// non-nil field is sufficient to cover both without double-stopping anything:
//   - JD mode (lifecycleManager/infoServer set, appCfg nil): the lifecycle manager and info server are stopped.
//   - Static-config mode (appCfg set, lifecycleManager/infoServer nil): the factory is stopped directly.
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
	if b.appCfg != nil {
		if err := b.fac.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop service factory: %w", err)
		}
	}
	return nil
}

func connectToDB(ctx context.Context, connStr string) (*sqlx.DB, error) {
	db, err := sqlx.ConnectContext(ctx, "postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}
	if err := dbpkg.RunMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run bootstrapper database migrations: %w", err)
	}
	return db, nil
}

func newServiceDeps(keyStore keystore.Keystore, logLevel zapcore.Level, name string) (ServiceDeps, error) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(logLevel))
	if err != nil {
		return ServiceDeps{}, fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, name))
	return ServiceDeps{
		Logger:   lggr,
		Keystore: keyStore,
	}, nil
}

func initializeKeystore(ctx context.Context, lggr logger.Logger, db *sqlx.DB, ksPassword string, requiredKeys []keyToInit) (keystore.Keystore, crypto.Signer, error) {
	ks, err := keystore.LoadKeystore(ctx, keys.NewPGStorage(db, "default"), ksPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load keystore: %w", err)
	}

	var csaKeyName string
	for _, k := range requiredKeys {
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

// Option configures a [Bootstrapper].
type Option func(*Bootstrapper) error

// WithLogLevel sets the log level for the logger passed to the application.
func WithLogLevel(logLevel zapcore.Level) Option {
	return func(b *Bootstrapper) error {
		b.logLevel = logLevel
		return nil
	}
}

type keyToInit struct {
	name    string
	purpose string
	keyType keystore.KeyType
}

// WithKey declares a key that the bootstrapper must ensure exists, creating it if absent.
// When no WithKey options are provided, the bootstrapper applies a default set of three keys:
// keys.DefaultCSAKeyName (Ed25519), keys.DefaultECDSASigningKeyName (ECDSA_S256), and
// keys.DefaultEdDSASigningKeyName (Ed25519). Passing one or more WithKey options suppresses
// those defaults entirely; the caller is responsible for declaring every key it requires.
func WithKey(name, purpose string, keyType keystore.KeyType) Option {
	return func(b *Bootstrapper) error {
		b.keys = append(b.keys, keyToInit{
			name:    name,
			purpose: purpose,
			keyType: keyType,
		})
		return nil
	}
}

// WithJD tells the bootstrapper to load config from JD and start the JD lifecycle manager.
// This is the default option if no AppConfig is provided.
// JD mode requires a keystore and a CSA key for node authentication. The bootstrapper
// automatically provisions keys.DefaultCSAKeyName unless a key with purpose "csa" is
// already declared via WithKey.
func WithJD() Option {
	return func(b *Bootstrapper) error {
		b.config = &Config{}
		return nil
	}
}

// WithBootstrapperConfigPath sets the bootstrapper config file path. If not set, the bootstrapper will look
// for the config path in the BOOTSTRAPPER_CONFIG_PATH environment variable, and if that is not
// set, it will default to DefaultConfigPath.
func WithBootstrapperConfigPath(path string) Option {
	return func(b *Bootstrapper) error {
		b.configPath = path
		return nil
	}
}

// WithTOMLAppConfig tells bootstrap to load the application config from a given filepath instead of JD.
func WithTOMLAppConfig(configFilePath string) Option {
	return func(b *Bootstrapper) error {
		configFilePath = filepath.Clean(configFilePath)
		cfg, err := os.ReadFile(configFilePath)
		if err != nil {
			return err
		}
		cfgs := string(cfg)
		b.appCfg = &cfgs
		return nil
	}
}

// Run is a convenience function that loads config, creates a bootstrapper,
// starts it, and blocks until SIGINT or SIGTERM is received.
func Run(
	name string,
	fac ServiceFactory,
	opts ...Option,
) error {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, "Bootstrapper"))

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
