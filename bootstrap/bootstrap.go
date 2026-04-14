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
	var spec JobSpec
	_, err := toml.Decode(config, &spec)
	if err != nil {
		return fmt.Errorf("bootstrap: failed to parse config: %w", err)
	}
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

	// If no configuration is provided, default to JD lifecycle manager with config loaded from the default path.
	if b.appCfg == nil && b.config == nil {
		b.config = &Config{}
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
	js := JobSpec{
		Name:          "no-jd",
		ExternalJobID: "",
		SchemaVersion: 0,
		Type:          "",
		AppConfig:     *b.appCfg,
	}
	return b.fac.Start(ctx, js, ServiceDeps{})
}

// startWithJDLifecycle initializes all components required for the JD lifecycle manager and starts it.
func (b *Bootstrapper) startWithJDLifecycle(ctx context.Context) error {
	db, err := connectToDB(ctx, b.config.DB.URL)
	if err != nil {
		return fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}

	keyStore, csaSigner, err := initializeKeystore(ctx, b.lggr, db, b.config.Keystore.Password)
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

// Stop shuts down the lifecycle manager and info server.
func (b *Bootstrapper) Stop(ctx context.Context) error {
	if err := b.lifecycleManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop lifecycle manager: %w", err)
	}
	if err := b.infoServer.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop info server: %w", err)
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

func initializeKeystore(ctx context.Context, lggr logger.Logger, db *sqlx.DB, ksPassword string) (keystore.Keystore, crypto.Signer, error) {
	ks, err := keystore.LoadKeystore(ctx, keys.NewPGStorage(db, "default"), ksPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load keystore: %w", err)
	}

	requiredKeys := []struct {
		name    string
		purpose string
		keyType keystore.KeyType
	}{
		{keys.DefaultCSAKeyName, "csa", keystore.Ed25519},
		{keys.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256},
		{keys.DefaultEdDSASigningKeyName, "signing", keystore.Ed25519},
	}
	for _, k := range requiredKeys {
		if err := keys.EnsureKey(ctx, lggr, ks, k.name, k.purpose, k.keyType); err != nil {
			return nil, nil, fmt.Errorf("failed to ensure %s key: %w", k.purpose, err)
		}
	}

	csaSigner, err := keys.NewCSASigner(ctx, ks, keys.DefaultCSAKeyName)
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

// WithJD tells the bootstrapper to load config from JD and start the JD lifecycle manager.
// This is the default option if no AppConfig is provided.
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
