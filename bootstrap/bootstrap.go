package bootstrap

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

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
type ServiceFactory[AppConfig any] interface {
	// Start starts the service with the parsed config received from JD.
	Start(ctx context.Context, appConfig AppConfig, deps ServiceDeps) error
	// Stop stops the service.
	Stop(ctx context.Context) error
}

// A runner adapts a [ServiceFactory] to the [lifecycle.JobRunner] interface.
type runner[AppConfig any] struct {
	fac  ServiceFactory[AppConfig]
	deps ServiceDeps
}

var _ lifecycle.JobRunner = (*runner[any])(nil)

// StartJob implements [lifecycle.JobRunner].
func (r *runner[AppConfig]) StartJob(ctx context.Context, spec string) error {
	appConfig, err := parseTOMLStrict[AppConfig](spec)
	if err != nil {
		return fmt.Errorf("failed to parse app config toml: %w", err)
	}
	return r.fac.Start(ctx, appConfig, r.deps)
}

// StopJob implements [lifecycle.JobRunner].
func (r *runner[AppConfig]) StopJob(ctx context.Context) error {
	return r.fac.Stop(ctx)
}

// A Bootstrapper manages the lifecycle of a CCIP standalone application.
type Bootstrapper[AppConfig any] struct {
	lggr logger.Logger
	cfg  Config
	fac  ServiceFactory[AppConfig]
	name string

	logLevel zapcore.Level

	lifecycleManager *lifecycle.Manager
	infoServer       *infoServer
}

// NewBootstrapper creates a new [Bootstrapper] with the given config and service factory.
func NewBootstrapper[AppConfig any](
	name string,
	lggr logger.Logger,
	cfg Config,
	fac ServiceFactory[AppConfig],
	opts ...Option[AppConfig],
) (*Bootstrapper[AppConfig], error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}

	b := &Bootstrapper[AppConfig]{
		lggr:     lggr,
		cfg:      cfg,
		fac:      fac,
		name:     name,
		logLevel: zapcore.InfoLevel,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
}

// Start initializes the keystore, connects to JD, and starts the lifecycle manager.
func (b *Bootstrapper[AppConfig]) Start(ctx context.Context) error {
	db, err := b.connectToDB(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}

	keyStore, csaSigner, err := b.initializeKeystore(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to initialize keystore: %w", err)
	}

	jdPublicKey, err := keys.DecodeEd25519PublicKey(b.cfg.JD.ServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get JD public key: %w", err)
	}
	jdClient := jdclient.New(csaSigner, jdPublicKey, b.cfg.JD.ServerWSRPCURL, b.lggr)

	deps, err := b.newServiceDeps(keyStore)
	if err != nil {
		return fmt.Errorf("failed to create service deps: %w", err)
	}

	jobRunner := &runner[AppConfig]{fac: b.fac, deps: deps}
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

	infoServer := newInfoServer(b.lggr, keyStore, b.cfg.Server.ListenPort)
	if err := infoServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start info server: %w", err)
	}
	b.infoServer = infoServer

	return nil
}

// Stop shuts down the lifecycle manager and info server.
func (b *Bootstrapper[AppConfig]) Stop(ctx context.Context) error {
	if err := b.lifecycleManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop lifecycle manager: %w", err)
	}
	if err := b.infoServer.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop info server: %w", err)
	}
	return nil
}

func (b *Bootstrapper[AppConfig]) connectToDB(ctx context.Context) (*sqlx.DB, error) {
	db, err := sqlx.ConnectContext(ctx, "postgres", b.cfg.DB.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}
	if err := dbpkg.RunMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run bootstrapper database migrations: %w", err)
	}
	return db, nil
}

func (b *Bootstrapper[AppConfig]) newServiceDeps(keyStore keystore.Keystore) (ServiceDeps, error) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(b.logLevel))
	if err != nil {
		return ServiceDeps{}, fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, b.name))
	return ServiceDeps{
		Logger:   lggr,
		Keystore: keyStore,
	}, nil
}

func (b *Bootstrapper[AppConfig]) initializeKeystore(ctx context.Context, db *sqlx.DB) (keystore.Keystore, crypto.Signer, error) {
	ks, err := keystore.LoadKeystore(ctx, keys.NewPGStorage(db, "default"), b.cfg.Keystore.Password)
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
		if err := keys.EnsureKey(ctx, b.lggr, ks, k.name, k.purpose, k.keyType); err != nil {
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
type Option[AppConfig any] func(*Bootstrapper[AppConfig])

// WithLogLevel sets the log level for the logger passed to the application.
func WithLogLevel[AppConfig any](logLevel zapcore.Level) Option[AppConfig] {
	return func(b *Bootstrapper[AppConfig]) {
		b.logLevel = logLevel
	}
}

// Run is a convenience function that loads config, creates a bootstrapper,
// starts it, and blocks until SIGINT or SIGTERM is received.
func Run[AppConfig any](
	name string,
	fac ServiceFactory[AppConfig],
	opts ...Option[AppConfig],
) error {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, "Bootstrapper"))

	configPath := os.Getenv(ConfigPathEnv)
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	bootstrapper, err := NewBootstrapper(name, lggr, cfg, fac, opts...)
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
