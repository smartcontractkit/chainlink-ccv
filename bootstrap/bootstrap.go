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
	jdclient "github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	jobstore "github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/pgstore"
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
	Logger   logger.Logger
	Keystore keystore.Keystore
}

// ServiceFactory is an interface implemented by the application that seeks to be bootstrapped.
// It is used to start and stop the services.
type ServiceFactory interface {
	// Start starts the service with the spec received from JD.
	Start(ctx context.Context, spec string, deps ServiceDeps) error
	// Stop stops the service.
	Stop(ctx context.Context) error
}

type Bootstrapper struct {
	lggr logger.Logger
	cfg  Config
	fac  ServiceFactory
	name string

	logLevel zapcore.Level

	// state
	lifecycleManager *lifecycle.Manager
	infoServer       *infoServer
}

func NewBootstrapper(name string, lggr logger.Logger, cfg Config, fac ServiceFactory, opts ...Option) (*Bootstrapper, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}

	bootstrapper := &Bootstrapper{
		lggr:     lggr,
		cfg:      cfg,
		fac:      fac,
		name:     name,
		logLevel: zapcore.InfoLevel, // default log level
	}
	for _, opt := range opts {
		opt(bootstrapper)
	}
	return bootstrapper, nil
}

// Run does the following:
// 1. Initializes the keystore and makes sure that all needed keys are present.
// 2. Connects to JD and creates the lifecycle manager.
// 3. Registers the appropriate JobRunner on the lifecycle manager, using the provided ServiceFactory.
// 4. Starts the lifecycle manager.
func (b *Bootstrapper) Start(ctx context.Context) error {
	db, err := b.connectToDB(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}

	keyStore, csaSigner, err := b.initializeKeystore(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to initialize keystore: %w", err)
	}

	jdPublicKey, err := getJDPublicKey(b.cfg.JD.ServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get JD public key: %w", err)
	}
	jdClient := jdclient.New(csaSigner, jdPublicKey, b.cfg.JD.ServerWSRPCURL, b.lggr)

	deps, err := b.newServiceDeps(keyStore)
	if err != nil {
		return fmt.Errorf("failed to create service deps: %w", err)
	}

	jobRunner := &runner{
		fac:  b.fac,
		deps: deps,
	}
	lifecycleManager, err := lifecycle.NewManager(lifecycle.Config{
		JDClient: jdClient,
		JobStore: jobstore.NewPostgresStore(db),
		Runner:   jobRunner,
		Logger:   logger.Named(b.lggr, "LifecycleManager"),
	})
	if err != nil {
		return fmt.Errorf("failed to create lifecycle manager: %w", err)
	}

	// Start the lifecycle manager
	if err := lifecycleManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start lifecycle manager: %w", err)
	}

	b.lifecycleManager = lifecycleManager

	// Start the info server
	infoServer := newInfoServer(b.lggr, keyStore, b.cfg.Server.ListenPort)
	if err := infoServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start info server: %w", err)
	}

	b.infoServer = infoServer

	return nil
}

func (b *Bootstrapper) Stop(ctx context.Context) error {
	if err := b.lifecycleManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop lifecycle manager: %w", err)
	}
	if err := b.infoServer.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop info server: %w", err)
	}
	return nil
}

func (b *Bootstrapper) connectToDB(ctx context.Context) (*sqlx.DB, error) {
	db, err := sqlx.ConnectContext(ctx, "postgres", b.cfg.DB.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bootstrapper database: %w", err)
	}
	// Run migrations
	if err := dbpkg.RunMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run bootstrapper database migrations: %w", err)
	}
	return db, nil
}

func (b *Bootstrapper) newServiceDeps(keyStore keystore.Keystore) (ServiceDeps, error) {
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

func (b *Bootstrapper) initializeKeystore(ctx context.Context, db *sqlx.DB) (keyStore keystore.Keystore, csaSigner crypto.Signer, err error) {
	keyStore, err = keystore.LoadKeystore(ctx, pgstore.NewStorage(db, "default"), b.cfg.Keystore.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load keystore: %w", err)
	}

	// Always ensure that the CSA key is present in the keystore.
	if err := ensureKey(
		ctx,
		b.lggr,
		keyStore,
		DefaultCSAKeyName,
		"csa",
		keystore.Ed25519,
	); err != nil {
		return nil, nil, fmt.Errorf("failed to ensure csa key: %w", err)
	}

	// Ensure that the ECDSA and EdDSA signing keys are present in the keystore.
	if err := ensureKey(
		ctx,
		b.lggr,
		keyStore,
		DefaultECDSASigningKeyName,
		"signing",
		keystore.ECDSA_S256,
	); err != nil {
		return nil, nil, fmt.Errorf("failed to ensure ecdsa signing key: %w", err)
	}

	if err := ensureKey(
		ctx,
		b.lggr,
		keyStore,
		DefaultEdDSASigningKeyName,
		"signing",
		keystore.Ed25519,
	); err != nil {
		return nil, nil, fmt.Errorf("failed to ensure eddsa signing key: %w", err)
	}

	csaSigner, err = newCSASigner(keyStore, DefaultCSAKeyName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get csa signer: %w", err)
	}

	return keyStore, csaSigner, nil
}

type Option func(*Bootstrapper)

// WithLogLevel sets the log level for the logger passed to the application.
// Default is info.
func WithLogLevel(logLevel zapcore.Level) Option {
	return func(b *Bootstrapper) {
		b.logLevel = logLevel
	}
}

// Run is a convenience function that:
// 1. Reads the bootstrapper config from the standard environment variable BOOTSTRAPPER_CONFIG_PATH.
// 2. Creates a new bootstrapper and starts it.
// 3. Waits for a shutdown signal and stops the bootstrapper on SIGINT or SIGTERM.
// 4. Returns the error from the bootstrapper.
//
// Note that Run is a blocking function that will not return until the service is shut down.
//
// It is recommended that most applications use this function to bootstrap their service unless they
// have very specific requirements not to.
func Run(name string, fac ServiceFactory, opts ...Option) error {
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
