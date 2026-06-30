package bootstrap

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap/zapcore"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

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
	Registry chainaccess.Registry

	// Monitoring is the operator-provided monitoring config from the bootstrap config (Config.Monitoring).
	// It is nil when the operator did not configure monitoring in the bootstrap config. Services prefer
	// this value and fall back to their own app-config monitoring field when it is nil.
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
	lggr logger.Logger

	// bootstrapper component configs
	configPath       string
	config           *Config
	lifecycleManager *lifecycle.Manager
	infoServer       *infoServer
	keys             []keyToInit

	// jdMode is true when the bootstrapper runs in JD lifecycle mode (WithJD or default).
	// false means static-TOML mode (WithTOMLAppConfig). Routing in Start() uses this flag
	// rather than checking b.config != nil, because b.config may now be set in both modes
	// (operator config is optionally loaded in static-TOML mode too).
	jdMode bool

	// application
	appCfg *string
	fac    ServiceFactory
	name   string

	// accCloser is set by startWithAppConfig; JD mode uses runner.accCloser instead.
	accCloser *AccessorCloserRegistry

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
			{DefaultCSAKeyName, "csa", keystore.Ed25519},
			{defaultECDSASigningKeyName, "signing", keystore.ECDSA_S256},
			{defaultEdDSASigningKeyName, "signing", keystore.Ed25519},
		}
	}

	// WithJD and WithTOMLAppConfig are mutually exclusive.
	if b.jdMode && b.appCfg != nil {
		return nil, fmt.Errorf("WithJD and WithTOMLAppConfig are mutually exclusive")
	}

	// If neither mode was explicitly selected, default to JD lifecycle mode.
	if !b.jdMode && b.appCfg == nil {
		b.jdMode = true
	}

	if b.jdMode {
		// JD mode requires a CSA key for node authentication. Inject the default if the caller
		// did not explicitly declare one, so callers only need to list their application keys.
		hasCSA := false
		for _, k := range b.keys {
			if k.purpose == "csa" {
				hasCSA = true
				break
			}
		}
		if !hasCSA {
			b.keys = append([]keyToInit{{DefaultCSAKeyName, "csa", keystore.Ed25519}}, b.keys...)
		}

		// Use provided config path if set by an option.
		if b.configPath == "" {
			// If no config path is provided by an option, check the environment variable.
			b.configPath = os.Getenv(ConfigPathEnv)
			if b.configPath == "" {
				// If the environment variable is not set, use the default config path.
				b.configPath = DefaultConfigPath
			}
		}

		b.config = &Config{}
		if err := LoadAndValidateConfig(b.configPath, b.config); err != nil {
			return nil, fmt.Errorf("failed to load bootstrap config (%s): %w", b.configPath, err)
		}

		// not logging config because it contains secrets.
		lggr.Infow("loaded bootstrap config")
	} else {
		// Static-TOML mode: optionally load operator config when BOOTSTRAPPER_CONFIG_PATH is
		// explicitly set. The default fallback to DefaultConfigPath is intentionally suppressed
		// here: TOKEN_VERIFIER_CONFIG_PATH and BOOTSTRAPPER_CONFIG_PATH both default to
		// /etc/config.toml, so applying the default would decode the wrong file. See issue #013.
		if path := os.Getenv(ConfigPathEnv); path != "" {
			b.config = &Config{}
			if err := LoadAndValidateConfig(path, b.config); err != nil {
				return nil, fmt.Errorf("failed to load operator config (%s): %w", path, err)
			}
			lggr.Infow("loaded operator config for static-TOML mode")
		}
	}

	return b, nil
}

// startWithAppConfig is a passthrough to the application's Start function.
func (b *Bootstrapper) startWithAppConfig(ctx context.Context) (startErr error) {
	if b.appCfg == nil {
		return fmt.Errorf("bootstrapper has no app config")
	}

	lggr, err := newLogger(b.logLevel, b.name)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	b.lggr.Infow("Calling NewRegistry with app config")
	reg, err := chainaccess.NewRegistry(b.lggr, *b.appCfg)
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
		AppConfig:     *b.appCfg,
	}

	deps := ServiceDeps{
		Logger:   lggr,
		Registry: b.accCloser,
	}
	if b.config != nil {
		deps.Monitoring = b.config.Monitoring
	}

	return b.fac.Start(ctx, js, deps)
}

// chainTypeFromString maps a config chain type string to the proto ChainType enum.
// It uses the proto-generated ChainType_value map so new enum values are supported
// automatically without any code change here.
func chainTypeFromString(s string) (pb.ChainType, error) {
	key := "CHAIN_TYPE_" + strings.ToUpper(s)
	if v, ok := pb.ChainType_value[key]; ok {
		return pb.ChainType(v), nil
	}
	return pb.ChainType_CHAIN_TYPE_UNSPECIFIED, fmt.Errorf("unknown chain type %q", s)
}

// signingAddressFromPublicKey derives the onchain signing address for the given chain type
// from a raw public key returned by the keystore.
//
// Format per family:
//   - EVM:     EIP-55 checksummed address, 0x-prefixed  (e.g. "0xAbCd…")
//   - Solana:  lowercase 20-byte Ethereum address, no 0x (e.g. "abcd…") — matches CL node prior art
//   - Aptos:   full uncompressed public key, lowercase hex, no prefix    (e.g. "04abcd…")
//   - Stellar: full uncompressed public key, lowercase hex, no prefix    (e.g. "04abcd…")
//   - Canton:  full uncompressed public key, lowercase hex, no prefix    (e.g. "04abcd…")
func signingAddressFromPublicKey(chainType pb.ChainType, pubKeyBytes []byte) (string, error) {
	switch chainType {
	case pb.ChainType_CHAIN_TYPE_EVM:
		addr, _, err := keys.EVMAddressFromPublicKey(pubKeyBytes)
		return addr, err
	case pb.ChainType_CHAIN_TYPE_SOLANA:
		return keys.SolanaAddressFromPublicKey(pubKeyBytes)
	case pb.ChainType_CHAIN_TYPE_APTOS,
		pb.ChainType_CHAIN_TYPE_STELLAR,
		pb.ChainType_CHAIN_TYPE_CANTON:
		return keys.RawPubKeyHex(pubKeyBytes), nil
	default:
		return "", fmt.Errorf("signing address derivation not implemented for chain type %v", chainType)
	}
}

// buildUpdateNodeRequest constructs the UpdateNodeRequest to send to JD on connect.
// It reads the public key for each key in signingKeyNames and builds one ChainConfig
// entry per chain in chains, with the signing address shoehorned into OCR2Config.OcrKeyBundle.
// Returns nil if there are no signing keys or no chains declared.
func buildUpdateNodeRequest(
	ctx context.Context,
	ks keystore.Keystore,
	signingKeyNames []string,
	chains []ChainRegistration,
) (*pb.UpdateNodeRequest, error) {
	if len(signingKeyNames) == 0 || len(chains) == 0 {
		return nil, nil
	}

	resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: signingKeyNames})
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keys from keystore: %w", err)
	}
	if len(resp.Keys) == 0 {
		return nil, fmt.Errorf("no signing keys found in keystore for names %v", signingKeyNames)
	}
	signingKey := resp.Keys[0]

	chainConfigs := make([]*pb.ChainConfig, 0, len(chains))
	for _, chain := range chains {
		chainType, err := chainTypeFromString(chain.Type)
		if err != nil {
			return nil, err
		}
		addr, err := signingAddressFromPublicKey(chainType, signingKey.KeyInfo.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("chain %s/%s: %w", chain.Type, chain.ID, err)
		}
		chainConfigs = append(chainConfigs, &pb.ChainConfig{
			Chain: &pb.Chain{Type: chainType, Id: chain.ID},
			Ocr2Config: &pb.OCR2Config{
				Enabled: true,
				OcrKeyBundle: &pb.OCR2Config_OCRKeyBundle{
					OnchainSigningAddress: addr,
				},
			},
		})
	}

	return &pb.UpdateNodeRequest{ChainConfigs: chainConfigs}, nil
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
	deps.Monitoring = b.config.Monitoring

	jobRunner := &runner{fac: b.fac, deps: deps}

	// b.keys is populated by WithKey options; collect names of signing keys to publish.
	var signingKeyNames []string
	for _, k := range b.keys {
		if k.keyType == keystore.ECDSA_S256 {
			signingKeyNames = append(signingKeyNames, k.name)
		}
	}
	if len(signingKeyNames) > 1 {
		return fmt.Errorf("expected at most one ECDSA_S256 signing key, got %d: %v", len(signingKeyNames), signingKeyNames)
	}

	var onConnectHook func(ctx context.Context) error
	if len(signingKeyNames) > 0 && len(b.config.Chains) > 0 {
		ks := keyStore
		chains := b.config.Chains
		names := signingKeyNames
		onConnectHook = func(ctx context.Context) error {
			req, err := buildUpdateNodeRequest(ctx, ks, names, chains)
			if err != nil {
				return fmt.Errorf("failed to build UpdateNodeRequest: %w", err)
			}
			if req == nil {
				return nil
			}
			return jdClient.UpdateNode(ctx, req)
		}
	}

	lifecycleManager, err := lifecycle.NewManager(lifecycle.Config{
		JDClient:      jdClient,
		JobStore:      jobstore.NewPostgresStore(db),
		Runner:        jobRunner,
		Logger:        logger.Named(b.lggr, "LifecycleManager"),
		OnConnectHook: onConnectHook,
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
	if b.jdMode {
		return b.startWithJDLifecycle(ctx)
	}
	return b.startWithAppConfig(ctx)
}

// Stop shuts down all active components.
//
// The two startup modes own mutually exclusive sets of objects, so stopping every
// non-nil field is sufficient to cover both without double-stopping anything:
//   - JD mode (lifecycleManager/infoServer set, appCfg nil): the lifecycle manager and info server are stopped.
//     Accessor cleanup is owned by runner.StopJob, invoked by the lifecycle manager.
//   - Static-config mode (appCfg set, lifecycleManager/infoServer nil): factory.Stop runs first, then accCloser.CloseAll
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
		return nil, fmt.Errorf("failed to run bootstrapper database migrations: %w", err)
	}
	return db, nil
}

func newLogger(logLevel zapcore.Level, name string) (logger.Logger, error) {
	lggr, err := logger.NewWith(zaplog.GetLogProfile(logLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	return logger.Sugared(logger.Named(lggr, name)), nil
}

func newServiceDeps(keyStore keystore.Keystore, logLevel zapcore.Level, name string) (ServiceDeps, error) {
	lggr, err := newLogger(logLevel, name)
	if err != nil {
		return ServiceDeps{}, err
	}
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

// WithLogLevelFromEnv sets the log level from the LOG_LEVEL environment variable,
// falling back to defaultLevel if the variable is unset or invalid.
func WithLogLevelFromEnv(defaultLevel zapcore.Level) Option {
	return func(b *Bootstrapper) error {
		b.logLevel = defaultLevel
		if lvlStr := os.Getenv("LOG_LEVEL"); lvlStr != "" {
			var lvl zapcore.Level
			if err := lvl.UnmarshalText([]byte(lvlStr)); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL '%s', defaulting to '%s'\n", lvlStr, defaultLevel)
			} else {
				b.logLevel = lvl
			}
		}
		return nil
	}
}

type keyToInit struct {
	name    string
	purpose string
	keyType keystore.KeyType
}

// WithKey declares a key that the bootstrapper must ensure exists, creating it if absent.
// When no WithKey options are provided, the bootstrapper applies a deprecated default set of
// three keys (CSA, ECDSA signing, EdDSA signing). Passing one or more WithKey options suppresses
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
// automatically provisions bootstrap.DefaultCSAKeyName unless a key with purpose "csa" is
// already declared via WithKey.
func WithJD() Option {
	return func(b *Bootstrapper) error {
		b.jdMode = true
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
