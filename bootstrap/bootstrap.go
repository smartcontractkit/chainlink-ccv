package bootstrap

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/grafana/pyroscope-go"
	"github.com/jmoiron/sqlx"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	dbpkg "github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	jdclient "github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	jobstore "github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/logging"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	ConfigPathEnv     = "BOOTSTRAPPER_CONFIG_PATH"
	DefaultConfigPath = "/etc/config.toml"

	// SecretsPathEnv names the env var pointing at the bootstrap secrets file, which carries the
	// credential-bearing [db] and [keystore] sections. The default is namespaced
	// under /etc/bootstrap/ to avoid the /etc/config.toml collision that DefaultConfigPath suffers.
	SecretsPathEnv     = "BOOTSTRAPPER_SECRETS_PATH"
	DefaultSecretsPath = "/etc/bootstrap/secrets.toml" //nolint:gosec // G101: this is a file path, not a credential

	defaultStartupTimeout  = 10 * time.Second
	defaultShutdownTimeout = 10 * time.Second

	// localConfigPollInterval is how often the local-mode watcher checks for a not-yet-present app
	// config file (see startLocal). There is no wait timeout: in a live deployment the operator may
	// provision the config an arbitrary amount of time after the node starts, so the watcher polls until
	// the file appears or the process is stopped.
	localConfigPollInterval = 2 * time.Second
)

// AppConfigMode is how the bootstrapper loads application config. It is operator-provided via the
// top-level app_config_mode key in the bootstrap config.toml (see NonSecretConfig)
// so switching a service between JD and local is a config change, not an image rebuild. It drives
// both config validation (see Config.validate) and startup routing (see Start).
type AppConfigMode string

const (
	// AppConfigModeJD loads the app config from a Job Distributor and runs the full job lifecycle.
	// This is the default when app_config_mode is unset.
	AppConfigModeJD AppConfigMode = "jd_app_config"
	// AppConfigModeLocal reads the app config from a local file (local_app_config_path) with no JD.
	// A [db]+[keystore] bootstrap config is optional and, when present, initializes a Postgres-backed
	// keystore so the service can sign; a service that needs no keystore (i.e. the token verifier) omits it.
	AppConfigModeLocal AppConfigMode = "local_app_config"
)

// ServiceDeps are the dependencies passed to the services started by the bootstrapper.
type ServiceDeps struct {
	// Logger is a logger that can be used by the service.
	Logger logger.Logger

	// Keystore is an initialized keystore that can be used by the service.
	Keystore keystore.Keystore

	// Registry for chainaccess.Accessor objects.
	Registry chainaccess.Registry
}

// ServiceFactory is an interface implemented by the application that seeks to be bootstrapped.
type ServiceFactory interface {
	// Start starts the service with the parsed config received from JD.
	Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error
	// Stop stops the service.
	Stop(ctx context.Context) error
	// MetricViews are OpenTelemetry histogram views used when initializing Beholder.
	MetricViews() []sdkmetric.View
}

// A runner adapts a [ServiceFactory] to the [lifecycle.JobRunner] interface.
type runner struct {
	lggr      logger.Logger
	fac       ServiceFactory
	deps      ServiceDeps
	accCloser *AccessorCloserRegistry
}

var _ lifecycle.JobRunner = (*runner)(nil)

// StartJob implements [lifecycle.JobRunner].
// On Start failure, the deferred CloseAll is the only chance to release accessors.
func (r *runner) StartJob(ctx context.Context, config string) (startErr error) {
	r.lggr.Infow("starting job")

	var spec JobSpec
	if _, err := toml.Decode(config, &spec); err != nil {
		return fmt.Errorf("bootstrap: failed to parse config: %w", err)
	}

	// Initialize registry, wrapping it so the keystore is injected into any
	// Accessor that implements KeystoreSetter.
	// Registry chain: NewRegistry > KeystoreRegistry (keystore injection) > AccessorCloserRegistry (accessor cleanup tracking).
	reg, err := chainaccess.NewRegistry(r.lggr, spec.AppConfig)
	if err != nil {
		return fmt.Errorf("failed to create registry: %w", err)
	}
	r.accCloser = NewAccessorCloserRegistry(r.lggr, NewKeystoreRegistry(r.lggr, reg, r.deps.Keystore))
	r.deps.Registry = r.accCloser

	// safety net
	defer func() {
		if startErr != nil {
			if cErr := r.accCloser.CloseAll(); cErr != nil {
				r.lggr.Warnw("close accessors after failed StartJob", "error", cErr)
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
	secretsPath      string
	config           *Config
	lifecycleManager *lifecycle.Manager
	infoServer       *infoServer
	keys             []keyToInit

	// mode is the resolved app-config mode (jd or local), read from the bootstrap config in
	// NewBootstrapper. Routing in Start() switches on it.
	mode AppConfigMode

	// localConfigPath is the app config file read in local mode (config.LocalAppConfigPath).
	localConfigPath string

	// application
	fac  ServiceFactory
	name string

	// accCloser is set by startLocal; JD mode uses runner.accCloser instead.
	accCloser *AccessorCloserRegistry

	// svcCancel cancels the long-lived context that backs the local-mode config watcher and the
	// service it eventually starts. It is nil unless local mode is waiting for its app config file
	// (see startLocal); Stop calls it to unblock the watcher and stop the service.
	svcCancel context.CancelFunc
	// watcherWG tracks the local-mode config-watcher goroutine so Stop can wait for it to finish.
	watcherWG sync.WaitGroup
	// localStartErr carries a failure from the local-mode config watcher's deferred service start back
	// to Run, so a start failure after config delivery is fatal (the process exits) — matching the
	// synchronous path, where a start error propagates to main. Buffered (size 1) and non-nil only
	// while waiting for the app config file. nil in every other mode, so Run's receive never fires.
	localStartErr chan error
	// pyroscope is a saved reference to profiler to close it on stop
	pyroscope *pyroscope.Profiler
}

// NewBootstrapper creates a new [Bootstrapper] with the given config and service factory.
func NewBootstrapper(
	name string,
	fac ServiceFactory,
	opts ...Option,
) (*Bootstrapper, error) {
	b := &Bootstrapper{
		fac:  fac,
		name: name,
	}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// JD mode always authenticates to the node with a CSA key; inject the default if the caller did
	// not declare one. Local mode reuses the same injection for Beholder auth when it has a keystore.
	if !hasCSAKey(b.keys) {
		b.keys = append([]keyToInit{{DefaultCSAKeyName, "csa", keystore.Ed25519}}, b.keys...)
	}

	// The bootstrap operator config (BOOTSTRAPPER_CONFIG_PATH, default /etc/config.toml) is always
	// loaded; its top-level app_config_mode key selects the lifecycle. Non-secret config first, then
	// overlay the secrets file (if present) so it wins for any section it defines.
	b.config = &Config{}
	paths := bootstrapConfigPaths(b.configPath, b.secretsPath)
	mode, err := LoadAndValidateConfig(paths, b.config)
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap config (%v): %w", paths, err)
	}
	b.mode = mode
	if mode == AppConfigModeLocal {
		b.localConfigPath = b.config.LocalAppConfigPath
	}

	// init tmp logger
	b.lggr, err = logging.InitLogger(b.name, "", monitoring.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to init logger: %w", err)
	}

	return b, nil
}

func (b *Bootstrapper) initMonitoring(signer crypto.Signer) error {
	// do not fall back b.config to it
	mon := monitoring.Config{}
	if b.config != nil && b.config.Monitoring != nil {
		mon = *b.config.Monitoring
	}
	err := monitoring.SetupBeholder(mon.Beholder, signer, b.fac.MetricViews())
	if err != nil {
		return fmt.Errorf("failed to setup beholder: %w", err)
	}
	lggr, err := logging.InitLogger(b.name, mon.LogLevel, mon)
	if err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}
	if b.lggr != nil {
		_ = b.lggr.Sync() // stdout sync always fails on Linux/macOS, safe to ignore
		b.lggr = lggr
	}
	b.lggr = lggr
	pyroscopeProfiler, err := monitoring.SetupPyroscope(lggr, b.name, mon.Pyroscope)
	if err != nil {
		return fmt.Errorf("failed to setup pyroscope: %w", err)
	}
	b.pyroscope = pyroscopeProfiler
	lggr.Infow("Monitoring initialized", "config", mon)
	return nil
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
					OnchainSigningPubKey:  keys.RawPubKeyHex(signingKey.KeyInfo.PublicKey),
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

	err = b.initMonitoring(csaSigner)
	if err != nil {
		return fmt.Errorf("failed to initialize monitoring: %w", err)
	}

	jdPublicKey, err := keys.DecodeEd25519PublicKey(b.config.JD.ServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get JD public key: %w", err)
	}
	jdClient := jdclient.New(csaSigner, jdPublicKey, b.config.JD.ServerWSRPCURL, b.lggr)

	// Surface the operator-provided monitoring config to the service. Only the JD path populates this;
	// static-TOML mode (startWithAppConfig) loads no bootstrap config and leaves it nil.
	deps := ServiceDeps{
		Logger:   b.lggr,
		Keystore: keyStore,
	}

	jobRunner := &runner{lggr: b.lggr, fac: b.fac, deps: deps}

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

// startLocal runs the service without JD. When a [db]+[keystore] bootstrap config is provided it
// initializes a Postgres-backed keystore (and, if a [server] port is set, the info server) so signing
// services work; without one it runs keystore-less. There is no JD client, no lifecycle manager, and
// no signing-key sync to JD.
//
// The app config is read from a local file. Two delivery modes are supported, chosen by whether the
// file is present at startup:
//
//   - present: the service starts synchronously. This is the token verifier and
//     the existing local-mode callers that mount the config at container start.
//   - absent (keystore + info server only): the keystore and info server come up immediately and
//     startLocal returns, then a background watcher waits for the file to appear and starts the
//     service once it does.
func (b *Bootstrapper) startLocal(ctx context.Context) error {
	// A keystore is initialized only when both the DB URL and keystore password are configured.
	// Services that sign (committee verifier, executor) supply them; the token verifier does not.
	var keyStore keystore.Keystore
	var csaSigner crypto.Signer
	var dbURL, ksPassword string
	if b.config != nil {
		dbURL = strings.TrimSpace(b.config.DB.URL)
		ksPassword = strings.TrimSpace(b.config.Keystore.Password)
	}
	switch {
	case dbURL != "" && ksPassword != "":
		db, err := connectToDB(ctx, dbURL)
		if err != nil {
			return fmt.Errorf("failed to connect to bootstrapper database: %w", err)
		}
		keyStore, csaSigner, err = initializeKeystore(ctx, b.lggr, db, ksPassword, b.keys)
		if err != nil {
			return fmt.Errorf("failed to initialize keystore: %w", err)
		}
	case dbURL != "" || ksPassword != "":
		// Exactly one of [db]/[keystore] is set — almost certainly a misconfiguration. Warn loudly:
		// running keystore-less here would surface later as a confusing nil-keystore failure in a
		// signing service.
		b.lggr.Warnw("local mode: bootstrap config sets only one of [db].url / [keystore].password; "+
			"both are required to initialize the keystore, so the service will run keystore-less",
			"hasDBURL", dbURL != "", "hasKeystorePassword", ksPassword != "")
	}

	if err := b.initMonitoring(csaSigner); err != nil {
		return fmt.Errorf("failed to initialize monitoring: %w", err)
	}

	// The info server exposes health/key inspection. It needs a keystore and a configured port; in
	// local mode [server] is optional, so start it only when both are present. It comes up before the
	// app config is read so that key discovery works while a not-yet-present config is awaited.
	if keyStore != nil && b.config.Server.ListenPort != 0 {
		infoServer := newInfoServer(b.lggr, keyStore, b.config.Server.ListenPort)
		if err := infoServer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start info server: %w", err)
		}
		b.infoServer = infoServer
	}

	// Defer the service start until the config file is present. The watch path requires a keystore
	// and info server (its whole purpose is exposing signing keys while the config is provisioned);
	// a keystore-less service (token verifier) always takes the synchronous path, where a missing
	// file is an immediate, clear error.
	if b.infoServer != nil && !localConfigFileReady(b.localConfigPath) {
		svcCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		b.svcCancel = cancel
		b.localStartErr = make(chan error, 1)
		b.lggr.Infow("local mode: app config not present yet; serving keys and waiting for it to appear",
			"path", b.localConfigPath)
		b.watcherWG.Add(1)
		go b.watchForConfigAndStart(svcCtx, keyStore)
		return nil
	}

	return b.startLocalService(ctx, keyStore)
}

// startLocalService reads the app config file, builds the accessor registry (injecting the keystore
// when one exists), and starts the service factory. It is the shared tail of both the synchronous and
// the watch-and-start local paths.
func (b *Bootstrapper) startLocalService(ctx context.Context, keyStore keystore.Keystore) (startErr error) {
	appCfg, err := os.ReadFile(b.localConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read local app config %q: %w", b.localConfigPath, err)
	}

	reg, err := chainaccess.NewRegistry(b.lggr, string(appCfg))
	if err != nil {
		return fmt.Errorf("failed to create registry: %w", err)
	}
	// Inject the keystore into accessors only when one exists; wrapping with a nil keystore would
	// push nil into any KeystoreSetter accessor.
	inner := reg
	if keyStore != nil {
		inner = NewKeystoreRegistry(b.lggr, reg, keyStore)
	}
	b.accCloser = NewAccessorCloserRegistry(b.lggr, inner)
	// safety net for partial-Start failure since Bootstrapper.Stop is not guaranteed
	defer func() {
		if startErr != nil {
			if cErr := b.accCloser.CloseAll(); cErr != nil {
				b.lggr.Warnw("close accessors after failed startLocal", "error", cErr)
			}
			b.accCloser = nil
		}
	}()

	js := JobSpec{Name: "local", AppConfig: string(appCfg)}
	return b.fac.Start(ctx, js, ServiceDeps{Logger: b.lggr, Keystore: keyStore, Registry: b.accCloser})
}

// watchForConfigAndStart polls for the local app config file and starts the service once it appears.
// It polls indefinitely until the file appears or ctx is canceled (Stop) — there is no wait timeout,
// because in a live deployment the operator may provision the config an arbitrary amount of time after
// the node starts. A start failure is logged rather than fatal: the info server stays up, so the
// operator/devenv can see the container is running but the service never became ready (devenv confirms
// readiness via the service's own health endpoint after it delivers the config).
func (b *Bootstrapper) watchForConfigAndStart(ctx context.Context, keyStore keystore.Keystore) {
	defer b.watcherWG.Done()
	ticker := time.NewTicker(localConfigPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.lggr.Infow("local mode: stopped waiting for app config", "path", b.localConfigPath)
			return
		case <-ticker.C:
			if !localConfigFileReady(b.localConfigPath) {
				continue
			}
			b.lggr.Infow("local mode: app config appeared, starting service", "path", b.localConfigPath)
			if err := b.startLocalService(ctx, keyStore); err != nil {
				// Hand the failure to Run so the process exits, as it would on the synchronous path.
				// The error is not logged here: it is returned up to main, whose existing handling
				// surfaces it (and avoids re-logging a value flagged as sensitive by static analysis —
				// the error names config sources, not credential values).
				select {
				case b.localStartErr <- err:
				default:
				}
			}
			return
		}
	}
}

// localConfigFileReady reports whether the local app config file exists and is non-empty. The
// non-empty check guards against reading a file mid-write; devenv writes it atomically (temp + rename)
// so a size greater than zero means the full config is present.
func localConfigFileReady(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// Start routes to the mode-specific startup path resolved in [NewBootstrapper].
func (b *Bootstrapper) Start(ctx context.Context) error {
	if b.lggr == nil {
		return fmt.Errorf("bootstrapper has no logger")
	}
	if b.mode == AppConfigModeJD {
		return b.startWithJDLifecycle(ctx)
	}
	return b.startLocal(ctx)
}

// Stop shuts down all active components. The two modes own mutually exclusive sets of objects, so
// stopping every non-nil field covers both without double-stopping:
//   - JD mode: the lifecycle manager and info server are stopped; accessor cleanup is owned by
//     runner.StopJob, invoked by the lifecycle manager.
//   - Local mode: factory.Stop runs first, then accCloser.CloseAll; the info server is stopped if
//     it was started.
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
	if b.pyroscope != nil {
		err := b.pyroscope.Stop()
		if err != nil {
			return fmt.Errorf("failed to stop pyroscope: %w", err)
		}
	}
	if b.mode == AppConfigModeLocal {
		return b.stopLocal(ctx)
	}
	return nil
}

// stopLocal tears down the local-mode service: it unblocks the config watcher (if still waiting) and
// waits for it, so a service start racing with shutdown finishes or aborts before the factory is
// stopped and accessors are closed.
func (b *Bootstrapper) stopLocal(ctx context.Context) error {
	if b.svcCancel != nil {
		b.svcCancel()
	}
	b.watcherWG.Wait()

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

func hasCSAKey(keys []keyToInit) bool {
	for _, k := range keys {
		if k.purpose == "csa" {
			return true
		}
	}
	return false
}

// resolveBootstrapConfigPath returns the effective bootstrap config path: the explicitly-provided
// path takes precedence, then BOOTSTRAPPER_CONFIG_PATH, then DefaultConfigPath.
func resolveBootstrapConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv(ConfigPathEnv); env != "" {
		return env
	}
	return DefaultConfigPath
}

// resolveBootstrapSecretsPath returns the effective bootstrap secrets path — the explicitly-provided
// path, then BOOTSTRAPPER_SECRETS_PATH, then DefaultSecretsPath — but only if that path points at an
// existing file. The secrets file is optional: absence returns "" so the caller skips the overlay,
// which is what keeps a legacy monolithic config (with [db]/[keystore] inline) working.
func resolveBootstrapSecretsPath(explicit string) string {
	path := explicit
	if path == "" {
		path = os.Getenv(SecretsPathEnv)
	}
	if path == "" {
		path = DefaultSecretsPath
	}
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: path is a trusted operator-provided config path
		return ""
	}
	return path
}

// bootstrapConfigPaths returns the ordered list of files to decode in JD mode: the non-secret config
// file, followed by the secrets file only when one is present. Later files overlay earlier ones, so
// the secrets file wins for any section it defines.
func bootstrapConfigPaths(explicitConfig, explicitSecrets string) []string {
	paths := []string{resolveBootstrapConfigPath(explicitConfig)}
	if secretsPath := resolveBootstrapSecretsPath(explicitSecrets); secretsPath != "" {
		paths = append(paths, secretsPath)
	}
	return paths
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

type keyToInit struct {
	name    string
	purpose string
	keyType keystore.KeyType
}

// WithKey declares a key that the bootstrapper must ensure exists, creating it if absent. The caller
// is responsible for declaring every key it requires; there is no default signing-key set.
//
// The exception is the CSA key used for JD authentication: if no CSA-purpose key is declared, the
// default CSA key (DefaultCSAKeyName) is injected automatically.
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

// withBootstrapperConfigPath is a test-only injection seam.
// We have this so that we can run parallel tests w/out t.Setenv, which is not thread-safe.
func withBootstrapperConfigPath(path string) Option {
	return func(b *Bootstrapper) error {
		b.configPath = path
		return nil
	}
}

// withBootstrapperSecretsPath is a test-only injection seam.
// We have this so that we can run parallel tests w/out t.Setenv, which is not thread-safe.
func withBootstrapperSecretsPath(path string) Option {
	return func(b *Bootstrapper) error {
		b.secretsPath = path
		return nil
	}
}

// Run is a convenience function that loads config, creates a [Bootstrapper],
// starts it, and blocks until SIGINT or SIGTERM is received.
func Run(
	name string,
	fac ServiceFactory,
	opts ...Option,
) error {
	bootstrapper, err := NewBootstrapper(name, fac, opts...)
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

	// In local mode the app config may be delivered after startup; if the deferred service start then
	// fails, localStartErr fires and the process exits with that error (as the synchronous path does).
	// localStartErr is nil outside that path, so the receive simply never fires.
	var startErr error
	select {
	case <-sigCh:
		bootstrapper.lggr.Infow("Received shutdown signal, stopping bootstrapper...")
	case startErr = <-bootstrapper.localStartErr:
		bootstrapper.lggr.Errorw("service failed to start after app config was delivered; shutting down")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer shutdownCancel()

	if err := bootstrapper.Stop(shutdownCtx); err != nil {
		if startErr != nil {
			return fmt.Errorf("service start failed (%w); also failed to stop bootstrapper: %v", startErr, err)
		}
		return fmt.Errorf("failed to stop bootstrapper: %w", err)
	}

	return startErr
}
