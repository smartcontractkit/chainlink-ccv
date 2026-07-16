package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// setupBootstrapTestDB starts a postgres container and returns the connection URL
// and a cleanup function. The bootstrap migrations are run by Bootstrapper.connectToDB
// when the URL is used; this helper only provides the database.
func setupBootstrapTestDB(t *testing.T) (dbURL string, cleanup func()) {
	ctx := context.Background()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("bootstrap_test_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	dbURL, err = postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	cleanup = func() {
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}
	return dbURL, cleanup
}

func TestBootstrapper_connectToDB(t *testing.T) {
	dbURL, cleanup := setupBootstrapTestDB(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbConn, err := connectToDB(ctx, dbURL)
	require.NoError(t, err)
	require.NotNil(t, dbConn)
	defer dbConn.Close()

	// Verify migrations ran: bootstrap/db creates job_store and encrypted_keystore
	var count int
	err = dbConn.GetContext(ctx, &count, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'job_store'")
	require.NoError(t, err)
	require.Equal(t, 1, count, "job_store table should exist after migrations")

	err = dbConn.GetContext(ctx, &count, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'encrypted_keystore'")
	require.NoError(t, err)
	require.Equal(t, 1, count, "encrypted_keystore table should exist after migrations")
}

func TestBootstrapper_connectToDB_InvalidURL(t *testing.T) {
	_, err := connectToDB(t.Context(), "postgres://invalid-host:5432/nonexistent?sslmode=disable")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to connect to bootstrapper database")
}

// Test that bootstrap db.RunMigrations works against the test container
// (ensures bootstrap/db/migrations are compatible with postgres).
func TestBootstrapDB_RunMigrations(t *testing.T) {
	dbURL, cleanup := setupBootstrapTestDB(t)
	defer cleanup()

	ctx := context.Background()
	dbConn, err := sqlx.ConnectContext(ctx, "postgres", dbURL)
	require.NoError(t, err)
	defer dbConn.Close()

	err = db.RunMigrations(dbConn)
	require.NoError(t, err)

	var count int
	err = dbConn.GetContext(ctx, &count, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('job_store', 'encrypted_keystore')")
	require.NoError(t, err)
	require.Equal(t, 2, count, "both bootstrap tables should exist")
}

// dummyAppConfig is a test-only config struct used to verify TOML parsing.
type dummyAppConfig struct {
	Name  string `toml:"name"`
	Count int    `toml:"count"`
}

// spyServiceFactoryDummy implements ServiceFactory[dummyAppConfig] for TOML parsing tests.
type spyServiceFactoryDummy struct {
	startFn func(context.Context, dummyAppConfig, ServiceDeps) error
	stopFn  func(context.Context) error
}

func (s *spyServiceFactoryDummy) Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error {
	var appConfig dummyAppConfig
	_, err := toml.Decode(spec.AppConfig, &appConfig)
	if err != nil {
		return err
	}
	if s.startFn != nil {
		return s.startFn(ctx, appConfig, deps)
	}
	return nil
}

func (s *spyServiceFactoryDummy) Stop(ctx context.Context) error {
	if s.stopFn != nil {
		return s.stopFn(ctx)
	}
	return nil
}

func (s *spyServiceFactoryDummy) MetricViews() []sdkmetric.View {
	return nil
}

var _ ServiceFactory = (*spyServiceFactoryDummy)(nil)

// --- WithKey / NewBootstrapper key tests ---

func TestNewBootstrapper_CSAAutoInjected(t *testing.T) {
	t.Parallel()

	// A local-mode bootstrap config avoids hitting JD config at construction.
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML("/nonexistent/app.toml", ""))
	b, err := NewBootstrapper("test", &mockServiceFactory{},
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)

	// No WithKey options → only the default CSA key is auto-injected (JD auth needs it). There is no
	// longer a default signing-key set; apps declare every signing key explicitly via WithKey.
	require.Len(t, b.keys, 1)
	require.Equal(t, DefaultCSAKeyName, b.keys[0].name)
	require.Equal(t, "csa", b.keys[0].purpose)
}

func TestNewBootstrapper_WithKey_Explicit(t *testing.T) {
	t.Parallel()

	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML("/nonexistent/app.toml", ""))
	b, err := NewBootstrapper("test", &mockServiceFactory{},
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
		WithKey("my_csa", "csa", keystore.Ed25519),
		WithKey("my_signing", "signing", keystore.ECDSA_S256),
	)
	require.NoError(t, err)

	// An explicit CSA WithKey suppresses the CSA auto-injection, and declaration order is preserved.
	require.Len(t, b.keys, 2)
	require.Equal(t, "my_csa", b.keys[0].name)
	require.Equal(t, "my_signing", b.keys[1].name)
}

// --- runner tests ---

func TestRunner(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	deps := ServiceDeps{}

	t.Run("parses TOML into AppConfig", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactoryDummy{
			startFn: func(_ context.Context, cfg dummyAppConfig, _ ServiceDeps) error {
				require.Equal(t, "test-name", cfg.Name)
				require.Equal(t, 42, cfg.Count)
				return nil
			},
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps}

		cfg := `name = "test-name"
count = 42`
		spec, err := toml.Marshal(JobSpec{AppConfig: cfg})
		require.NoError(t, err)
		require.NoError(t, r.StartJob(ctx, string(spec)))
	})

	t.Run("delegates start", func(t *testing.T) {
		t.Parallel()
		var started bool
		fac := &spyServiceFactory{
			startFn: func(_ context.Context, _ any, _ ServiceDeps) error {
				started = true
				return nil
			},
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps}

		// runner parses spec as TOML into AppConfig, then calls fac.Start(ctx, appConfig, deps)
		// use empty TOML so parseTomlStrict[any] succeeds (no undecoded fields)
		require.NoError(t, r.StartJob(ctx, ""))
		require.True(t, started)
	})

	t.Run("delegates stop", func(t *testing.T) {
		t.Parallel()
		var stopped bool
		fac := &spyServiceFactory{
			stopFn: func(context.Context) error {
				stopped = true
				return nil
			},
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps}

		require.NoError(t, r.StopJob(ctx))
		require.True(t, stopped)
	})

	t.Run("propagates start error", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactory{
			startFn: func(context.Context, any, ServiceDeps) error {
				return errors.New("boom")
			},
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps}
		require.EqualError(t, r.StartJob(ctx, ""), "boom")
	})

	t.Run("propagates stop error", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("stop failed")
		fac := &spyServiceFactory{
			stopFn: func(context.Context) error { return wantErr },
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps}
		got := r.StopJob(ctx)
		require.ErrorIs(t, got, wantErr)
	})

	t.Run("StopJob closes accessors after factory.Stop", func(t *testing.T) {
		t.Parallel()
		var calls []string
		acc := mocks.NewMockAccessor(t)
		acc.EXPECT().Close().Run(func() {
			calls = append(calls, "accessor.Close")
		}).Return(nil).Once()

		inner := mocks.NewMockAccessorFactory(t)
		inner.EXPECT().GetAccessor(mock.Anything, mock.Anything).Return(acc, nil).Once()
		accessors := NewAccessorCloserRegistry(logger.Test(t), inner)
		_, err := accessors.GetAccessor(ctx, protocol.ChainSelector(1))
		require.NoError(t, err)

		fac := &spyServiceFactory{
			stopFn: func(context.Context) error {
				calls = append(calls, "factory.Stop")
				return nil
			},
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps, accCloser: accessors}

		require.NoError(t, r.StopJob(ctx))
		require.Equal(t, []string{"factory.Stop", "accessor.Close"}, calls,
			"factory.Stop must complete before accessor.Close")
	})

	t.Run("StartJob partial failure closes accessors", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("start failed")
		acc := mocks.NewMockAccessor(t)
		acc.EXPECT().Close().Return(nil).Once()
		fac := &spyServiceFactory{
			startFn: func(_ context.Context, _ any, d ServiceDeps) error {
				// Simulate a factory that obtains an accessor then fails.
				inner := d.Registry.(*AccessorCloserRegistry)
				inner.mu.Lock()
				inner.accessors = append(inner.accessors, acc)
				inner.mu.Unlock()
				return wantErr
			},
		}
		r := &runner{lggr: logger.Test(t), fac: fac, deps: deps}
		require.ErrorIs(t, r.StartJob(ctx, ""), wantErr)
	})
}

func TestBootstrapper_Stop_LocalKeystoreless_ClosesAccessors(t *testing.T) {
	t.Parallel()
	acc := mocks.NewMockAccessor(t)
	acc.EXPECT().Close().Return(nil).Once()
	fac := &spyServiceFactory{
		startFn: func(_ context.Context, _ any, d ServiceDeps) error {
			// Simulate factory obtaining an accessor during Start.
			accessors := d.Registry.(*AccessorCloserRegistry)
			accessors.mu.Lock()
			accessors.accessors = append(accessors.accessors, acc)
			accessors.mu.Unlock()
			return nil
		},
	}
	// Local mode with no [db]/[keystore] bootstrap config → keystore-less start (like the token verifier).
	appPath := writeAppConfigFile(t, "")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, ""))
	b, err := NewBootstrapper("t", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)
	require.NoError(t, b.Start(t.Context()))
	require.NotNil(t, b.accCloser)

	require.NoError(t, b.Stop(t.Context()))
	require.Nil(t, b.accCloser, "accCloser must be cleared after Stop")
}

// --- test helpers ---

type mockServiceFactory struct{}

func (m *mockServiceFactory) Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error {
	return nil
}

func (m *mockServiceFactory) Stop(ctx context.Context) error {
	return nil
}

func (s *mockServiceFactory) MetricViews() []sdkmetric.View {
	return nil
}

var _ ServiceFactory = (*mockServiceFactory)(nil)

type spyServiceFactory struct {
	validateFn func(JobSpec) error
	startFn    func(context.Context, any, ServiceDeps) error
	stopFn     func(context.Context) error
}

func (s *spyServiceFactory) Validate(spec JobSpec) error {
	if s.validateFn != nil {
		return s.validateFn(spec)
	}
	return nil
}

func (s *spyServiceFactory) Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error {
	if s.startFn != nil {
		return s.startFn(ctx, spec, deps)
	}
	return nil
}

func (s *spyServiceFactory) Stop(ctx context.Context) error {
	if s.stopFn != nil {
		return s.stopFn(ctx)
	}
	return nil
}

func (s *spyServiceFactory) MetricViews() []sdkmetric.View {
	return nil
}

func TestBuildUpdateNodeRequest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("returns nil when no signing keys", func(t *testing.T) {
		t.Parallel()
		ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), "test", keystore.WithScryptParams(keystore.FastScryptParams))
		require.NoError(t, err)
		req, err := buildUpdateNodeRequest(ctx, ks, nil, []ChainRegistration{{Type: "EVM", ID: "1"}})
		require.NoError(t, err)
		require.Nil(t, req)
	})

	t.Run("returns nil when no chains", func(t *testing.T) {
		t.Parallel()
		ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), "test", keystore.WithScryptParams(keystore.FastScryptParams))
		require.NoError(t, err)
		req, err := buildUpdateNodeRequest(ctx, ks, []string{"signing-key"}, nil)
		require.NoError(t, err)
		require.Nil(t, req)
	})

	t.Run("builds request with EVM signing address", func(t *testing.T) {
		t.Parallel()
		ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), "test", keystore.WithScryptParams(keystore.FastScryptParams))
		require.NoError(t, err)
		resp, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "signing-key", KeyType: keystore.ECDSA_S256}},
		})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)

		chains := []ChainRegistration{{Type: "EVM", ID: "1"}, {Type: "EVM", ID: "137"}}
		req, err := buildUpdateNodeRequest(ctx, ks, []string{"signing-key"}, chains)
		require.NoError(t, err)
		require.NotNil(t, req)
		require.Len(t, req.ChainConfigs, 2)

		for i, cc := range req.ChainConfigs {
			require.NotNil(t, cc.Ocr2Config)
			require.NotNil(t, cc.Ocr2Config.OcrKeyBundle)
			require.True(t, cc.Ocr2Config.Enabled)
			require.Equal(t, chains[i].ID, cc.Chain.Id)
			require.NotEmpty(t, cc.Ocr2Config.OcrKeyBundle.OnchainSigningAddress)
			// EVM addresses are 42 chars (0x + 40 hex)
			require.Len(t, cc.Ocr2Config.OcrKeyBundle.OnchainSigningAddress, 42)
			require.NotEmpty(t, cc.Ocr2Config.OcrKeyBundle.OnchainSigningPubKey)
		}

		// Both chains must have the same address (same signing key)
		addr0 := req.ChainConfigs[0].Ocr2Config.OcrKeyBundle.OnchainSigningAddress
		addr1 := req.ChainConfigs[1].Ocr2Config.OcrKeyBundle.OnchainSigningAddress
		require.Equal(t, addr0, addr1)

		// The raw public key is identical across chains too: it's the same key, just
		// rendered per-family in OnchainSigningAddress.
		pubKey0 := req.ChainConfigs[0].Ocr2Config.OcrKeyBundle.OnchainSigningPubKey
		pubKey1 := req.ChainConfigs[1].Ocr2Config.OcrKeyBundle.OnchainSigningPubKey
		require.Equal(t, pubKey0, pubKey1)
	})

	t.Run("unsupported chain type returns error", func(t *testing.T) {
		t.Parallel()
		ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), "test", keystore.WithScryptParams(keystore.FastScryptParams))
		require.NoError(t, err)
		_, err = ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "signing-key", KeyType: keystore.ECDSA_S256}},
		})
		require.NoError(t, err)

		// STARKNET has no signing address derivation implemented yet.
		_, err = buildUpdateNodeRequest(ctx, ks, []string{"signing-key"}, []ChainRegistration{{Type: "STARKNET", ID: "mainnet"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}

// --- mode resolution tests ---

// writeBootstrapConfigFiles writes contents to a bootstrap config.toml under a temp dir and returns
// its path plus a (deliberately nonexistent) secrets path, so the optional secrets overlay is
// skipped regardless of what exists on the host. Parallel-safe (no env vars).
func writeBootstrapConfigFiles(t *testing.T, contents string) (cfgPath, secretsPath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(contents), 0o600))
	return cfgPath, filepath.Join(dir, "no-secrets.toml")
}

// writeAppConfigFile writes an app-config TOML under a temp dir and returns its path.
func writeAppConfigFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

// localBootstrapTOML builds a local-mode bootstrap config: app_config_mode + local_app_config_path,
// plus [db]/[keystore] when dbURL is non-empty (so the keystore initializes).
func localBootstrapTOML(appConfigPath, dbURL string) string {
	s := "app_config_mode = \"" + string(AppConfigModeLocal) + "\"\n" +
		"local_app_config_path = \"" + appConfigPath + "\"\n"
	if dbURL != "" {
		s += "[db]\nurl = \"" + dbURL + "\"\n[keystore]\npassword = \"testpassword\"\n"
	}
	return s
}

func TestNewBootstrapper_ModeResolution(t *testing.T) {
	t.Parallel()

	t.Run("app_config_mode=local_app_config resolves to local mode", func(t *testing.T) {
		t.Parallel()
		// A non-connectable DB URL is fine: NewBootstrapper only validates presence; the connection
		// happens in Start.
		cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML("/etc/myapp/app.toml", "postgres://localhost:5432/db"))
		b, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.NoError(t, err)
		require.Equal(t, AppConfigModeLocal, b.mode)
		require.Equal(t, "/etc/myapp/app.toml", b.localConfigPath)
	})

	t.Run("omitted app_config_mode defaults to JD", func(t *testing.T) {
		t.Parallel()
		// A config with no app_config_mode and no [jd] resolves to JD and fails JD validation — proof
		// that the default is JD (a local default would have passed, since local ignores [jd]).
		cfgPath, secretsPath := writeBootstrapConfigFiles(t, "[db]\nurl = \"postgres://localhost:5432/db\"\n[keystore]\npassword = \"x\"\n")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate 'jd' section")
	})

	t.Run("local mode requires local_app_config_path", func(t *testing.T) {
		t.Parallel()
		cfgPath, secretsPath := writeBootstrapConfigFiles(t, "app_config_mode = \"local_app_config\"\n")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "local_app_config_path")
	})

	t.Run("invalid app_config_mode errors", func(t *testing.T) {
		t.Parallel()
		cfgPath, secretsPath := writeBootstrapConfigFiles(t, "app_config_mode = \"bogus\"\n")
		_, err := NewBootstrapper("t", &mockServiceFactory{},
			withBootstrapperConfigPath(cfgPath),
			withBootstrapperSecretsPath(secretsPath),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "app_config_mode")
	})
}

// TestBootstrapper_LocalMode_StartStop drives the full local-mode lifecycle against a real Postgres
// keystore: Start reads the local app-config file and invokes the factory with a non-nil keystore,
// and Stop tears it down.
func TestBootstrapper_LocalMode_StartStop(t *testing.T) {
	dbURL, cleanup := setupBootstrapTestDB(t)
	defer cleanup()

	appPath := writeAppConfigFile(t, "name = \"hello\"\ncount = 7\n")
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, localBootstrapTOML(appPath, dbURL))

	var (
		started     bool
		stopped     bool
		gotKeystore keystore.Keystore
		gotCfg      dummyAppConfig
	)
	fac := &spyServiceFactoryDummy{
		startFn: func(_ context.Context, cfg dummyAppConfig, deps ServiceDeps) error {
			started = true
			gotKeystore = deps.Keystore
			gotCfg = cfg
			return nil
		},
		stopFn: func(context.Context) error { stopped = true; return nil },
	}

	b, err := NewBootstrapper("local-test", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)
	require.Equal(t, AppConfigModeLocal, b.mode)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, b.Start(ctx))
	require.True(t, started, "factory Start must be called in local mode")
	require.NotNil(t, gotKeystore, "local mode with [db]+[keystore] must provide a keystore to the factory")
	require.Equal(t, "hello", gotCfg.Name)
	require.Equal(t, 7, gotCfg.Count)
	require.NotNil(t, b.accCloser)

	require.NoError(t, b.Stop(ctx))
	require.True(t, stopped, "factory Stop must be called on Stop")
	require.Nil(t, b.accCloser, "accCloser must be cleared after Stop")
}

func TestLocalConfigFileReady(t *testing.T) {
	t.Parallel()

	t.Run("absent file is not ready", func(t *testing.T) {
		t.Parallel()
		require.False(t, localConfigFileReady(filepath.Join(t.TempDir(), "missing.toml")))
	})

	t.Run("empty file is not ready", func(t *testing.T) {
		t.Parallel()
		require.False(t, localConfigFileReady(writeAppConfigFile(t, "")))
	})

	t.Run("directory is not ready", func(t *testing.T) {
		t.Parallel()
		require.False(t, localConfigFileReady(t.TempDir()))
	})

	t.Run("non-empty file is ready", func(t *testing.T) {
		t.Parallel()
		require.True(t, localConfigFileReady(writeAppConfigFile(t, "name = \"x\"\n")))
	})
}

// freeTCPPort returns a currently-free localhost TCP port. A small race window exists between close
// and reuse, acceptable for a test.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// TestBootstrapper_LocalMode_WaitsForConfig exercises the wait-for-config path: local mode starts with
// the app-config file absent, so Start returns immediately with the keystore + info server up and the
// factory not yet started. Once the file is written, the background watcher starts the factory.
func TestBootstrapper_LocalMode_WaitsForConfig(t *testing.T) {
	dbURL, cleanup := setupBootstrapTestDB(t)
	defer cleanup()

	// Point local_app_config_path at a file that does not exist yet.
	appPath := filepath.Join(t.TempDir(), "app.toml")
	port := freeTCPPort(t)
	cfg := fmt.Sprintf(
		"app_config_mode = %q\nlocal_app_config_path = %q\n[server]\nlisten_port = %d\n[db]\nurl = %q\n[keystore]\npassword = \"testpassword\"\n",
		AppConfigModeLocal, appPath, port, dbURL,
	)
	cfgPath, secretsPath := writeBootstrapConfigFiles(t, cfg)

	var started atomic.Bool
	var gotKeystore atomic.Bool
	fac := &spyServiceFactoryDummy{
		startFn: func(_ context.Context, _ dummyAppConfig, deps ServiceDeps) error {
			gotKeystore.Store(deps.Keystore != nil)
			started.Store(true)
			return nil
		},
	}

	b, err := NewBootstrapper("wait-test", fac,
		withBootstrapperConfigPath(cfgPath),
		withBootstrapperSecretsPath(secretsPath),
	)
	require.NoError(t, err)
	require.Equal(t, AppConfigModeLocal, b.mode)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Start returns immediately without the factory having started (config file is absent).
	require.NoError(t, b.Start(ctx))
	require.False(t, started.Load(), "factory must not start until the app config file appears")
	require.NotNil(t, b.infoServer, "info server must be up while waiting for the app config")

	// Deliver the config; the watcher (poll interval 2s) should start the factory shortly after.
	require.NoError(t, os.WriteFile(appPath, []byte("name = \"hello\"\ncount = 7\n"), 0o600))
	require.Eventually(t, started.Load, 30*time.Second, 500*time.Millisecond,
		"factory must start once the app config file appears")
	require.True(t, gotKeystore.Load(), "local mode with [db]+[keystore] must provide a keystore to the factory")

	require.NoError(t, b.Stop(ctx))
}

func TestChainTypeFromString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		wantErr  bool
		wantType string // proto enum name suffix, e.g. "EVM"
	}{
		{"EVM", false, "CHAIN_TYPE_EVM"},
		{"evm", false, "CHAIN_TYPE_EVM"},
		{"Evm", false, "CHAIN_TYPE_EVM"},
		{"SOLANA", false, "CHAIN_TYPE_SOLANA"},
		{"solana", false, "CHAIN_TYPE_SOLANA"},
		{"APTOS", false, "CHAIN_TYPE_APTOS"},
		{"STELLAR", false, "CHAIN_TYPE_STELLAR"},
		{"stellar", false, "CHAIN_TYPE_STELLAR"},
		{"CANTON", false, "CHAIN_TYPE_CANTON"},
		{"canton", false, "CHAIN_TYPE_CANTON"},
		{"STARKNET", false, "CHAIN_TYPE_STARKNET"},
		{"SUI", false, "CHAIN_TYPE_SUI"},
		{"BITCOIN", true, ""},
		{"", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got, err := chainTypeFromString(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantType, got.String())
		})
	}
}
