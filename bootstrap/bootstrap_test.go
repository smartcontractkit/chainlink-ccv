package bootstrap

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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

var _ ServiceFactory = (*spyServiceFactoryDummy)(nil)

// --- WithKey / NewBootstrapper key tests ---

func TestNewBootstrapper_WithKey_Defaults(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)

	// Create an empty temp TOML file so WithTOMLAppConfig succeeds without hitting JD config.
	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	b, err := NewBootstrapper("test", lggr, &mockServiceFactory{}, WithTOMLAppConfig(f.Name()))
	require.NoError(t, err)

	// No WithKey options → the three original defaults must be applied.
	require.Len(t, b.keys, 3)
	require.Equal(t, DefaultCSAKeyName, b.keys[0].name)
	require.Equal(t, defaultECDSASigningKeyName, b.keys[1].name)
	require.Equal(t, defaultEdDSASigningKeyName, b.keys[2].name)
}

func TestNewBootstrapper_WithKey_Explicit(t *testing.T) {
	t.Parallel()
	lggr := logger.Test(t)

	f, err := os.CreateTemp(t.TempDir(), "*.toml")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	b, err := NewBootstrapper("test", lggr, &mockServiceFactory{},
		WithTOMLAppConfig(f.Name()),
		WithKey("my_csa", "csa", keystore.Ed25519),
		WithKey("my_signing", "signing", keystore.ECDSA_S256),
	)
	require.NoError(t, err)

	// Explicit WithKey options must suppress defaults and preserve order.
	require.Len(t, b.keys, 2)
	require.Equal(t, "my_csa", b.keys[0].name)
	require.Equal(t, "my_signing", b.keys[1].name)
}

// --- runner tests ---

func TestRunner(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	deps := ServiceDeps{
		Logger: logger.Test(t),
	}

	t.Run("parses TOML into AppConfig", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactoryDummy{
			startFn: func(_ context.Context, cfg dummyAppConfig, _ ServiceDeps) error {
				require.Equal(t, "test-name", cfg.Name)
				require.Equal(t, 42, cfg.Count)
				return nil
			},
		}
		r := &runner{fac: fac, deps: deps}

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
		r := &runner{fac: fac, deps: deps}

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
		r := &runner{fac: fac, deps: deps}

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
		r := &runner{fac: fac, deps: deps}
		require.EqualError(t, r.StartJob(ctx, ""), "boom")
	})

	t.Run("propagates stop error", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactory{
			stopFn: func(context.Context) error {
				return errors.New("stop failed")
			},
		}
		r := &runner{fac: fac, deps: deps}
		require.EqualError(t, r.StopJob(ctx), "stop failed")
	})
}

// --- test helpers ---

type mockServiceFactory struct{}

func (m *mockServiceFactory) Start(ctx context.Context, spec JobSpec, deps ServiceDeps) error {
	return nil
}

func (m *mockServiceFactory) Stop(ctx context.Context) error {
	return nil
}

var _ ServiceFactory = (*mockServiceFactory)(nil)

type spyServiceFactory struct {
	startFn func(context.Context, any, ServiceDeps) error
	stopFn  func(context.Context) error
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
