package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/freeport"

	_ "github.com/lib/pq"
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

// validTestConfig returns a Config that passes validation (for use with test DB URL).
func validTestConfig(t *testing.T, dbURL string) Config {
	return Config{
		JD: JDConfig{
			ServerWSRPCURL:     "ws://localhost:8080/ws",
			ServerCSAPublicKey: validEd25519PublicKeyHex,
		},
		Keystore: KeystoreConfig{
			Password: "test-keystore-password",
		},
		DB: DBConfig{
			URL: dbURL,
		},
		Server: ServerConfig{
			ListenPort: freeport.GetOne(t),
		},
	}
}

func TestBootstrapper_connectToDB(t *testing.T) {
	dbURL, cleanup := setupBootstrapTestDB(t)
	defer cleanup()

	cfg := validTestConfig(t, dbURL)
	b, err := NewBootstrapper("test", logger.TestSugared(t), cfg, &mockServiceFactory{})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbConn, err := b.connectToDB(ctx)
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
	cfg := validTestConfig(t, "postgres://invalid-host:5432/nonexistent?sslmode=disable")
	b, err := NewBootstrapper("test", logger.TestSugared(t), cfg, &mockServiceFactory{})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = b.connectToDB(ctx)
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

func (s *spyServiceFactoryDummy) Start(ctx context.Context, appConfig dummyAppConfig, deps ServiceDeps) error {
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

var _ ServiceFactory[dummyAppConfig] = (*spyServiceFactoryDummy)(nil)

// --- runner tests ---

func TestRunner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("parses TOML into AppConfig", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactoryDummy{
			startFn: func(_ context.Context, cfg dummyAppConfig, _ ServiceDeps) error {
				require.Equal(t, "test-name", cfg.Name)
				require.Equal(t, 42, cfg.Count)
				return nil
			},
		}
		r := &runner[dummyAppConfig]{fac: fac, deps: ServiceDeps{}}

		spec := `name = "test-name"
count = 42`
		require.NoError(t, r.StartJob(ctx, spec))
	})

	t.Run("rejects TOML with undecoded fields", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactoryDummy{}
		r := &runner[dummyAppConfig]{fac: fac, deps: ServiceDeps{}}

		// extra field "unknown" is not in dummyAppConfig, so strict decode fails
		spec := `name = "x"
count = 1
unknown = true`
		err := r.StartJob(ctx, spec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse app config toml")
		require.Contains(t, err.Error(), "undecoded fields")
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
		r := &runner[any]{fac: fac, deps: ServiceDeps{}}

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
		r := &runner[any]{fac: fac, deps: ServiceDeps{}}

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
		r := &runner[any]{fac: fac, deps: ServiceDeps{}}
		require.EqualError(t, r.StartJob(ctx, ""), "boom")
	})

	t.Run("propagates stop error", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactory{
			stopFn: func(context.Context) error {
				return errors.New("stop failed")
			},
		}
		r := &runner[any]{fac: fac, deps: ServiceDeps{}}
		require.EqualError(t, r.StopJob(ctx), "stop failed")
	})
}

// --- test helpers ---

type mockServiceFactory struct{}

func (m *mockServiceFactory) Start(ctx context.Context, appConfig any, deps ServiceDeps) error {
	return nil
}

func (m *mockServiceFactory) Stop(ctx context.Context) error {
	return nil
}

var _ ServiceFactory[any] = (*mockServiceFactory)(nil)

type spyServiceFactory struct {
	startFn func(context.Context, any, ServiceDeps) error
	stopFn  func(context.Context) error
}

func (s *spyServiceFactory) Start(ctx context.Context, appConfig any, deps ServiceDeps) error {
	if s.startFn != nil {
		return s.startFn(ctx, appConfig, deps)
	}
	return nil
}

func (s *spyServiceFactory) Stop(ctx context.Context) error {
	if s.stopFn != nil {
		return s.stopFn(ctx)
	}
	return nil
}
