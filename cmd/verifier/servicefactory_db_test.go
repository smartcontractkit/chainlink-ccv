package verifier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

const testDBSpec = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"

[committee_verifier_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000002"

[rmn_remote_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000003"
`

// dbCheckRegistry records, at each GetAccessor, whether the factory's database was open and which
// migrations it had applied. It then fails the lookup so Start ends with "no source readers".
type dbCheckRegistry struct {
	f         *factory
	calls     int
	dbWasOpen bool
	versions  []int64
}

func (r *dbCheckRegistry) GetAccessor(ctx context.Context, _ protocol.ChainSelector) (chainaccess.Accessor, error) {
	r.calls++
	r.f.dbMu.Lock()
	db := r.f.db
	r.f.dbMu.Unlock()
	if db != nil && db.PingContext(ctx) == nil {
		r.dbWasOpen = true
		r.versions, _ = appliedVersions(ctx, db)
	}
	return nil, errors.New("no accessor in this test")
}

// stubKeystore satisfies keystore.Keystore; Start fails before it is used in these tests.
type stubKeystore struct{ keystore.Keystore }

// setFactoryEnv points the factory at dbURL and supplies the aggregator credentials Start resolves.
func setFactoryEnv(t *testing.T, dbURL string) {
	t.Helper()
	t.Setenv(vsecrets.DatabaseURLEnvVar, dbURL)
	t.Setenv(vsecrets.CommitteeVerifierSecretsPathEnv, t.TempDir()+"/absent.toml")
	t.Setenv(commit.DefaultAggregatorAPIKeyEnvVar, "00000000-0000-0000-0000-000000000001")
	t.Setenv(commit.DefaultAggregatorSecretKeyEnvVar, strings.Repeat("ab", 32))
	t.Setenv(admin.ConfigPathEnv, t.TempDir()+"/absent-admin.toml")
}

func startFactory(t *testing.T, f *factory, reg chainaccess.Registry) error {
	t.Helper()
	return startFactoryCtx(t.Context(), t, f, reg)
}

func startFactoryCtx(ctx context.Context, t *testing.T, f *factory, reg chainaccess.Registry) error {
	t.Helper()
	return f.Start(ctx, bootstrap.JobSpec{AppConfig: testDBSpec}, bootstrap.ServiceDeps{
		Logger:   logger.Test(t),
		Keystore: stubKeystore{},
		Registry: reg,
	})
}

// appliedVersions lists the goose migration versions applied to db, in order.
func appliedVersions(ctx context.Context, db sqlx.QueryerContext) ([]int64, error) {
	var versions []int64
	err := sqlx.SelectContext(ctx, db, &versions,
		"SELECT DISTINCT version_id FROM goose_db_version WHERE is_applied AND version_id > 0 ORDER BY version_id")
	return versions, err
}

// emptyDatabase creates a new, unmigrated database next to the one at dbURL and returns its URL.
func emptyDatabase(t *testing.T, dbURL string) string {
	t.Helper()
	admin, err := sqlx.Open("postgres", dbURL)
	require.NoError(t, err)
	defer func() { _ = admin.Close() }()
	name := fmt.Sprintf("empty_%d", time.Now().UnixNano())
	_, err = admin.ExecContext(t.Context(), "CREATE DATABASE "+name)
	require.NoError(t, err)
	u, err := url.Parse(dbURL)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}

// idleRegistry hands out accessors for a chain with no messages and keeps them so the test can
// close them, as bootstrap's AccessorCloserRegistry would.
type idleRegistry struct {
	mu        sync.Mutex
	accessors []*idleAccessor
}

func (r *idleRegistry) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := &idleAccessor{}
	r.accessors = append(r.accessors, a)
	return a, nil
}

func (r *idleRegistry) closeAll(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.accessors {
		require.NoError(t, a.Close())
	}
	r.accessors = nil
}

type idleAccessor struct{ chainaccess.Accessor }

func (*idleAccessor) SourceReader() (chainaccess.SourceReader, error) { return idleSourceReader{}, nil }
func (*idleAccessor) Close() error                                    { return nil }

// idleSourceReader is a chain at a fixed height with no CCIP messages and no curses.
type idleSourceReader struct{}

func header(n uint64) *protocol.BlockHeader {
	return &protocol.BlockHeader{Number: n, Hash: protocol.Bytes32{byte(n)}, ParentHash: protocol.Bytes32{byte(n - 1)}}
}

func (idleSourceReader) FetchMessageSentEvents(context.Context, uint64, uint64) ([]protocol.MessageSentEvent, error) {
	return nil, nil
}

func (idleSourceReader) GetBlocksHeaders(_ context.Context, nums []uint64) (map[uint64]protocol.BlockHeader, error) {
	out := make(map[uint64]protocol.BlockHeader, len(nums))
	for _, n := range nums {
		out[n] = *header(n)
	}
	return out, nil
}

func (idleSourceReader) LatestAndFinalizedBlock(context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
	return header(100), header(90), nil
}

func (idleSourceReader) LatestSafeBlock(context.Context) (*protocol.BlockHeader, error) {
	return nil, nil
}

func (idleSourceReader) GetRMNCursedSubjects(context.Context) ([]protocol.Bytes16, error) {
	return nil, nil
}

// startServing runs a Start that succeeds: a real signing key, an idle chain and an HTTP port.
func startServing(t *testing.T, f *factory, reg chainaccess.Registry, port int) error {
	t.Helper()
	return startServingWith(t, f, reg, port)
}

// startServingWith is startServing with the given feature flags.
func startServingWith(t *testing.T, f *factory, reg chainaccess.Registry, port int) error {
	t.Helper()
	ks, err := keystore.LoadKeystore(t.Context(), keystore.NewMemoryStorage(), "test",
		keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)
	_, err = ks.CreateKeys(t.Context(), keystore.CreateKeysRequest{Keys: []keystore.CreateKeyRequest{
		{KeyName: commit.DefaultECDSASigningKeyName, KeyType: keystore.ECDSA_S256},
	}})
	require.NoError(t, err)
	// Top-level TOML keys must precede the spec's tables.
	spec := fmt.Sprintf("signer_address = %q\nhttp_listen_port = %d\n", commit.AutoSignerAddress, port) + testDBSpec
	return f.Start(t.Context(), bootstrap.JobSpec{AppConfig: spec}, bootstrap.ServiceDeps{
		Logger:   logger.Test(t),
		Keystore: ks,
		Registry: reg,
	})
}

// release runs the teardown bootstrap performs: factory Stop, then accessors, then the hook.
func release(t *testing.T, f *factory, reg *idleRegistry) {
	t.Helper()
	require.NoError(t, f.Stop(t.Context()))
	reg.closeAll(t)
	require.NoError(t, f.AfterAccessorsClosed(t.Context()))
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func serving(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// serverConnections counts other backends on the test database, from an independent connection.
func serverConnections(t *testing.T, dbURL string) int {
	t.Helper()
	observer, err := sqlx.Open("postgres", dbURL)
	require.NoError(t, err)
	observer.SetMaxOpenConns(1)
	defer func() { _ = observer.Close() }()
	var n int
	require.NoError(t, observer.GetContext(t.Context(),
		&n, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()"))
	return n
}

// With the LogPoller off, Start applies the same migrations as before, now ahead of the first
// GetAccessor. Story 1.5 extends this for the flag-on path.
func TestFactoryStart_FlagOff_ConnectsAndMigratesDBBeforeFirstGetAccessor(t *testing.T) {
	reference, dbURL := testutil.NewTestDBWithURL(t)
	want, err := appliedVersions(t.Context(), reference)
	require.NoError(t, err)
	require.Contains(t, want, int64(9), "reference schema must include the verifier migrations")

	setFactoryEnv(t, emptyDatabase(t, dbURL))
	f := &factory{}
	reg := &dbCheckRegistry{f: f}

	require.ErrorContains(t, startFactory(t, f, reg), "no source readers configured")
	require.Equal(t, 1, reg.calls)
	require.True(t, reg.dbWasOpen, "database must be connected before the first GetAccessor")
	require.Equal(t, want, reg.versions, "every migration must be applied before the first GetAccessor")

	require.NoError(t, f.Stop(t.Context()))
	require.NoError(t, f.AfterAccessorsClosed(t.Context()))
}

// The subtests share one Postgres container and run serially (they set environment variables).
// Each compares server-side connections against a baseline taken before it starts.
func TestFactoryDatabaseOwnership(t *testing.T) {
	_, dbURL := testutil.NewTestDBWithURL(t)
	settled := func(t *testing.T, baseline int, msg string) {
		t.Helper()
		require.Eventually(t, func() bool { return serverConnections(t, dbURL) <= baseline },
			5*time.Second, 50*time.Millisecond, msg)
	}

	t.Run("Stop leaves the handle and the hook closes it exactly once", func(t *testing.T) {
		setFactoryEnv(t, dbURL)
		baseline := serverConnections(t, dbURL)
		f := &factory{}
		require.NoError(t, f.AfterAccessorsClosed(t.Context()), "no database configured is a no-op")
		require.ErrorContains(t, startFactory(t, f, &dbCheckRegistry{f: f}), "no source readers")
		require.Greater(t, serverConnections(t, dbURL), baseline)

		require.NoError(t, f.Stop(t.Context()))
		f.dbMu.Lock()
		db := f.db
		f.dbMu.Unlock()
		require.NotNil(t, db, "Stop must leave the handle for AfterAccessorsClosed")
		require.NoError(t, db.PingContext(t.Context()), "database must still be usable after Stop")

		require.NoError(t, f.AfterAccessorsClosed(t.Context()))
		require.Error(t, db.PingContext(t.Context()), "hook must close the database")
		require.NoError(t, f.AfterAccessorsClosed(t.Context()), "second call is a no-op")
		settled(t, baseline, "hook must release every server-side connection")
	})

	t.Run("a started job releases the database and HTTP port on teardown", func(t *testing.T) {
		setFactoryEnv(t, dbURL)
		baseline := serverConnections(t, dbURL)
		f, reg, port := &factory{}, &idleRegistry{}, freePort(t)

		require.NoError(t, startServing(t, f, reg, port))
		require.Eventually(t, func() bool { return serving(port) }, 5*time.Second, 20*time.Millisecond, "HTTP server must be listening")
		require.Greater(t, serverConnections(t, dbURL), baseline)

		release(t, f, reg)
		require.False(t, serving(port), "HTTP server must be stopped")
		settled(t, baseline, "teardown must release every server-side connection")
	})

	t.Run("restarts do not accumulate connections", func(t *testing.T) {
		setFactoryEnv(t, dbURL)
		baseline := serverConnections(t, dbURL)
		f, reg, port := &factory{}, &idleRegistry{}, freePort(t)

		for i := range 5 {
			require.NoError(t, startServing(t, f, reg, port), "start %d", i)
			release(t, f, reg)
		}
		settled(t, baseline, "connections must not accumulate across restarts")
	})

	t.Run("a Start that fails after its services run is fully released", func(t *testing.T) {
		setFactoryEnv(t, dbURL)
		// A present but invalid console config fails Start after the coordinator and HTTP server run.
		badAdmin := filepath.Join(t.TempDir(), "admin.toml")
		require.NoError(t, os.WriteFile(badAdmin, []byte("not = [valid"), 0o600))
		t.Setenv(admin.ConfigPathEnv, badAdmin)
		baseline := serverConnections(t, dbURL)
		f, reg, port := &factory{}, &idleRegistry{}, freePort(t)

		require.ErrorContains(t, startServing(t, f, reg, port), "failed to start admin console")
		require.Eventually(t, func() bool { return serving(port) }, 5*time.Second, 20*time.Millisecond, "services were running when Start failed")

		release(t, f, reg)
		require.False(t, serving(port), "HTTP server must be stopped")
		settled(t, baseline, "teardown must release every server-side connection")
	})

	t.Run("Start closes a handle the hook never released", func(t *testing.T) {
		setFactoryEnv(t, dbURL)
		baseline := serverConnections(t, dbURL)
		f := &factory{}
		require.ErrorContains(t, startFactory(t, f, &dbCheckRegistry{f: f}), "no source readers")
		f.dbMu.Lock()
		leftover := f.db
		f.dbMu.Unlock()

		require.ErrorContains(t, startFactory(t, f, &dbCheckRegistry{f: f}), "no source readers")
		require.Error(t, leftover.PingContext(t.Context()), "previous handle must be closed")

		require.NoError(t, f.AfterAccessorsClosed(t.Context()))
		settled(t, baseline, "only the test's own connections may remain")
	})

	t.Run("an unreachable database fails startup before any accessor is requested", func(t *testing.T) {
		setFactoryEnv(t, "postgres://nobody:nopass@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
		f := &factory{}
		reg := &dbCheckRegistry{f: f}

		// The connect retries are bounded by the startup ctx, so a short deadline keeps this fast.
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		require.ErrorContains(t, startFactoryCtx(ctx, t, f, reg), "failed to connect to Postgres DB")
		require.Zero(t, reg.calls)
	})
}
