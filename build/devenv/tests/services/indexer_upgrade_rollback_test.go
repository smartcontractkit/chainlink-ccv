package services_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	idxUpgradeName   = "indexer-upgrade"
	idxUpgradePort   = 8130
	idxUpgradeDBPort = 6440
	// idxVisibilityWindow is the VerificationVisibilityWindow in seconds. A message must stay inside it during a swap.
	idxVisibilityWindow = 3600
	// idxDeadlineMargin is how much of the window must be left before a swap.
	idxDeadlineMargin = 5 * time.Minute
	idxStatusTimeout  = 2 * time.Minute
	statusProcessing  = "PROCESSING"
	statusSuccess     = "SUCCESS"
)

// TestIndexer_UpgradeRollbackInFlight runs one indexer replica against fake verifiers. A message waits for a held
// token verification while the replica is upgraded, and a second one while it is rolled back.
// Each message must then reach SUCCESS with both verifications.
func TestIndexer_UpgradeRollbackInFlight(t *testing.T) {
	fromImage, toImage := upgradeImages(t, "indexer")
	ctx := t.Context()
	fakes := newFakeVerifiers(t)
	env := newIdxUpgradeEnv(t, fromImage, fakes)

	t.Run("message in flight across the upgrade", func(t *testing.T) {
		id := fakes.publish(t, 1)
		env.requireHeld(t, ctx, id)
		swapContainer(t, ctx, env.out.ContainerName, toImage, "indexer", "", services.UpgradeContainer)
		env.requireStatus(t, ctx, id, statusProcessing)
		fakes.release(id)
		env.requireDelivered(t, ctx, id)
	})

	t.Run("message in flight across the rollback", func(t *testing.T) {
		id := fakes.publish(t, 2)
		env.requireHeld(t, ctx, id)
		env.requireInsideWindow(t, ctx, id)
		swapContainer(t, ctx, env.out.ContainerName, fromImage, "indexer", "", services.RollbackContainer)
		env.requireStatus(t, ctx, id, statusProcessing)
		fakes.release(id)
		env.requireDelivered(t, ctx, id)
	})
}

type idxUpgradeEnv struct {
	out     *services.IndexerOutput
	db      *sql.DB
	monitor *ccv.IndexerMonitor
}

// newIdxUpgradeEnv starts one indexer replica on image. They discover messages from the fake aggregator and need
// a result from the fake committee verifier and from the fake token verifier.
func newIdxUpgradeEnv(t *testing.T, image string, fakes *fakeVerifiers) *idxUpgradeEnv {
	t.Helper()
	const committeeName, tokenName = "Committee Verifier", "Token Verifier"
	out, err := services.NewIndexer(&services.IndexerInput{
		Image:         image,
		Port:          idxUpgradePort,
		ContainerName: idxUpgradeName,
		Replicas:      1,
		DB:            &services.DBInput{Image: services.DefaultIndexerDBImage, HostPort: idxUpgradeDBPort},
		IndexerConfig: &config.Config{
			LogLevel: "debug",
			Scheduler: config.SchedulerConfig{
				TickerInterval:               100,
				VerificationVisibilityWindow: idxVisibilityWindow,
				BaseDelay:                    100,
				MaxDelay:                     1000,
			},
			Pool: config.PoolConfig{ConcurrentWorkers: 5, WorkerTimeout: 30},
			Discoveries: []config.DiscoveryConfig{{
				AggregatorReaderConfig: config.AggregatorReaderConfig{Address: fakes.GRPCAddr, InsecureConnection: true},
				PollInterval:           500,
				Timeout:                5000,
				NtpServer:              "time.google.com", // the same as env.toml; config validation requires it
			}},
			Verifiers: []config.VerifierConfig{
				{
					Type: config.ReaderTypeAggregator, Name: committeeName, BatchSize: 10, MaxBatchWaitTime: 50,
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: fakes.GRPCAddr, InsecureConnection: true},
				},
				{
					Type: config.ReaderTypeRest, Name: tokenName, BatchSize: 10, MaxBatchWaitTime: 50,
					RestReaderConfig: config.RestReaderConfig{BaseURL: fakes.RESTBaseURL},
				},
			},
			Storage: config.StorageConfig{
				Strategy: config.StorageStrategySingle,
				Single: &config.SingleStorageConfig{
					Type:     config.StorageBackendTypePostgres,
					Postgres: &config.PostgresConfig{MaxOpenConnections: 10, MaxIdleConnections: 5},
				},
			},
		},
		GeneratedCfg: &config.GeneratedConfig{Verifier: []config.GeneratedVerifierConfig{
			{Name: committeeName, IssuerAddresses: []string{fakes.committeeAddr.String()}},
			{Name: tokenName, IssuerAddresses: []string{fakes.tokenAddr.String()}},
		}},
	})
	require.NoError(t, err)
	require.Len(t, out.ReplicaContainerNames, 1)

	// The DB name, user, and password are the indexer name.
	db, err := sql.Open("postgres", fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable",
		idxUpgradeName, idxUpgradeName, out.DBURL, idxUpgradeName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(t.Context()))

	ic, err := client.NewIndexerClient(out.ExternalHTTPURL, &http.Client{Timeout: 10 * time.Second})
	require.NoError(t, err)
	monitor, err := ccv.NewIndexerMonitor(zerolog.Nop(), ic)
	require.NoError(t, err)
	return &idxUpgradeEnv{out: out, db: db, monitor: monitor}
}

// requireHeld waits until the indexer stores the message as PROCESSING with only its committee verification.
func (e *idxUpgradeEnv) requireHeld(t *testing.T, ctx context.Context, id protocol.Bytes32) {
	t.Helper()
	e.requireStatus(t, ctx, id, statusProcessing)
	e.requireVerifications(t, ctx, id, 1)
}

// requireDelivered waits until the message is SUCCESS and the indexer serves both verifications.
func (e *idxUpgradeEnv) requireDelivered(t *testing.T, ctx context.Context, id protocol.Bytes32) {
	t.Helper()
	e.requireStatus(t, ctx, id, statusSuccess)
	e.requireVerifications(t, ctx, id, 2)
}

func (e *idxUpgradeEnv) requireStatus(t *testing.T, ctx context.Context, id protocol.Bytes32, want string) {
	t.Helper()
	var got string
	require.Eventually(t, func() bool {
		err := e.db.QueryRowContext(ctx, `SELECT status FROM indexer.messages WHERE message_id = $1`, id.String()).Scan(&got)
		return err == nil && got == want
	}, idxStatusTimeout, 500*time.Millisecond, "message %s: want status %s, last status %q", id.String(), want, got)
}

func (e *idxUpgradeEnv) requireVerifications(t *testing.T, ctx context.Context, id protocol.Bytes32, want int) {
	t.Helper()
	var got int
	require.Eventually(t, func() bool {
		resp, err := e.monitor.GetVerificationsForMessageID(ctx, id)
		if err != nil {
			return false
		}
		got = len(resp.Results)
		return got == want
	}, idxStatusTimeout, 500*time.Millisecond, "message %s: want %d verifications, last count %d", id.String(), want, got)
}

// requireInsideWindow checks that the retry deadline leaves time for the swap. Versions without the column skip it.
func (e *idxUpgradeEnv) requireInsideWindow(t *testing.T, ctx context.Context, id protocol.Bytes32) {
	t.Helper()
	if !columnExists(t, e.db, "indexer.messages", "retry_deadline") {
		t.Log("indexer.messages has no retry_deadline column: no visibility window check")
		return
	}
	var left time.Duration
	var seconds float64
	require.NoError(t, e.db.QueryRowContext(ctx,
		`SELECT EXTRACT(EPOCH FROM retry_deadline - NOW()) FROM indexer.messages WHERE message_id = $1`, id.String()).Scan(&seconds))
	left = time.Duration(seconds * float64(time.Second))
	require.Greater(t, left, idxDeadlineMargin, "message %s must stay inside the visibility window during the rollback", id.String())
}
