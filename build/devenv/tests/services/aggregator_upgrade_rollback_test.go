package services_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

const (
	aggUpgradeCommittee = "upgrade"
	aggUpgradeHostPort  = 8120
	aggUpgradeDBPort    = 7450
	aggUpgradeRedisPort = 6400
	// aggregationJobsTable is the durable aggregation queue. Versions without it have no persisted job to carry.
	aggregationJobsTable = "ccv_aggregation_jobs"
	// aggregationQueueOwner is the owner_id that every aggregator replica uses for the queue.
	aggregationQueueOwner = "aggregator"
	aggregationTimeout    = time.Minute
)

// TestAggregator_UpgradeRollbackWithPendingJob runs one aggregator replica. A persisted aggregation job stays
// pending while the replica is swapped, so only the swapped image can drain it. The swapped image must then also
// aggregate a fresh message. Phase A does this for an upgrade, phase B for a rollback.
func TestAggregator_UpgradeRollbackWithPendingJob(t *testing.T) {
	fromImage, toImage := upgradeImages(t, "aggregator")
	ctx := t.Context()
	env := newAggUpgradeEnv(t, fromImage)
	replica := env.out.ReplicaContainerNames[0]
	proxy := env.out.NginxContainerName

	t.Run("phase A: upgrade with a pending job", func(t *testing.T) {
		if !tableExists(t, env.db, aggregationJobsTable) {
			t.Skipf("%s has no %s table: no persisted job to carry over the upgrade", fromImage, aggregationJobsTable)
		}
		held := env.holdJob(t, ctx)
		swapContainer(t, ctx, replica, toImage, "aggregator", proxy, services.UpgradeContainer)
		env.releaseAndDrain(t, ctx, held)
		env.requireAggregates(t, ctx)
	})
	// A skipped phase A leaves the replica on the old image.
	onTo, err := services.RunsImage(ctx, replica, toImage)
	require.NoError(t, err)
	if !onTo {
		swapContainer(t, ctx, replica, toImage, "aggregator", proxy, services.UpgradeContainer)
	}

	t.Run("phase B: rollback with a pending job", func(t *testing.T) {
		if !tableExists(t, env.db, aggregationJobsTable) {
			t.Skipf("%s has no %s table: no persisted job to carry over the rollback", toImage, aggregationJobsTable)
		}
		held := env.holdJob(t, ctx)
		swapContainer(t, ctx, replica, fromImage, "aggregator", proxy, services.RollbackContainer)
		env.releaseAndDrain(t, ctx, held)
		env.requireAggregates(t, ctx)
	})
}

type aggUpgradeEnv struct {
	*aggregatorTestFixture
	out *services.AggregatorOutput
	db  *sql.DB
}

// heldJob is a pending aggregation job that a blocker row keeps from being claimed.
type heldJob struct {
	messageID protocol.Bytes32
	key       string
	blockerID int64
}

// newAggUpgradeEnv starts one aggregator replica on image with a 2-of-3 committee and TLS clients through nginx.
func newAggUpgradeEnv(t *testing.T, image string) *aggUpgradeEnv {
	t.Helper()
	sourceChainSel := uint64(12922642891491394802)
	verifierAddress := "0x68B1D87F95878fE05B998F19b66F4baba5De1aed"
	signer1 := newTestSigner(t, aggUpgradeCommittee, 0)
	signer2 := newTestSigner(t, aggUpgradeCommittee, 1)
	signer3 := newTestSigner(t, aggUpgradeCommittee, 2)
	creds1, err := hmacutil.GenerateCredentials()
	require.NoError(t, err)
	creds2, err := hmacutil.GenerateCredentials()
	require.NoError(t, err)

	instance := aggUpgradeCommittee
	selector := fmt.Sprintf("%d", sourceChainSel)
	out, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName: aggUpgradeCommittee,
		Image:         image,
		HostPort:      aggUpgradeHostPort,
		Replicas:      1,
		DB:            &services.AggregatorDBInput{Image: "postgres:16-alpine", HostPort: aggUpgradeDBPort},
		Redis:         &services.AggregatorRedisInput{Image: "redis:7-alpine", HostPort: aggUpgradeRedisPort},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@%s-%s:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername, services.DefaultAggregatorDBPassword,
				instance, services.AggregatorDBContainerNameSuffix, services.DefaultAggregatorDBName),
			RedisAddress: fmt.Sprintf("%s-%s:6379", instance, services.AggregatorRedisContainerNameSuffix),
			RedisDB:      "0",
		},
		APIClients: []*services.AggregatorClientConfig{
			{ClientID: "upgrade-verifier-1", Enabled: true, Groups: []string{"service-tests-1"},
				APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: creds1.APIKey, Secret: creds1.Secret}}},
			{ClientID: "upgrade-verifier-2", Enabled: true, Groups: []string{"service-tests-1"},
				APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: creds2.APIKey, Secret: creds2.Secret}}},
		},
		GeneratedCommittee: &model.Committee{
			QuorumConfigs: map[string]*model.QuorumConfig{
				selector: {
					SourceVerifierAddress: verifierAddress,
					Signers:               []model.Signer{{Address: signer1.publicKeyHex}, {Address: signer2.publicKeyHex}, {Address: signer3.publicKeyHex}},
					Threshold:             2,
				},
			},
			// The report needs the verifier of the destination chain of the message (createValidMessage uses 2).
			DestinationVerifiers: map[string]string{selector: verifierAddress, "2": verifierAddress},
		},
	})
	require.NoError(t, err)
	require.Len(t, out.ReplicaContainerNames, 1)
	t.Cleanup(func() {
		if t.Failed() {
			dumpLogs(t, out.ReplicaContainerNames, "-pre-upgrade", "-pre-rollback")
		}
	})

	tlsCreds, err := credentials.NewClientTLSFromFile(out.TLSCACertFile, "localhost")
	require.NoError(t, err)
	dial := func(c hmacutil.Credentials) *grpc.ClientConn {
		conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", aggUpgradeHostPort),
			grpc.WithTransportCredentials(tlsCreds),
			grpc.WithUnaryInterceptor(hmacutil.NewClientInterceptor(&hmacutil.ClientConfig{APIKey: c.APIKey, Secret: c.Secret})))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	conn1, conn2 := dial(creds1), dial(creds2)

	db, err := sql.Open("postgres", fmt.Sprintf("postgresql://%s:%s@localhost:%d/%s?sslmode=disable",
		services.DefaultAggregatorDBUsername, services.DefaultAggregatorDBPassword, aggUpgradeDBPort, services.DefaultAggregatorDBName))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(t.Context()))

	return &aggUpgradeEnv{
		aggregatorTestFixture: &aggregatorTestFixture{
			honestSigner1:          signer1,
			honestSigner2:          signer2,
			sourceChainSel:         sourceChainSel,
			destChainSel:           2,
			verifierAddress:        verifierAddress,
			honest1CommitteeClient: committeepb.NewCommitteeVerifierClient(conn1),
			honest2CommitteeClient: committeepb.NewCommitteeVerifierClient(conn2),
			verifierClient:         verifierpb.NewVerifierClient(conn1),
			sequenceCounter:        5000,
		},
		out: out,
		db:  db,
	}
}

// write sends the signature of one signer for msg.
func (e *aggUpgradeEnv) write(t *testing.T, ctx context.Context, client committeepb.CommitteeVerifierClient, signer *testSigner, msg *protocol.Message) {
	t.Helper()
	resp, err := client.WriteCommitteeVerifierNodeResult(ctx, e.signMessage(t, signer, msg))
	require.NoError(t, err)
	require.Equal(t, committeepb.WriteStatus_SUCCESS, resp.Status)
}

// holdJob makes a pending aggregation job for a new message and keeps it pending with a blocker row.
// Fewer than quorum signatures make no job, and workers cannot be paused, so a processing row with the same key
// blocks the claim (the queue serializes per key).
func (e *aggUpgradeEnv) holdJob(t *testing.T, ctx context.Context) heldJob {
	t.Helper()
	msg := e.createValidMessage(t)
	id, err := msg.MessageID()
	require.NoError(t, err)
	e.write(t, ctx, e.honest1CommitteeClient, e.honestSigner1, msg)

	var key string
	require.NoError(t, e.db.QueryRowContext(ctx,
		`SELECT aggregation_key FROM commit_verification_records WHERE message_id = $1 LIMIT 1`,
		protocol.ByteSlice(id[:]).String()).Scan(&key))

	var blockerID int64
	require.NoError(t, e.db.QueryRowContext(ctx, `
		INSERT INTO `+aggregationJobsTable+` (job_id, owner_id, dedup_key, task_data, status, started_at, retry_deadline)
		VALUES (gen_random_uuid(), $1, $2, '{}', 'processing', NOW(), NOW() + INTERVAL '1 hour')
		RETURNING id`, aggregationQueueOwner, key).Scan(&blockerID))

	e.write(t, ctx, e.honest2CommitteeClient, e.honestSigner2, msg)
	require.Equal(t, 1, e.jobCount(t, ctx, key, "pending"), "quorum must leave one pending job behind the blocker")
	return heldJob{messageID: id, key: key, blockerID: blockerID}
}

// releaseAndDrain removes the blocker, waits until the queue has no open job for the key, and checks the report.
// It must run within the queue lock duration (2m), else the stale reclaim changes the blocker row.
func (e *aggUpgradeEnv) releaseAndDrain(t *testing.T, ctx context.Context, h heldJob) {
	t.Helper()
	require.Equal(t, 1, e.jobCount(t, ctx, h.key, "pending"), "the job must still be pending before the release")
	_, err := e.db.ExecContext(ctx, `DELETE FROM `+aggregationJobsTable+` WHERE id = $1`, h.blockerID)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return e.jobCount(t, ctx, h.key, "pending")+e.jobCount(t, ctx, h.key, "processing") == 0
	}, aggregationTimeout, time.Second, "the queue did not drain the job of %s", h.key)
	e.requireReport(t, ctx, h.messageID)
}

// requireAggregates signs a fresh message with quorum and requires a report with a seq_num above all earlier ones.
func (e *aggUpgradeEnv) requireAggregates(t *testing.T, ctx context.Context) {
	t.Helper()
	var maxBefore int64
	require.NoError(t, e.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq_num), 0) FROM commit_aggregated_reports`).Scan(&maxBefore))
	msg := e.createValidMessage(t)
	id, err := msg.MessageID()
	require.NoError(t, err)
	e.write(t, ctx, e.honest1CommitteeClient, e.honestSigner1, msg)
	e.write(t, ctx, e.honest2CommitteeClient, e.honestSigner2, msg)
	e.requireReport(t, ctx, id)

	// The read API can answer before the report row is committed, so wait for the row.
	var seq sql.NullInt64
	require.Eventually(t, func() bool {
		err := e.db.QueryRowContext(ctx, `SELECT MAX(seq_num) FROM commit_aggregated_reports WHERE message_id = $1`,
			protocol.ByteSlice(id[:]).String()).Scan(&seq)
		return err == nil && seq.Valid
	}, aggregationTimeout, time.Second, "no report row for %s", protocol.ByteSlice(id[:]).String())
	require.Greater(t, seq.Int64, maxBefore, "the report of the fresh message must come after all earlier reports")
}

// requireReport waits until the aggregator serves the aggregated result of the message.
func (e *aggUpgradeEnv) requireReport(t *testing.T, ctx context.Context, id protocol.Bytes32) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp, err := e.verifierClient.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{MessageIds: [][]byte{id[:]}})
		// A message with no report comes back as an empty result, so check for its message.
		return err == nil && len(resp.Results) == 1 && resp.Results[0].GetMessage() != nil
	}, aggregationTimeout, time.Second, "no aggregated result for %s", protocol.ByteSlice(id[:]).String())
}

func (e *aggUpgradeEnv) jobCount(t *testing.T, ctx context.Context, key, status string) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM `+aggregationJobsTable+` WHERE owner_id = $1 AND dedup_key = $2 AND status = $3`,
		aggregationQueueOwner, key, status).Scan(&n))
	return n
}
