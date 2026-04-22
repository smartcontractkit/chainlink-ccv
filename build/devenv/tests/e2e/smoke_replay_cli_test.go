package e2e

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const replayBinary = "/bin/indexer-replay"

func execInContainer(ctx context.Context, containerName string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"exec", containerName}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func openIndexerDB(t *testing.T, in *ccv.Cfg) (*sql.DB, string) {
	t.Helper()
	require.GreaterOrEqual(t, len(in.Indexer), 1, "expected at least one indexer")
	require.NotNil(t, in.Indexer[0].Out, "first indexer must have output")

	containerName := strings.TrimPrefix(in.Indexer[0].Out.ContainerName, "/")
	require.NotEmpty(t, containerName)

	dbURL := in.Indexer[0].Out.DBURL
	require.NotEmpty(t, dbURL, "indexer DB URL must be set")
	dbUser := containerName
	dbConnStr := fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable",
		dbUser, dbUser, dbURL, dbUser)

	db, err := sql.Open("postgres", dbConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Ping(), "must be able to reach the indexer DB")

	return db, containerName
}

func replayCLIArgs(subcommand string, extra ...string) []string {
	return append([]string{replayBinary, subcommand}, extra...)
}

// TestE2ESmoke_ReplayCLI verifies the replay CLI subcommands work end-to-end:
// migration check, list, status, and a discovery dry-run.
func TestE2ESmoke_ReplayCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	db, containerName := openIndexerDB(t, in)

	const fakeJobID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	// Clean slate: remove any leftover jobs from previous runs.
	_, err = db.ExecContext(context.Background(), "DELETE FROM indexer.replay_jobs")
	require.NoError(t, err, "cleanup of replay_jobs table")

	t.Cleanup(func() {
		_, err = db.ExecContext(context.Background(), "DELETE FROM indexer.replay_jobs")
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	t.Run("list empty", func(t *testing.T) {
		out, err := execInContainer(t.Context(), containerName, replayCLIArgs("list")...)
		require.NoError(t, err, "list should succeed; output: %s", out)
		require.Contains(t, out, "No replay jobs found", "empty list should report no jobs; output: %s", out)
	})

	t.Run("seed and list", func(t *testing.T) {
		ctx := context.Background()
		_, err := db.ExecContext(ctx, `
			INSERT INTO indexer.replay_jobs (id, type, status, force_overwrite, created_at, updated_at)
			VALUES ($1, 'messages', 'completed', false, NOW(), NOW())`,
			fakeJobID,
		)
		require.NoError(t, err, "seeding fake replay job")

		out, err := execInContainer(ctx, containerName, replayCLIArgs("list")...)
		require.NoError(t, err, "list should succeed; output: %s", out)
		require.Contains(t, out, fakeJobID, "list output must contain the seeded job ID; output: %s", out)
	})

	t.Run("status", func(t *testing.T) {
		out, err := execInContainer(t.Context(), containerName, replayCLIArgs("status", "--id", fakeJobID)...)
		require.NoError(t, err, "status should succeed; output: %s", out)
		require.Contains(t, out, fakeJobID, "status output must contain the job ID; output: %s", out)
		require.Contains(t, out, "completed", "status output must show completed status; output: %s", out)
	})

	t.Run("discovery", func(t *testing.T) {
		out, err := execInContainer(t.Context(), containerName, replayCLIArgs("discovery", "--since", "1")...)
		require.NoError(t, err, "discovery replay should succeed with sequence 1; output: %s", out)
	})
}

// getIngestionTimestamp reads the most recent ingestion_timestamp for a message
// from the indexer verifier_results table.
func getIngestionTimestamp(ctx context.Context, db *sql.DB, msgIDHex string) (time.Time, error) {
	var ts time.Time
	err := db.QueryRowContext(ctx,
		"SELECT ingestion_timestamp FROM indexer.verifier_results WHERE message_id = $1 ORDER BY ingestion_timestamp DESC LIMIT 1",
		msgIDHex,
	).Scan(&ts)
	return ts, err
}

// sendAndWaitForIndexed sends a message with fast finality and waits until the
// indexer has picked up its verifications. Returns the [32]byte messageID and
// its hex representation.
func sendAndWaitForIndexed(
	t *testing.T,
	ctx context.Context,
	src, dest cciptestinterfaces.CCIP17,
	msgData []byte,
	executorAddr, ccvAddr, receiver protocol.UnknownAddress,
	testCtx *tcapi.TestingContext,
) (protocol.Bytes32, string) {
	t.Helper()

	seqNo, err := src.GetExpectedNextSequenceNumber(ctx, dest.ChainSelector())
	require.NoError(t, err)

	_, err = src.SendMessage(ctx, dest.ChainSelector(),
		cciptestinterfaces.MessageFields{Receiver: receiver, Data: msgData},
		evm.MessageOptions{
			Version:        3,
			FinalityConfig: 1,
			Executor:       executorAddr,
			CCVs:           []protocol.CCV{{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}},
		},
	)
	require.NoError(t, err, "failed to send message")

	sentEvt, err := src.ConfirmSendOnSource(ctx, dest.ChainSelector(), cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, tcapi.DefaultSentTimeout)
	require.NoError(t, err, "failed to wait for sent event")
	msgIDHex := "0x" + hex.EncodeToString(sentEvt.MessageID[:])
	t.Logf("Message sent: %s", msgIDHex)

	result, err := testCtx.AssertMessage(sentEvt.MessageID, tcapi.AssertMessageOptions{
		TickInterval:            1 * time.Second,
		Timeout:                 tcapi.DefaultExecTimeout,
		ExpectedVerifierResults: 1,
	})
	require.NoError(t, err, "message %s was not indexed in time", msgIDHex)
	require.True(t, result.IndexerFound, "message %s must be found in indexer", msgIDHex)
	t.Logf("Message %s indexed with %d verification(s)", msgIDHex, len(result.IndexedVerifications.Results))

	return sentEvt.MessageID, msgIDHex
}

// TestE2ESmoke_ReplayForceOverwrite exercises the replay system end-to-end:
//
//  1. Sends two messages with fast finality, waits for both to be indexed.
//  2. Replays message-1 only with `messages --ids <msg1> --force` and verifies
//     only message-1's ingestion_timestamp changed while message-2 is untouched.
//  3. Replays both with `discovery --since <ts> --force` and verifies both
//     messages' timestamps are updated.
//  4. Replays again with `discovery --since <ts>` (no --force, backfill-only)
//     and verifies neither message's timestamp changed because there is nothing
//     new to backfill.
func TestE2ESmoke_ReplayForceOverwrite(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	db, containerName := openIndexerDB(t, in)

	ctx := ccv.Plog.WithContext(t.Context())

	harness, err := tcapi.NewTestHarness(ctx, smokeTestConfig, in, chain_selectors.FamilyEVM)
	require.NoError(t, err)

	chains, err := harness.Lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains")

	src := chains[0].CCIP17
	dest := chains[1].CCIP17

	executorAddr := getContractAddress(t, in, src.ChainSelector(),
		datastore.ContractType(sequences.ExecutorProxyType),
		proxy.Deploy.Version(),
		devenvcommon.DefaultExecutorQualifier,
		"executor")
	ccvAddr := getContractAddress(t, in, src.ChainSelector(),
		datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
		versioned_verifier_resolver.Version.String(),
		devenvcommon.DefaultCommitteeVerifierQualifier,
		"committee verifier proxy")
	receiver := mustGetEOAReceiverAddress(t, dest)

	aggregatorClient := harness.AggregatorClients[devenvcommon.DefaultCommitteeVerifierQualifier]
	chainMap, err := harness.Lib.ChainsMap(ctx)
	require.NoError(t, err)
	testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, harness.IndexerMonitor)
	defer cleanupFn()

	t.Cleanup(func() {
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	// The aggregator's GetMessagesSince uses a monotonic sequence number.
	// Using sequence 1 ensures the aggregator returns all messages from the beginning.
	const discoverySince = "1"

	// ── Step 1: send two messages and wait for indexing ──────────────────────
	t.Log("Step 1: sending two messages with finality=1...")
	msgID1, msgHex1 := sendAndWaitForIndexed(t, ctx, src, dest,
		[]byte("replay-test-msg-1"), executorAddr, ccvAddr, receiver, &testCtx)
	msgID2, msgHex2 := sendAndWaitForIndexed(t, ctx, src, dest,
		[]byte("replay-test-msg-2"), executorAddr, ccvAddr, receiver, &testCtx)

	ts1Before, err := getIngestionTimestamp(ctx, db, msgHex1)
	require.NoError(t, err, "read msg1 ingestion_timestamp")
	ts2Before, err := getIngestionTimestamp(ctx, db, msgHex2)
	require.NoError(t, err, "read msg2 ingestion_timestamp")
	t.Logf("Before replay: msg1=%s  msg2=%s",
		ts1Before.Format(time.RFC3339Nano), ts2Before.Format(time.RFC3339Nano))

	time.Sleep(2 * time.Second)

	// ── Step 2: replay msg1 only with --force via --ids ─────────────────────
	t.Log("Step 2: replaying msg1 with messages --ids --force...")
	out, err := execInContainer(ctx, containerName,
		replayCLIArgs("messages", "--ids", msgHex1, "--force")...)
	require.NoError(t, err, "messages replay failed; output: %s", out)

	ts1AfterIDs, err := getIngestionTimestamp(ctx, db, msgHex1)
	require.NoError(t, err)
	ts2AfterIDs, err := getIngestionTimestamp(ctx, db, msgHex2)
	require.NoError(t, err)
	t.Logf("After --ids replay: msg1=%s  msg2=%s",
		ts1AfterIDs.Format(time.RFC3339Nano), ts2AfterIDs.Format(time.RFC3339Nano))

	require.True(t, ts1AfterIDs.After(ts1Before),
		"msg1 ingestion_timestamp must be updated after --ids --force replay")
	require.True(t, ts2AfterIDs.Equal(ts2Before),
		"msg2 ingestion_timestamp must be unchanged after replaying only msg1")

	time.Sleep(2 * time.Second)

	// ── Step 3: replay both with --force via discovery --since ───────────────
	t.Logf("Step 3: replaying both with discovery --since %s --force...", discoverySince)
	out, err = execInContainer(ctx, containerName,
		replayCLIArgs("discovery", "--since", discoverySince, "--force")...)
	require.NoError(t, err, "discovery force replay failed; output: %s", out)

	ts1AfterDisc, err := getIngestionTimestamp(ctx, db, msgHex1)
	require.NoError(t, err)
	ts2AfterDisc, err := getIngestionTimestamp(ctx, db, msgHex2)
	require.NoError(t, err)
	t.Logf("After discovery --force: msg1=%s  msg2=%s",
		ts1AfterDisc.Format(time.RFC3339Nano), ts2AfterDisc.Format(time.RFC3339Nano))

	require.True(t, ts1AfterDisc.After(ts1AfterIDs),
		"msg1 ingestion_timestamp must be updated after discovery --force")
	require.True(t, ts2AfterDisc.After(ts2AfterIDs),
		"msg2 ingestion_timestamp must be updated after discovery --force")

	time.Sleep(2 * time.Second)

	// ── Step 4: replay without --force (backfill-only, nothing to fill) ─────
	t.Logf("Step 4: replaying with discovery --since %s (no --force)...", discoverySince)
	out, err = execInContainer(ctx, containerName,
		replayCLIArgs("discovery", "--since", discoverySince)...)
	require.NoError(t, err, "discovery backfill replay failed; output: %s", out)

	ts1AfterBackfill, err := getIngestionTimestamp(ctx, db, msgHex1)
	require.NoError(t, err)
	ts2AfterBackfill, err := getIngestionTimestamp(ctx, db, msgHex2)
	require.NoError(t, err)
	t.Logf("After discovery (no force): msg1=%s  msg2=%s",
		ts1AfterBackfill.Format(time.RFC3339Nano), ts2AfterBackfill.Format(time.RFC3339Nano))

	require.True(t, ts1AfterBackfill.Equal(ts1AfterDisc),
		"msg1 ingestion_timestamp must NOT change on backfill-only replay (already exists)")
	require.True(t, ts2AfterBackfill.Equal(ts2AfterDisc),
		"msg2 ingestion_timestamp must NOT change on backfill-only replay (already exists)")

	// ── Final: verify data integrity via indexer HTTP API ────────────────────
	for _, tc := range []struct {
		name  string
		msgID protocol.Bytes32
	}{
		{"msg1", msgID1},
		{"msg2", msgID2},
	} {
		verifs, err := harness.IndexerMonitor.GetVerificationsForMessageID(ctx, tc.msgID)
		require.NoError(t, err, "%s: failed to read verifications after all replays", tc.name)
		require.GreaterOrEqual(t, len(verifs.Results), 1,
			"%s: verifications must still be present after all replays", tc.name)
	}
}
