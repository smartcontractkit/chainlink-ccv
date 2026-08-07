package e2e

// Durability coverage: every test here kills or isolates a service that is holding state, and
// asserts a message still gets delivered once it comes back.
//
// The standalone stack keeps restart-critical state in three different places, and each one has a
// test below:
//
//   - The executor keeps in-flight transaction state in memory only (TXM v2 has no store), so a
//     restart loses track of anything already broadcast. Recovery is nonce-gap detection in the EVM
//     accessor. See TestChaos_ExecutorRestartWithInFlightTransaction.
//   - The verifier keeps its source-chain scan position in ccv_chain_statuses and its in-progress
//     verification work in ccv_task_verifier_jobs, both in Postgres. Recovery is resuming from the
//     checkpoint and reclaiming stale job locks. See TestChaos_VerifierRestartWithMessageOnChain
//     and TestChaos_VerifierResumesFromCheckpoint.
//   - Postgres itself can go away underneath a running verifier. See
//     TestChaos_VerifierDatabaseOutage.
//
// Nothing else in the EVM path is persisted: the head tracker runs in-memory and rebuilds from RPC,
// and the executor rediscovers work from the indexer and on-chain execution state.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/chaos"
)

const (
	// inFlightPollInterval is how often a test polls the chain or a service database while waiting
	// for a durability precondition to hold.
	inFlightPollInterval = 500 * time.Millisecond
	// inFlightWaitTimeout bounds the wait for the executor to put a transaction in the mempool. It
	// has to cover the executor noticing the message through the indexer and aggregator, not just
	// the send, which takes a few seconds in devenv.
	//
	// It is also the ceiling on how long mining stays held, and that has a hard limit: MultiNode
	// marks an RPC out of sync after three minutes without a new head. devenv gives each chain a
	// single RPC, so the pool cannot fail over and the executor carries on in a degraded state, but
	// it is not a state to run a test in. Keep this comfortably under three minutes.
	inFlightWaitTimeout = 90 * time.Second
	// executorOutageDuration is how long the executor stays down. Pumba restarts it afterwards.
	executorOutageDuration = 20 * time.Second
	// recoveryTimeout bounds how long execution may take after a service comes back. It has to
	// cover the accessor's orphan recovery grace period plus a re-execution.
	recoveryTimeout = 6 * time.Minute

	// verifierJobOutageDuration outlives the verifier's task queue lock (taskQueueLockDuration, 2m
	// in verifier/pkg/coordinator.go). A shorter outage would let a restarted verifier pick up its
	// own job before the lock expired, leaving the stale-job reclaim path untested.
	verifierJobOutageDuration = 150 * time.Second
	// verifierCheckpointOutage only has to outlive the send and the block fast-forward that follow
	// it, so it is much shorter than verifierJobOutageDuration.
	verifierCheckpointOutage = 90 * time.Second
	// verifierDBOutageDuration is how long the verifier's Postgres stays down while a message is
	// sent underneath it. A message travels end to end in a few seconds here, so the window has to
	// be comfortably longer than that or the verifier finishes before the outage bites.
	verifierDBOutageDuration = 60 * time.Second
	// dbTransitionTimeout bounds the wait for a database to go down or come back. It exceeds
	// verifierDBOutageDuration because the wait for the database to return starts before the outage
	// has necessarily elapsed.
	dbTransitionTimeout = 90 * time.Second

	// checkpointFallbackLookback mirrors the lookback the verifier's source reader uses when it
	// finds no checkpoint (verifier/pkg/sourcereader/service.go, initializeStartBlock).
	checkpointFallbackLookback = 500
	// checkpointFastForwardBlocks moves the head far enough past the message that the fallback
	// window can no longer reach it, with margin for blocks mined by the node itself in the
	// meantime. Only a verifier that resumed from its checkpoint can still find the message.
	checkpointFastForwardBlocks = 600
	// checkpointWaitTimeout bounds the wait for verifiers to have written any checkpoint at all,
	// which they do every scan cycle once the source reader is running.
	checkpointWaitTimeout = 2 * time.Minute
)

// TestChaos_ExecutorRestartWithInFlightTransaction is the disaster recovery case for the executor:
// the process dies with a transaction already in the destination mempool, and the message still has
// to execute once it comes back.
//
// That gap matters because TXM v2 keeps transaction state in memory. A restarted executor has no
// record of what the old process had in flight, so nothing rebroadcasts or gas bumps it, and until
// it mines or is evicted nothing behind its nonce can confirm. The accessor detects the orphan from
// the gap between the address's pending and latest nonce and drives it to completion; this test is
// the end-to-end check that a message survives the whole sequence.
//
// The transaction is held in flight deliberately rather than by racing block production: mining on
// the destination is stopped so the executor's transaction sits in the mempool for as long as the
// test needs, which is the only way to make the kill land in the right window every run.
//
// Requires a destination chain that can hold mining (anvil). Skips otherwise.
func TestChaos_ExecutorRestartWithInFlightTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	holdable := requireMineHoldableChain(t, ctx, lib, dst)
	transmitters := executorTransmitterAddresses(t, setup, dst)
	interval := chainMiningInterval(t, setup, dst)

	// Stop mining on the destination so the executor's transaction stays in the mempool. Resuming
	// is registered before anything else can fail, so a mid-test failure does not leave the chain
	// frozen for later tests.
	require.NoError(t, holdable.HoldMining(ctx), "stop mining on destination")
	t.Cleanup(func() {
		if err := holdable.ResumeMining(context.WithoutCancel(ctx), interval); err != nil {
			t.Logf("failed to resume mining on destination: %v", err)
		}
	})

	messageKey := sendDurabilityMessage(t, ctx, lib, src, dst)

	// Wait for the executor to actually broadcast. Killing it before this point would test an
	// ordinary restart, not a restart with work in flight, and the test would pass without
	// exercising recovery at all.
	waitForInFlightTransaction(t, ctx, holdable, transmitters)

	// Every executor serving this destination goes down. Leaving one up would let it execute the
	// message itself, and the test would pass without the orphaned transaction being recovered.
	executorTargets, err := chaos.ExecutorContainersForDest(setup.in, dst, devenvcommon.DefaultExecutorQualifier)
	require.NoError(t, err)
	cleanup, err := chaos.InjectOutage(ctx, &chaos.OutageSpec{
		Duration: executorOutageDuration,
		Targets:  executorTargets,
	})
	require.NoError(t, err, "stop the executor")
	t.Cleanup(cleanup)

	// Let mining resume while the executor is down, so the orphan's fate (mined, or still pending
	// when the executor returns) is decided by the chain rather than by test timing.
	//
	// Mining resumes here rather than being held through the accessor's grace period, which would
	// force the seed-and-replace path instead of letting the orphan mine. That does not work on a
	// frozen chain and is not worth making work: the gas estimator samples recent blocks, so with
	// none being produced it refuses to bump ("90 percentile price is not set... Preventing bumping
	// until valid price is available") and the replacement can never outbid the original. A stuck
	// transaction in production is stuck on a live chain, which is what this reproduces. The
	// seed-and-replace path itself is covered by unit tests in the accessor.
	require.NoError(t, holdable.ResumeMining(ctx, interval), "resume mining on destination")

	// Pumba restarts the container after the outage; the assertion below covers the restart, the
	// accessor's orphan recovery, and any re-execution the executor decides to do.
	requireExecOnDest(t, ctx, lib, src, dst, messageKey,
		"message should execute after the executor restarts with a transaction in flight")
}

// TestChaos_VerifierRestartWithMessageOnChain kills enough verifiers to break quorum after the
// message is already on the source chain, and keeps them down for longer than the task queue lock.
//
// This is the complement to TestChaos_VerifierFaultToleranceThresholdViolated, which stops
// verifiers before the send. Here the message exists while they are down, so whichever point in the
// discovery -> claim -> verify sequence the kill lands on, recovery has to pick it up from durable
// state: either by rescanning from the chain status checkpoint, or by reclaiming a job left in
// 'processing' once its lock expires.
//
// The outage deliberately outlives taskQueueLockDuration so the reclaim path is reachable, and the
// test asserts afterwards that no job was left holding a lock.
func TestChaos_VerifierRestartWithMessageOnChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	stopped := quorumBreakingVerifiers(t, setup, src)
	targets := verifierContainerNames(t, setup, stopped)

	messageKey := sendDurabilityMessage(t, ctx, lib, src, dst)

	setup.l.Info().
		Strs("verifiers", targets).
		Dur("outage", verifierJobOutageDuration).
		Msg("stopping verifiers with the message already on chain")

	cleanup, err := chaos.InjectOutage(ctx, &chaos.OutageSpec{
		Duration: verifierJobOutageDuration,
		Targets:  targets,
	})
	require.NoError(t, err, "stop the verifiers")
	t.Cleanup(cleanup)

	requireExecOnDest(t, ctx, lib, src, dst, messageKey,
		"message should execute after quorum-breaking verifiers restart")

	// A job still in 'processing' after the message executed means a lock outlived the process that
	// took it. Nothing would ever retry that job, so the next message to hit the same path stalls.
	for _, verifier := range stopped {
		stuck := processingJobCount(t, ctx, verifier)
		require.Zerof(t, stuck, "verifier %s left %d job(s) locked in 'processing' after restart",
			verifier.ContainerName, stuck)
	}
}

// TestChaos_VerifierResumesFromCheckpoint proves the chain status checkpoint is load-bearing, which
// no other test does.
//
// The source reader starts from ccv_chain_statuses.finalized_block_height + 1, and falls back to a
// fixed lookback window when there is no checkpoint. Devenv chains are far shorter than that
// window, so a verifier that ignored its checkpoint entirely would still rescan the whole chain and
// find every message - the existing restart tests pass either way.
//
// This test removes that safety net. The verifiers are stopped, the message is sent, and then the
// head is fast-forwarded well past the fallback window before they come back. A verifier that
// resumes from its checkpoint scans the message's block; one that falls back starts after it and
// never sees the message, so the execution assertion fails.
//
// Requires a source chain the test can mine on demand (anvil). Skips otherwise.
func TestChaos_VerifierResumesFromCheckpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	mineable := requireMineHoldableChain(t, ctx, lib, src)
	stopped := quorumBreakingVerifiers(t, setup, src)
	targets := verifierContainerNames(t, setup, stopped)

	// Without a checkpoint on disk there is nothing to resume from and the test would be asserting
	// the fallback path instead. Wait for one rather than assuming the environment has been up long
	// enough to have written it.
	checkpoints := waitForCheckpoints(t, ctx, stopped, src)

	setup.l.Info().
		Strs("verifiers", targets).
		Interface("checkpoints", checkpoints).
		Msg("stopping verifiers before sending, then moving the head past the fallback window")

	cleanup, err := chaos.InjectOutage(ctx, &chaos.OutageSpec{
		Duration: verifierCheckpointOutage,
		Targets:  targets,
	})
	require.NoError(t, err, "stop the verifiers")
	t.Cleanup(cleanup)

	messageKey := sendDurabilityMessage(t, ctx, lib, src, dst)

	// One call, and no timestamp drift: mining these one at a time would also push chain time
	// forward by one block interval each, which changes finality and message age for every other
	// service in the environment.
	require.NoError(t, mineable.MineBlocks(ctx, checkpointFastForwardBlocks),
		"fast-forward the source chain past the fallback window")
	setup.l.Info().
		Uint64("blocks", checkpointFastForwardBlocks).
		Int("fallbackLookback", checkpointFallbackLookback).
		Msg("source head moved beyond the verifier fallback window")

	requireExecOnDest(t, ctx, lib, src, dst, messageKey,
		"message should execute only if the restarted verifiers resumed from their checkpoint")

	// Belt and braces: the checkpoint has to have moved past where it was, otherwise the verifiers
	// found the message some other way and the assertion above proved less than it looks.
	for _, verifier := range stopped {
		after, ok := verifierCheckpoint(t, ctx, verifier, src)
		require.Truef(t, ok, "verifier %s has no checkpoint after recovery", verifier.ContainerName)
		require.Greaterf(t, after, checkpoints[verifier.ContainerName],
			"verifier %s checkpoint did not advance past %d", verifier.ContainerName, checkpoints[verifier.ContainerName])
	}
}

// TestChaos_VerifierDatabaseOutage takes Postgres away from a running verifier while a message is
// sent, which is the failure the source reader is written to survive: it holds tasks in memory and
// retries rather than dropping them, and only advances the checkpoint after a successful write.
//
// The container hosts both the verifier database and that verifier's bootstrap database, so the
// outage removes chain statuses, the job queues, the keystore and the job store at once.
func TestChaos_VerifierDatabaseOutage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	stopped := quorumBreakingVerifiers(t, setup, src)
	stoppedNames := make(map[string]struct{}, len(stopped))
	for _, verifier := range stopped {
		stoppedNames[verifier.ContainerName] = struct{}{}
	}
	dbTargets, err := chaos.VerifierDBContainers(setup.in, devenvcommon.DefaultCommitteeVerifierQualifier,
		func(v *committeeverifier.Input) bool {
			_, ok := stoppedNames[v.ContainerName]
			return ok
		})
	require.NoError(t, err)

	before := waitForCheckpoints(t, ctx, stopped, src)

	setup.l.Info().
		Strs("databases", dbTargets).
		Dur("outage", verifierDBOutageDuration).
		Msg("stopping verifier databases, then sending a message while they are down")

	cleanup, err := chaos.InjectOutage(ctx, &chaos.OutageSpec{
		Duration: verifierDBOutageDuration,
		Targets:  dbTargets,
	})
	require.NoError(t, err, "stop the verifier databases")
	t.Cleanup(cleanup)

	// Pumba pulls and starts a sidecar before it issues the stop, so InjectOutage returning does not
	// mean the database is down. A message sent in that window gets verified and executed before the
	// outage lands, and the test asserts nothing.
	waitForDatabases(t, ctx, stopped, src, dbUnreachable)

	messageKey := sendDurabilityMessage(t, ctx, lib, src, dst)

	requireExecOnDest(t, ctx, lib, src, dst, messageKey,
		"message should execute after the verifier databases come back")

	// Reading the checkpoint has to wait for Postgres to accept connections again. Pumba restarts the
	// container at the end of the outage, and it spends a few seconds in recovery answering
	// "the database system is starting up" before it will serve a query.
	waitForDatabases(t, ctx, stopped, src, dbReachable)
	for _, verifier := range stopped {
		after, ok := verifierCheckpoint(t, ctx, verifier, src)
		require.Truef(t, ok, "verifier %s has no checkpoint after the database came back", verifier.ContainerName)
		require.GreaterOrEqualf(t, after, before[verifier.ContainerName],
			"verifier %s checkpoint went backwards across the database outage", verifier.ContainerName)
	}
}

// dbReachability is what waitForDatabases waits for.
type dbReachability bool

const (
	dbReachable   dbReachability = true
	dbUnreachable dbReachability = false
)

func (r dbReachability) String() string {
	if r {
		return "reachable"
	}
	return "unreachable"
}

// waitForDatabases blocks until every given verifier's database is in the wanted state. Postgres
// refuses queries for a while on both edges of a container stop, once while shutting down and again
// while recovering on start, so a test that cares which side of the outage it is on has to wait for
// the transition rather than assume it.
func waitForDatabases(
	t *testing.T,
	ctx context.Context,
	verifiers []*committeeverifier.Input,
	src uint64,
	want dbReachability,
) {
	t.Helper()

	deadline := time.Now().Add(dbTransitionTimeout)
	for _, verifier := range verifiers {
		for {
			_, err := readVerifierCheckpoint(ctx, verifier, src)
			// errNoCheckpoint means the query itself worked, so the database is up.
			reachable := err == nil || errors.Is(err, errNoCheckpoint)
			if reachable == bool(want) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("verifier %s database did not become %s within %s (last error: %v)",
					verifier.ContainerName, want, dbTransitionTimeout, err)
			}
			select {
			case <-ctx.Done():
				t.Fatalf("context canceled waiting for a verifier database: %v", ctx.Err())
			case <-time.After(inFlightPollInterval):
			}
		}
	}
}

// sendDurabilityMessage sends a V3 message and waits for the source-chain send to confirm, so the
// message exists on chain before the test injects its outage.
func sendDurabilityMessage(t *testing.T, ctx context.Context, lib ccv.Lib, src, dst uint64) cciptestinterfaces.MessageEventKey {
	t.Helper()

	receiver, ccvs, executor, err := tcapi.ResolveV3SendAddresses(ctx, lib, src, dst)
	require.NoError(t, err)

	v3Src, err := lib.V3Source(ctx, src)
	require.NoError(t, err)
	v3Dst, err := lib.V3Destination(ctx, dst)
	require.NoError(t, err)

	sent, _, err := tcapi.SendV3Message(ctx, v3Src, v3Dst, cciptestinterfaces.MessageFields{
		Receiver: receiver,
	}, cciptestinterfaces.MessageOptions{
		FinalityConfig: 1,
		Executor:       executor,
		CCVs:           ccvs,
	}, tcapi.SendArgs{})
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, [32]byte(sent.MessageID), "send returned zero message ID")

	messageKey := cciptestinterfaces.MessageEventKey{MessageID: sent.MessageID}
	_, err = v3Src.ConfirmSendOnSource(ctx, dst, messageKey, tcapi.DefaultSentTimeout)
	require.NoError(t, err, "confirm send on source")
	return messageKey
}

// requireExecOnDest waits for the message to execute on the destination within recoveryTimeout,
// which has to cover the outage, the restart, and whatever recovery the service does on the way up.
func requireExecOnDest(
	t *testing.T,
	ctx context.Context,
	lib ccv.Lib,
	src, dst uint64,
	messageKey cciptestinterfaces.MessageEventKey,
	msg string,
) {
	t.Helper()

	v3Dst, err := lib.V3Destination(ctx, dst)
	require.NoError(t, err)

	execCtx, cancel := context.WithTimeout(ctx, recoveryTimeout)
	defer cancel()
	_, err = v3Dst.ConfirmExecOnDest(execCtx, src, messageKey, recoveryTimeout)
	require.NoError(t, err, msg)
}

// quorumBreakingVerifiers returns the smallest set of default-committee verifiers whose loss takes
// the committee below its quorum threshold for the source chain. Stopping fewer would let the
// message verify without them and the test would prove nothing about their recovery.
func quorumBreakingVerifiers(t *testing.T, setup *chaosSetup, src uint64) []*committeeverifier.Input {
	t.Helper()

	var verifiers []*committeeverifier.Input
	for _, verifier := range setup.in.Verifier {
		if verifier.CommitteeName == devenvcommon.DefaultCommitteeVerifierQualifier {
			verifiers = append(verifiers, verifier)
		}
	}
	require.NotEmpty(t, verifiers, "no default-committee verifiers in the environment")

	var threshold uint8
	for _, aggregator := range setup.in.Aggregator {
		if aggregator.CommitteeName != devenvcommon.DefaultCommitteeVerifierQualifier {
			continue
		}
		require.NotNil(t, aggregator.Out, "default aggregator has no output")
		require.NotNil(t, aggregator.Out.GeneratedCommittee, "default aggregator has no generated committee")
		quorum, ok := aggregator.Out.GeneratedCommittee.QuorumConfigs[strconv.FormatUint(src, 10)]
		require.Truef(t, ok, "no quorum config for source chain %d", src)
		threshold = quorum.Threshold
		break
	}
	require.NotZero(t, threshold, "default committee has no quorum threshold for source chain")
	require.GreaterOrEqual(t, len(verifiers), int(threshold), "fewer verifiers than the quorum threshold")

	toStop := len(verifiers) - int(threshold) + 1
	require.Greater(t, toStop, 0, "quorum cannot be broken by stopping verifiers")
	return verifiers[:toStop]
}

// verifierContainerNames resolves Pumba targets for the given verifiers.
func verifierContainerNames(t *testing.T, setup *chaosSetup, verifiers []*committeeverifier.Input) []string {
	t.Helper()

	wanted := make(map[string]struct{}, len(verifiers))
	for _, verifier := range verifiers {
		require.NotNilf(t, verifier.Out, "verifier %s has no output", verifier.ContainerName)
		wanted[verifier.Out.ContainerName] = struct{}{}
	}
	targets, err := chaos.VerifierContainers(setup.in, devenvcommon.DefaultCommitteeVerifierQualifier,
		func(v *committeeverifier.Input) bool {
			_, ok := wanted[v.Out.ContainerName]
			return ok
		})
	require.NoError(t, err)
	return targets
}

// waitForCheckpoints blocks until every given verifier has written a source-chain checkpoint, and
// returns them keyed by verifier container name. Verifiers write one every scan cycle, so this only
// waits on a freshly started environment.
func waitForCheckpoints(t *testing.T, ctx context.Context, verifiers []*committeeverifier.Input, src uint64) map[string]uint64 {
	t.Helper()

	checkpoints := make(map[string]uint64, len(verifiers))
	deadline := time.Now().Add(checkpointWaitTimeout)
	for _, verifier := range verifiers {
		var lastErr error
		for {
			block, err := readVerifierCheckpoint(ctx, verifier, src)
			if err == nil && block > 0 {
				checkpoints[verifier.ContainerName] = block
				break
			}
			if err != nil {
				lastErr = err
			}
			if time.Now().After(deadline) {
				t.Fatalf("verifier %s wrote no checkpoint for chain %d within %s (last error: %v)",
					verifier.ContainerName, src, checkpointWaitTimeout, lastErr)
			}
			select {
			case <-ctx.Done():
				t.Fatalf("context canceled waiting for a verifier checkpoint: %v", ctx.Err())
			case <-time.After(inFlightPollInterval):
			}
		}
	}
	return checkpoints
}

// verifierCheckpoint reads the source-chain scan position the verifier would resume from, failing
// the test if the database cannot be read. Returns false when the verifier has written no
// checkpoint for that chain.
func verifierCheckpoint(t *testing.T, ctx context.Context, verifier *committeeverifier.Input, src uint64) (uint64, bool) {
	t.Helper()

	block, err := readVerifierCheckpoint(ctx, verifier, src)
	if errors.Is(err, errNoCheckpoint) {
		return 0, false
	}
	require.NoErrorf(t, err, "read checkpoint from verifier %s", verifier.ContainerName)
	return block, true
}

// errNoCheckpoint means the query succeeded and the verifier has not written a checkpoint for that
// chain. Distinct from a database that cannot be reached, which a poller should retry.
var errNoCheckpoint = errors.New("verifier has no checkpoint for chain")

func readVerifierCheckpoint(ctx context.Context, verifier *committeeverifier.Input, src uint64) (uint64, error) {
	db, err := openVerifierDB(verifier)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	// A verifier writes one row per (chain, verifier ID); take the furthest, which is the one that
	// determines where a restart picks up. MAX over no rows yields a single NULL, so an absent
	// checkpoint shows up as an invalid value rather than sql.ErrNoRows.
	var height sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT MAX(finalized_block_height)::TEXT FROM ccv_chain_statuses WHERE chain_selector = $1`,
		strconv.FormatUint(src, 10),
	).Scan(&height); err != nil {
		return 0, fmt.Errorf("query checkpoint for %s: %w", verifier.ContainerName, err)
	}
	if !height.Valid {
		return 0, errNoCheckpoint
	}

	block, ok := new(big.Int).SetString(height.String, 10)
	if !ok {
		return 0, fmt.Errorf("verifier %s wrote an unparseable checkpoint %q", verifier.ContainerName, height.String)
	}
	return block.Uint64(), nil
}

// processingJobCount counts verification jobs the verifier still holds a lock on. After a message
// has executed this should be zero: a job left in 'processing' means its owner died holding the
// lock and nothing reclaimed it.
func processingJobCount(t *testing.T, ctx context.Context, verifier *committeeverifier.Input) int {
	t.Helper()

	db, err := openVerifierDB(verifier)
	require.NoError(t, err)
	defer db.Close()

	var count int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ccv_task_verifier_jobs WHERE status = 'processing'`).Scan(&count)
	require.NoErrorf(t, err, "count processing jobs for verifier %s", verifier.ContainerName)
	return count
}

// openVerifierDB dials the verifier's Postgres over its host-mapped port. Callers close it; these
// are single-query lookups, so there is no connection to keep around between them.
func openVerifierDB(verifier *committeeverifier.Input) (*sql.DB, error) {
	if verifier.Out == nil || verifier.Out.DBConnectionString == "" {
		return nil, fmt.Errorf("verifier %s has no database connection string", verifier.ContainerName)
	}
	db, err := sql.Open("postgres", verifier.Out.DBConnectionString)
	if err != nil {
		return nil, fmt.Errorf("open verifier %s database: %w", verifier.ContainerName, err)
	}
	return db, nil
}

// requireMineHoldableChain returns the chain's mining controls, skipping the test when the chain
// cannot provide them (anything other than an anvil-backed node).
func requireMineHoldableChain(t *testing.T, ctx context.Context, lib ccv.Lib, selector uint64) cciptestinterfaces.MineHoldableChain {
	t.Helper()

	chains, err := lib.Chains(ctx)
	require.NoError(t, err)

	for _, c := range chains {
		if c.Details.ChainSelector != selector {
			continue
		}
		holdable, ok := c.CCIP17.(cciptestinterfaces.MineHoldableChain)
		if !ok || !holdable.SupportMineHold(ctx) {
			t.Skipf("chain %d cannot control mining; run against an anvil-backed environment", selector)
		}
		return holdable
	}

	t.Fatalf("chain %d not found in environment", selector)
	return nil
}

// chainMiningInterval reports the block interval the chain's node was started with, read back from
// the anvil block-time flag. A test that stops mining restores this value rather than switching the
// node to automining, so later tests see the chain behaving as it did before.
func chainMiningInterval(t *testing.T, setup *chaosSetup, selector uint64) time.Duration {
	t.Helper()

	bc, err := chaos.BlockchainInputForSelector(setup.in, selector)
	require.NoError(t, err)

	params := bc.DockerCmdParamsOverrides
	for i, param := range params {
		if param != "-b" && param != "--block-time" {
			continue
		}
		require.Lessf(t, i+1, len(params), "chain %d has %s with no value", selector, param)
		seconds, err := strconv.Atoi(params[i+1])
		require.NoErrorf(t, err, "chain %d has an unparseable %s value %q", selector, param, params[i+1])
		return time.Duration(seconds) * time.Second
	}
	// No block-time flag means the node mines on demand, which ResumeMining reads as "turn
	// automining back on".
	return 0
}

// executorTransmitterAddresses returns the addresses that sign destination transactions for dst,
// which are the addresses whose nonce gap the accessor's recovery watches.
//
// It resolves them through the executor pool topology rather than taking the first executor in the
// config. A pool spreads destinations across its executors, so in the default devenv the chain the
// chaos tests pick as destination is served by the second executor, and watching the first would
// mean watching an address that never transacts.
func executorTransmitterAddresses(t *testing.T, setup *chaosSetup, dst uint64) []string {
	t.Helper()

	executors, err := chaos.ExecutorsForDest(setup.in, dst, devenvcommon.DefaultExecutorQualifier)
	require.NoError(t, err)

	var addresses []string
	for _, exec := range executors {
		reg, err := chainreg.GetRegistry().Get(exec.ChainFamily)
		if err != nil || reg.ExecutorInfo == nil {
			continue
		}
		if addr := reg.ExecutorInfo.ExecutorTransmitterAddress(exec.Out.BootstrapKeys); addr != "" {
			addresses = append(addresses, addr)
		}
	}
	require.NotEmptyf(t, addresses, "no executor transmitter address found for destination chain %d", dst)
	return addresses
}

// waitForInFlightTransaction blocks until one of the transmitters has a transaction accepted into
// the mempool but not mined, which with mining held means an executor has broadcast.
func waitForInFlightTransaction(
	t *testing.T,
	ctx context.Context,
	holdable cciptestinterfaces.MineHoldableChain,
	transmitters []string,
) {
	t.Helper()

	deadline := time.Now().Add(inFlightWaitTimeout)
	for {
		var state []string
		for _, transmitter := range transmitters {
			pending, latest, err := holdable.PendingAndLatestNonce(ctx, transmitter)
			require.NoError(t, err, "read transmitter nonces")
			if pending > latest {
				t.Logf("executor %s has %d transaction(s) in flight (latest=%d pending=%d)",
					transmitter, pending-latest, latest, pending)
				return
			}
			state = append(state, fmt.Sprintf("%s latest=%d pending=%d", transmitter, latest, pending))
		}
		if time.Now().After(deadline) {
			t.Fatalf("no executor broadcast a transaction within %s (%s)",
				inFlightWaitTimeout, strings.Join(state, "; "))
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context canceled while waiting for an in-flight transaction: %v", ctx.Err())
		case <-time.After(inFlightPollInterval):
		}
	}
}
