package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/chaos"
)

const (
	// inFlightPollInterval is how often the test checks whether the executor has put a transaction
	// into the destination mempool.
	inFlightPollInterval = 500 * time.Millisecond
	// inFlightWaitTimeout bounds the wait for that transaction. It has to cover the executor
	// noticing the message through the indexer and aggregator, not just the send.
	inFlightWaitTimeout = 4 * time.Minute
	// executorOutageDuration is how long the executor stays down. Pumba restarts it afterwards.
	executorOutageDuration = 20 * time.Second
	// recoveryTimeout bounds how long execution may take after the executor comes back. It has to
	// cover the accessor's orphan recovery grace period plus a re-execution.
	recoveryTimeout = 6 * time.Minute
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
// The transaction is held in flight deliberately rather than by racing block production: automining
// on the destination is turned off so the executor's transaction sits in the mempool for as long as
// the test needs, which is the only way to make the kill land in the right window every run.
//
// Requires a destination chain that can hold mining (anvil). Skips otherwise.
func TestChaos_ExecutorRestartWithInFlightTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	holdable, transmitter := resolveMineHoldableDestination(t, ctx, lib, setup, dst)

	// Hold mining on the destination so the executor's transaction stays in the mempool. Restoring
	// it is registered before anything else can fail, so a mid-test failure does not leave the
	// environment frozen for later tests.
	require.NoError(t, holdable.SetAutomine(ctx, false), "stop automining on destination")
	t.Cleanup(func() {
		if err := holdable.SetAutomine(context.WithoutCancel(ctx), true); err != nil {
			t.Logf("failed to restore automining on destination: %v", err)
		}
	})

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

	// Wait for the executor to actually broadcast. Killing it before this point would test an
	// ordinary restart, not a restart with work in flight, and the test would pass without
	// exercising recovery at all.
	waitForInFlightTransaction(t, ctx, holdable, transmitter)

	executorTargets, err := chaos.ExecutorContainers(setup.in, devenvcommon.DefaultExecutorQualifier)
	require.NoError(t, err)
	cleanup, err := chaos.InjectOutage(ctx, &chaos.OutageSpec{
		Duration: executorOutageDuration,
		Targets:  executorTargets,
	})
	require.NoError(t, err, "stop the executor")
	t.Cleanup(cleanup)

	// Let mining resume while the executor is down, so the orphan's fate (mined, or still pending
	// when the executor returns) is decided by the chain rather than by test timing.
	require.NoError(t, holdable.SetAutomine(ctx, true), "resume automining on destination")

	// Pumba restarts the container after the outage; the assertion below covers the restart, the
	// accessor's orphan recovery, and any re-execution the executor decides to do.
	execCtx, cancel := context.WithTimeout(ctx, recoveryTimeout)
	defer cancel()
	_, err = v3Dst.ConfirmExecOnDest(execCtx, src, messageKey, recoveryTimeout)
	require.NoError(t, err, "message should execute after the executor restarts with a transaction in flight")
}

// resolveMineHoldableDestination returns the destination chain's mine-hold controls and the
// executor's transmitter address on it, skipping the test when the chain cannot hold mining.
func resolveMineHoldableDestination(
	t *testing.T,
	ctx context.Context,
	lib ccv.Lib,
	setup *chaosSetup,
	dst uint64,
) (cciptestinterfaces.MineHoldableChain, string) {
	t.Helper()

	chains, err := lib.Chains(ctx)
	require.NoError(t, err)

	for _, c := range chains {
		if c.Details.ChainSelector != dst {
			continue
		}
		holdable, ok := c.CCIP17.(cciptestinterfaces.MineHoldableChain)
		if !ok || !holdable.SupportMineHold(ctx) {
			t.Skip("destination chain cannot hold mining; run against an anvil-backed environment")
		}
		return holdable, executorTransmitterAddress(t, setup, dst)
	}

	t.Fatalf("destination chain %d not found in environment", dst)
	return nil, ""
}

// executorTransmitterAddress finds the address the executor signs destination transactions with,
// which is the address whose nonce gap the accessor's recovery watches.
func executorTransmitterAddress(t *testing.T, setup *chaosSetup, dst uint64) string {
	t.Helper()

	for _, exec := range setup.in.Executor {
		reg, err := chainreg.GetRegistry().Get(exec.ChainFamily)
		if err != nil || reg.ExecutorInfo == nil {
			continue
		}
		if addr := reg.ExecutorInfo.ExecutorTransmitterAddress(exec.Out.BootstrapKeys); addr != "" {
			return addr
		}
	}

	t.Fatalf("no executor transmitter address found for destination chain %d", dst)
	return ""
}

// waitForInFlightTransaction blocks until the transmitter has a transaction accepted into the
// mempool but not mined, which with automining off means the executor has broadcast.
func waitForInFlightTransaction(
	t *testing.T,
	ctx context.Context,
	holdable cciptestinterfaces.MineHoldableChain,
	transmitter string,
) {
	t.Helper()

	deadline := time.Now().Add(inFlightWaitTimeout)
	for {
		pending, latest, err := holdable.PendingAndLatestNonce(ctx, transmitter)
		require.NoError(t, err, "read transmitter nonces")
		if pending > latest {
			t.Logf("executor has %d transaction(s) in flight (latest=%d pending=%d)", pending-latest, latest, pending)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("executor did not broadcast a transaction within %s (latest=%d pending=%d)",
				inFlightWaitTimeout, latest, pending)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context canceled while waiting for an in-flight transaction: %v", ctx.Err())
		case <-time.After(inFlightPollInterval):
		}
	}
}
