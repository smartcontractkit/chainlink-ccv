package e2e

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/adapters" // register the EVM 1.6.0 curse adapter
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccip/deployment/fastcurse"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// TestE2EReorg tests that messages sent in different orders
// before and after a reorg are correctly verified after finality is reached.
// IMPORTANT: Need to run this test against an env that has source chain with auto mining.
// Run `just rebuild-all "env.toml,env-src-auto-mine.toml"` before running this test.
func TestE2EReorg(t *testing.T) {
	ctx := ccv.Plog.WithContext(context.Background())
	l := zerolog.Ctx(ctx)
	smokeTestConfig := GetSmokeTestConfig()
	lib, err := ccv.NewLibFromCCVEnv(l, smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	cldfEnv, err := lib.CLDFEnvironment()
	require.NoError(t, err)
	require.NotNil(t, cldfEnv)

	// TODO: put LoadOutput behind the lib.
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 3, "expected 3 chains for this test in the environment")

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	defaultAggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	require.NotNil(t, defaultAggregatorClient)
	t.Cleanup(func() {
		defaultAggregatorClient.Close()
	})

	// Create chain status manager to read from the verifier's PostgreSQL database
	chainStatusLggr, err := logger.New()
	require.NoError(t, err)
	// Build connection string from input (Out may not be populated when loading from cached config)
	verifierDBConnectionString := in.Verifier[0].Out.DBConnectionString
	chainStatusDB, err := sqlx.Connect("postgres", verifierDBConnectionString)
	require.NoError(t, err, "should be able to connect to verifier's postgres database")

	chainStatusStore := chainstatus.NewPostgresChainStatusStore(chainStatusDB, chainStatusLggr)
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusStore, in.Verifier[0].Out.VerifierID)
	t.Cleanup(func() {
		_ = chainStatusDB.Close()
	})

	srcImpl := chains[0]
	destImpl := chains[1]
	dest2Impl := chains[2]

	curseAdapter, ok := fastcurse.GetCurseRegistry().GetCurseAdapter(chain_selectors.FamilyEVM, semver.MustParse("1.6.0"))
	require.True(t, ok)
	require.NotNil(t, curseAdapter)
	require.NoError(t, curseAdapter.Initialize(*cldfEnv, srcImpl.ChainSelector()))

	srcSelector := srcImpl.Details.ChainSelector
	destSelector := destImpl.Details.ChainSelector
	destSelector2 := dest2Impl.Details.ChainSelector

	// The source chain must support driving block progression and
	// snapshot/revert from the test. Skip cleanly if the concrete impl
	// doesn't satisfy the interfaces (e.g. a real testnet RPC).
	progressable, ok := srcImpl.CCIP17.(cciptestinterfaces.ProgressableChain)
	if !ok {
		t.Skip("source chain does not implement ProgressableChain; skipping finality/reorg/curse tests")
	}
	reorgable, ok := srcImpl.CCIP17.(cciptestinterfaces.ReorgableChain)
	if !ok {
		t.Skip("source chain does not implement ReorgableChain; skipping finality/reorg/curse tests")
	}
	require.True(t, progressable.SupportManualBlockProgress(ctx),
		"source chain must support manual block progression with automining enabled; run with env-src-auto-mine.toml")
	require.True(t, reorgable.SupportReorgs(ctx),
		"source chain must support snapshot/revert for reorg tests")

	advanceBlocks := func(numBlocks int) {
		require.NoError(t, progressable.AdvanceBlocks(ctx, numBlocks), "advance %d blocks", numBlocks)
		time.Sleep(3 * time.Second) // Give the verifier time to process
	}
	snapshot := func() cciptestinterfaces.SnapshotID {
		id, err := reorgable.Snapshot(ctx)
		require.NoError(t, err, "take snapshot")
		return id
	}
	revert := func(id cciptestinterfaces.SnapshotID) {
		require.NoError(t, reorgable.Revert(ctx, id), "revert to snapshot %s", id)
	}

	receiver := mustGetEOAReceiverAddress(t, destImpl)

	executorAddr := getContractAddress(t, in, srcSelector,
		datastore.ContractType(sequences.ExecutorProxyType),
		proxy.Deploy.Version(),
		devenvcommon.DefaultExecutorQualifier,
		"executor")

	ccvAddr := getContractAddress(t, in, srcSelector,
		datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
		versioned_verifier_resolver.Version.String(),
		devenvcommon.DefaultCommitteeVerifierQualifier,
		"committee verifier proxy")

	// Get receiver for destSelector2 (chain2)
	receiver2 := mustGetEOAReceiverAddress(t, dest2Impl)

	// Default message options for sending CCIP messages
	defaultMessageOptions := cciptestinterfaces.MessageOptions{
		Executor: executorAddr,
		CCVs: []protocol.CCV{
			{
				CCVAddress: ccvAddr,
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
	}
	defaultMessageVersion := uint8(3)

	// Helper to create MessageFields from receiver address and data string
	newMessageFields := func(recv protocol.UnknownAddress, data string) cciptestinterfaces.MessageFields {
		return cciptestinterfaces.MessageFields{
			Receiver: recv,
			Data:     []byte(data),
		}
	}

	// Helper to log a sent message event
	logSentMessage := func(event cciptestinterfaces.MessageSentEvent, description string) {
		l.Info().
			Str("messageID", fmt.Sprintf("%x", event.MessageID[:])).
			Int("seqNumber", int(event.Message.SequenceNumber)).
			Msgf("📨 %s", description)
	}

	// Helper function to verify a message exists in aggregator (with polling)
	verifyMessageExists := func(messageID [32]byte, description string) {
		waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
		defer waitCancel()
		result, err := defaultAggregatorClient.WaitForVerifierResultForMessage(waitCtx, messageID, 500*time.Millisecond)
		require.NoError(t, err, "%s should be found after finality", description)
		l.Info().
			Str("messageID", fmt.Sprintf("%x", messageID[:])).
			Str("verifierResult", fmt.Sprintf("%x", result)).
			Msgf("✅ %s verified in aggregator after finality", description)
	}

	// Helper function to verify a message does NOT exist in aggregator
	verifyMessageNotExists := func(messageID [32]byte, description string) {
		_, err := defaultAggregatorClient.GetVerifierResultForMessage(ctx, messageID)
		require.Error(t, err, "%s should not be found in aggregator", description)
	}

	t.Run("simple reorg with message ordering", func(t *testing.T) {
		// 1/5 Blocks
		advanceBlocks(verifier.ConfirmationDepth / 5)
		snapshotID := snapshot()
		l.Info().Msg("💾 Snapshot created (2 blocks before messages)")
		// 2/5 Blocks
		advanceBlocks(verifier.ConfirmationDepth / 5)

		event1, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 1"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message 1")
		msg1IDBeforeReorg := event1.MessageID

		event2, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 2"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event2, "Sending message 2")
		msg2IDBeforeReorg := event2.MessageID

		// 3/5 Blocks + 2 (for above messages to be mined)
		advanceBlocks(verifier.ConfirmationDepth / 5)

		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot")
		revert(snapshotID)

		advanceBlocks(1)

		event3, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 2"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event3, "Sending message 2 first (swapped order)")
		msg2IDAfterReorg := event3.MessageID

		event4, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 1"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event4, "Sending message 1 second (swapped order)")
		msg1IDAfterReorg := event4.MessageID

		event5, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 3"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event5, "Sending a new msg that wasn't sent pre reorg")
		msg3ID := event5.MessageID

		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks to cross finality threshold")
		advanceBlocks(verifier.ConfirmationDepth + 5)

		// Verify all messages are found in aggregator after finality
		l.Info().Msg("🔍 Verifying messages are in aggregator (after finality)")
		verifyMessageExists(msg2IDAfterReorg, "Message 2 after reorg")
		verifyMessageExists(msg1IDAfterReorg, "Message 1 after reorg")
		verifyMessageExists(msg3ID, "Message 3 after reorg")

		l.Info().Msg("🔍 Checking messages are NOT in aggregator (before reorg)")
		verifyMessageNotExists(msg1IDBeforeReorg, "Message 1 before reorg")
		verifyMessageNotExists(msg2IDBeforeReorg, "Message 2 before reorg")
		l.Info().Msg("✅ Confirmed messages not in aggregator")

		l.Info().
			Msg("✨ Test completed: Messages sent in swapped order after reorg and verified after finality")
	})

	t.Run("curse lane verifier side", func(t *testing.T) {
		// Set up log asserter to verify message is dropped after curse
		lokiURL := DefaultLokiURL
		logAssertLogger := l.With().Str("component", "log-asserter").Logger()
		logAssert := logasserter.New(lokiURL, logAssertLogger)

		err := logAssert.StartStreaming(ctx, []logasserter.LogStage{
			logasserter.MessageReachedVerifier(),
			logasserter.MessageDroppedInVerifier(),
		})
		require.NoError(t, err, "should be able to start log streaming")
		t.Cleanup(func() {
			logAssert.StopStreaming()
		})

		event1, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 1"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message 1")
		msg1ID := event1.MessageID

		advanceBlocks(verifier.ConfirmationDepth / 5)

		l.Info().Msg("Applying lane curse between chain0 and chain1 (before message gets picked up by verifier)")
		// normally it's bidirectional, for the sake of the test we only curse one direction
		curseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)

		l.Info().Msg("🔍 Asserting message reached verifier but was dropped due to curse")
		assertCtx, assertCancel := context.WithTimeout(ctx, 100*time.Second)
		defer assertCancel()

		_, err = logAssert.WaitForStage(assertCtx, msg1ID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message should be dropped in verifier due to curse")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1ID[:])).
			Msg("✅ Confirmed message was dropped in verifier after curse")

		// Verify the message is NOT in the aggregator (it was dropped, not processed)
		verifyMessageNotExists(msg1ID, "Cursed message should not be in aggregator")

		_, err = srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "cursed lane message"), defaultMessageOptions, defaultMessageVersion)
		require.Error(t, err, "should not be able to send message on cursed lane")

		// Verify uncursed lane still works (srcSelector -> destSelector2)
		l.Info().Msg("🔍 Verifying uncursed lane (chain0 -> chain2) still works")
		event2, err := srcImpl.SendMessage(ctx, destSelector2, newMessageFields(receiver2, "uncursed lane message"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event2, "Verifying uncursed lane (to chain2)")

		advanceBlocks(verifier.ConfirmationDepth + 5)
		verifyMessageExists(event2.MessageID, "Uncursed lane message")
		l.Info().Msg("✅ Confirmed uncursed lane still works")

		// Uncurse the lane
		l.Info().Msg("🔓 Uncursing the cursed lane")
		uncurseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)

		// Send a message again on the previously cursed lane to verify it works now
		event3, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message 2 after uncurse"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event3, "Sending message 2 after uncurse")

		advanceBlocks(verifier.ConfirmationDepth + 5)
		verifyMessageExists(event3.MessageID, "Message 2 after uncurse")

		l.Info().Msg("✨ Test completed: Lane curse verified - message dropped, uncursed lane worked")
	})

	t.Run("global curse verifier side", func(t *testing.T) {
		// Set up log asserter to verify messages are dropped after global curse
		lokiURL := DefaultLokiURL
		logAssertLogger := l.With().Str("component", "log-asserter").Logger()
		logAssert := logasserter.New(lokiURL, logAssertLogger)

		err := logAssert.StartStreaming(ctx, []logasserter.LogStage{
			logasserter.MessageDroppedInVerifier(),
		})
		require.NoError(t, err, "should be able to start log streaming")
		t.Cleanup(func() {
			logAssert.StopStreaming()
		})

		// Send messages to BOTH destinations before applying global curse
		l.Info().Msg("📨 Sending messages to chain1 and chain2 before global curse")

		// Message to destSelector (chain1)
		event1, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "global curse test msg to chain1"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message to chain1")
		msg1ID := event1.MessageID

		// Message to destSelector2 (chain2)
		event2, err := srcImpl.SendMessage(ctx, destSelector2, newMessageFields(receiver2, "global curse test msg to chain2"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event2, "Sending message to chain2")
		msg2ID := event2.MessageID

		advanceBlocks(verifier.ConfirmationDepth / 5)

		l.Info().Msg("🌐 Applying GLOBAL curse to source chain (affects ALL lanes from this chain)")
		curseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), 0, true)

		l.Info().Msg("🔍 Asserting BOTH messages are dropped due to global curse")
		assertCtx, assertCancel := context.WithTimeout(ctx, 100*time.Second)
		defer assertCancel()

		// Verify message to chain1 is dropped
		_, err = logAssert.WaitForStage(assertCtx, msg1ID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message to chain1 should be dropped due to global curse")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1ID[:])).
			Msg("✅ Confirmed message to chain1 was dropped due to global curse")

		// Verify message to chain2 is dropped
		_, err = logAssert.WaitForStage(assertCtx, msg2ID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message to chain2 should be dropped due to global curse")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg2ID[:])).
			Msg("✅ Confirmed message to chain2 was dropped due to global curse")

		// Verify BOTH messages are NOT in the aggregator
		verifyMessageNotExists(msg1ID, "Globally cursed message to chain1 should not be in aggregator")
		verifyMessageNotExists(msg2ID, "Globally cursed message to chain2 should not be in aggregator")

		// Uncurse the chain
		l.Info().Msg("🔓 Removing global curse from source chain")
		uncurseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), 0, true)

		// Send new messages after uncurse to verify both lanes work
		l.Info().Msg("📨 Sending messages after global uncurse to verify lanes work")
		event3, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "post-global-uncurse msg to chain1"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event3, "Sending message to chain1 after uncurse")

		advanceBlocks(verifier.ConfirmationDepth + 5)
		verifyMessageExists(event3.MessageID, "Message to chain1 after global uncurse")

		event4, err := srcImpl.SendMessage(ctx, destSelector2, newMessageFields(receiver2, "post-global-uncurse msg to chain2"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event4, "Sending message to chain2 after uncurse")

		advanceBlocks(verifier.ConfirmationDepth + 5)
		verifyMessageExists(event4.MessageID, "Message to chain2 after global uncurse")

		l.Info().Msg("✨ Test completed: Global curse verified - both lanes blocked, then unblocked after uncurse")
	})

	t.Run("lane curse blocks one lane while peer lane keeps verifying traffic", func(t *testing.T) {
		curseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)
		t.Cleanup(func() {
			uncurseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)
		})

		_, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "blocked lane msg"), defaultMessageOptions, defaultMessageVersion)
		require.Error(t, err, "send to cursed lane (chain0 -> chain1) should fail")

		uncursedMsgIDs := make([][32]byte, 0, 3)
		for i := range 3 {
			evt, sendErr := srcImpl.SendMessage(ctx, destSelector2, newMessageFields(receiver2, fmt.Sprintf("uncursed lane msg %d", i)), defaultMessageOptions, defaultMessageVersion)
			require.NoError(t, sendErr, "send to uncursed lane (chain0 -> chain2) should succeed")
			uncursedMsgIDs = append(uncursedMsgIDs, evt.MessageID)
		}

		advanceBlocks(verifier.ConfirmationDepth + 5)
		for i, msgID := range uncursedMsgIDs {
			verifyMessageExists(msgID, fmt.Sprintf("Uncursed lane message %d", i))
		}

		_, err = srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "still blocked"), defaultMessageOptions, defaultMessageVersion)
		require.Error(t, err, "cursed lane should still be blocked after uncursed lane traffic")
	})

	t.Run("curse on dest2 lane does not block dest1 lane", func(t *testing.T) {
		curseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector2, false)
		t.Cleanup(func() {
			uncurseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector2, false)
		})

		_, err = srcImpl.SendMessage(ctx, destSelector2, newMessageFields(receiver2, "blocked dest2 msg"), defaultMessageOptions, defaultMessageVersion)
		require.Error(t, err, "send to cursed lane (chain0 -> chain2) should fail")

		evt, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "dest1 msg while dest2 cursed"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		advanceBlocks(verifier.ConfirmationDepth + 5)
		verifyMessageExists(evt.MessageID, "dest1 message while dest2 cursed")
	})

	t.Run("dropped message under curse can be replayed via CLI checkpoint rewind", func(t *testing.T) {
		require.GreaterOrEqual(t, len(in.Verifier), 1)
		require.NotNil(t, in.Verifier[0].Out)
		verifierID := in.Verifier[0].Out.VerifierID
		require.NotEmpty(t, verifierID)

		// Every verifier with the same VerifierID belongs to the same committee. The aggregator
		// only returns a result once every member has signed, so every committee member's DB
		// checkpoint must be rewound and process restarted.
		var members []*verifiercli.Client
		for _, v := range in.Verifier {
			if v.Out == nil || v.Out.VerifierID != verifierID {
				continue
			}
			require.NotEmpty(t, v.Out.ContainerName, "verifier container name must be set")
			members = append(members, verifiercli.NewClient(v.Out.ContainerName))
		}
		committee, err := verifiercli.NewCommitteeClient(verifierID, members...)
		require.NoError(t, err)

		// A prior iteration may have left a committee process paused by pkill -STOP;
		// resume now and again on cleanup so we don't leak a paused process.
		committee.ResumeAllBestEffort(ctx)
		t.Cleanup(func() { committee.ResumeAllBestEffort(ctx) })

		logAssert := logasserter.New(DefaultLokiURL, l.With().Str("component", "log-asserter").Logger())
		require.NoError(t, logAssert.StartStreaming(ctx, []logasserter.LogStage{
			logasserter.MessageReachedVerifier(),
			logasserter.MessageDroppedInVerifier(),
		}))
		t.Cleanup(logAssert.StopStreaming)

		// Send a message and wait for it to enter the verifier's pending queue before cursing.
		// Doing so makes the subsequent drop deterministic once the curse detector catches up.
		event, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "curse recovery msg"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event, "Message to be dropped during curse")
		droppedMsgID := event.MessageID

		advanceBlocks(verifier.ConfirmationDepth / 5)
		reachedCtx, reachedCancel := context.WithTimeout(ctx, 60*time.Second)
		defer reachedCancel()
		_, err = logAssert.WaitForStage(reachedCtx, droppedMsgID, logasserter.MessageReachedVerifier())
		require.NoError(t, err, "message should reach verifier pending queue before curse is applied")

		curseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)
		t.Cleanup(func() {
			uncurseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)
		})

		dropCtx, dropCancel := context.WithTimeout(ctx, 60*time.Second)
		defer dropCancel()
		_, err = logAssert.WaitForStage(dropCtx, droppedMsgID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message should be dropped in verifier due to curse")
		verifyMessageNotExists(droppedMsgID, "Dropped message should not be in aggregator")

		// Advance the finalized checkpoint well past the dropped message block while the curse is
		// still active. Without this, the verifier would keep re-fetching the log each poll, and
		// lifting the curse alone would verify the message - masking the need for a CLI rewind.
		advanceBlocks(verifier.ConfirmationDepth*3 + 30)
		verifyMessageNotExists(droppedMsgID, "Dropped message should not reach aggregator while cursed")

		uncurseSelector(t, cldfEnv, curseAdapter, srcImpl.ChainSelector(), destSelector, false)

		// With the checkpoint past the message block, uncursing on-chain alone must not replay it.
		advanceBlocks(verifier.ConfirmationDepth + 5)
		time.Sleep(10 * time.Second)
		verifyMessageNotExists(droppedMsgID, "Dropped message should not reappear after uncurse alone")

		require.NoError(t, committee.RewindFinalizedHeight(ctx,
			verifiercli.FormatChainSelector(srcSelector), verifiercli.FormatBlockHeight(0)),
			"rewind committee finalized height")

		// Push finality well past the dropped message block again so the fresh rescan that starts
		// at block 1 can mark the message ready for verification immediately.
		advanceBlocks(verifier.ConfirmationDepth*2 + 10)

		waitCtx, waitCancel := context.WithTimeout(ctx, 120*time.Second)
		defer waitCancel()
		_, err = defaultAggregatorClient.WaitForVerifierResultForMessage(waitCtx, droppedMsgID, 1*time.Second)
		require.NoError(t, err, "dropped message should be reprocessed after CLI checkpoint rewind and restart")
	})

	t.Run("reorg with faster-than-finality message", func(t *testing.T) {
		// This test verifies that when a message with custom (faster) finality is affected by a reorg,
		// the verifier will wait for full finalization before processing it, ignoring the custom finality.
		//
		// Timeline:
		// 1. Send message with custom finality (faster than ConfirmationDepth)
		// 2. Immediately trigger reorg BEFORE custom finality is met (so message isn't verified yet)
		// 3. Re-send the message (same seqNum since we reverted)
		// 4. Mine enough blocks for custom finality to be met
		// 5. Verify message is NOT verified (because seqNum was tracked as reorged)
		// 6. Mine to full finalization
		// 7. Verify message IS verified after finalization

		// Custom finality: 5 blocks (much faster than ConfirmationDepth)
		const customFinality protocol.Finality = 5
		customFinalityMessageOptions := cciptestinterfaces.MessageOptions{
			FinalityConfig: customFinality,
			Executor:       executorAddr,
			CCVs: []protocol.CCV{
				{
					CCVAddress: ccvAddr,
					Args:       []byte{},
					ArgsLen:    0,
				},
			},
		}

		// Create snapshot before sending message
		snapshotID := snapshot()
		l.Info().Str("snapshotID", string(snapshotID)).Msg("💾 Snapshot created before sending custom finality message")

		// Send message with custom finality
		event1, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "fast finality message"), customFinalityMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message with custom finality")
		msgIDBeforeReorg := event1.MessageID

		// Mine only 1-2 blocks - NOT enough for custom finality to be met
		// This ensures the verifier hasn't verified the message yet
		l.Info().Int("blocks", 2).Msg("⛏️  Mining just 2 blocks (not enough for custom finality)")
		advanceBlocks(2)

		// Trigger reorg IMMEDIATELY by reverting to snapshot (before custom finality is met)
		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot (before custom finality met)")
		revert(snapshotID)

		// Mine 1 block to advance chain
		advanceBlocks(1)
		// Give the verifier time to process
		time.Sleep(3 * time.Second)

		// Re-send the message (will have same seqNum since we reverted)
		event2, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "fast finality message after reorg"), customFinalityMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event2, "Sending message with custom finality after reorg")
		msgIDAfterReorg := event2.MessageID

		// Mine enough blocks for custom finality to be met (but NOT full finalization)
		blocksToMineForCustomFinality := int(customFinality) + 1
		l.Info().Int("blocks", blocksToMineForCustomFinality).Msg("⛏️  Mining blocks for custom finality")
		advanceBlocks(blocksToMineForCustomFinality)

		// At this point, custom finality is met but full finalization is not
		// The message should NOT be in the aggregator yet because its seqNum was tracked as reorged

		// Give the verifier a moment to process (if it were going to verify with custom finality)
		time.Sleep(3 * time.Second)

		// Verify message is NOT in aggregator yet (reorg tracking should prevent early verification)
		l.Info().Msg("🔍 Verifying message is NOT in aggregator yet (custom finality ignored due to reorg)")
		verifyMessageNotExists(msgIDAfterReorg, "Message after reorg should not be verified yet")
		verifyMessageNotExists(msgIDBeforeReorg, "Message before reorg should not be verified")

		// Now mine to full finalization
		remainingBlocks := verifier.ConfirmationDepth - blocksToMineForCustomFinality + 5
		l.Info().Int("blocks", remainingBlocks).Msg("⛏️  Mining remaining blocks to reach full finalization")
		advanceBlocks(remainingBlocks)

		// Now the message should be verified (after full finalization)
		l.Info().Msg("🔍 Verifying message is in aggregator after full finalization")
		verifyMessageExists(msgIDAfterReorg, "Message after reorg should be verified after finalization")

		// Original message should still not exist (it was reorged out)
		verifyMessageNotExists(msgIDBeforeReorg, "Message before reorg should not be in aggregator")

		l.Info().Msg("✨ Test completed: Message with custom finality waited for full finalization after reorg")
	})

	t.Run("reorg after message already verified", func(t *testing.T) {
		// This test verifies that when a message with custom finality is ALREADY verified and sent
		// to the aggregator, then a reorg removes it, the replacement message with the same seqNum
		// must still wait for full finalization before being verified again.
		//
		// This tests the "double execution bound" scenario and specifically the sentTasks tracking
		// in addToPendingQueueHandleReorg.
		//
		// Timeline:
		// 1. Send message with custom finality
		// 2. Mine blocks until custom finality met
		// 3. Wait for message to be verified (first execution - unavoidable)
		// 4. Trigger reorg that removes the message
		// 5. Re-send message (same seqNum)
		// 6. Verify NEW message waits for full finalization (reorg tracking from sentTasks)

		// Custom finality: 5 blocks (much faster than ConfirmationDepth)
		const customFinality protocol.Finality = 5
		customFinalityMessageOptions := cciptestinterfaces.MessageOptions{
			FinalityConfig: customFinality,
			Executor:       executorAddr,
			CCVs: []protocol.CCV{
				{
					CCVAddress: ccvAddr,
					Args:       []byte{},
					ArgsLen:    0,
				},
			},
		}

		// Create snapshot before sending message
		snapshotID := snapshot()
		l.Info().Str("snapshotID", string(snapshotID)).Msg("💾 Snapshot created before sending message")

		// Send message with custom finality
		event1, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "message to be verified then reorged"), customFinalityMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message with custom finality (will be verified first)")
		msgIDFirstExecution := event1.MessageID

		// Mine enough blocks for custom finality to be met
		blocksToMineForCustomFinality := int(customFinality) + 1
		l.Info().Int("blocks", blocksToMineForCustomFinality).Msg("⛏️  Mining blocks for custom finality")
		advanceBlocks(blocksToMineForCustomFinality)

		// Wait for the message to be verified (first execution)
		l.Info().Msg("⏳ Waiting for first message to be verified...")
		_, err = defaultAggregatorClient.WaitForVerifierResultForMessage(ctx, msgIDFirstExecution, 500*time.Millisecond)
		require.NoError(t, err, "first message should be verified (this is the unavoidable first execution)")
		l.Info().Msg("✅ First message verified (first execution complete)")

		// Now trigger reorg by reverting to snapshot (removes the verified message from chain)
		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot (after first verification)")
		revert(snapshotID)

		// Mine 1 block to advance chain
		advanceBlocks(1)
		// Give the verifier time to process
		time.Sleep(3 * time.Second)

		// Re-send the message (will have same seqNum since we reverted)
		event2, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "replacement message after reorg"), customFinalityMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event2, "Sending replacement message after reorg")
		msgIDSecondExecution := event2.MessageID

		// The messageIDs should be different (different message content)
		require.NotEqual(t, msgIDFirstExecution, msgIDSecondExecution, "message IDs should differ due to different content")

		// Mine enough blocks for custom finality to be met (but NOT full finalization)
		l.Info().Int("blocks", blocksToMineForCustomFinality).Msg("⛏️  Mining blocks for custom finality again")
		advanceBlocks(blocksToMineForCustomFinality)

		// Give the verifier time to process
		time.Sleep(3 * time.Second)

		// The NEW message should NOT be verified yet because:
		// - The verifier detected that the first message (from sentTasks) is no longer in the chain
		// - The seqNum was tracked as reorged
		// - The new message with that seqNum must wait for full finalization
		l.Info().Msg("🔍 Verifying replacement message is NOT in aggregator yet (reorg tracking from sentTasks)")
		verifyMessageNotExists(msgIDSecondExecution, "Replacement message should not be verified yet - must wait for finalization")

		// Now mine to full finalization
		remainingBlocks := verifier.ConfirmationDepth - blocksToMineForCustomFinality + 5
		l.Info().Int("blocks", remainingBlocks).Msg("⛏️  Mining remaining blocks to reach full finalization")
		advanceBlocks(remainingBlocks)

		// Now the replacement message should be verified (after full finalization)
		l.Info().Msg("🔍 Verifying replacement message is in aggregator after full finalization")
		verifyMessageExists(msgIDSecondExecution, "Replacement message should be verified after full finalization")

		l.Info().Msg("✨ Test completed: Replacement message waited for full finalization after reorg (sentTasks tracking)")
	})

	t.Run("finality violation", func(t *testing.T) {
		// Log the source chain selector for verification
		l.Info().Uint64("srcSelector", srcSelector).Msg("Source chain selector for finality violation test")

		l.Info().Msg("💾 Creating initial snapshot before mining blocks")
		snapshotID := snapshot()
		l.Info().Str("snapshotID", string(snapshotID)).Msg("✅ Initial snapshot created")

		l.Info().Msg("📨 Sending pre-violation message")
		event1, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "pre-violation message"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event1, "Sending pre-violation message")
		preViolationMessageID := event1.MessageID

		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks to establish finalized state")
		advanceBlocks(verifier.ConfirmationDepth + 5)
		l.Info().Msg("✅ Finalized state established")

		// Wait for message to be processed and appear in aggregator
		verifyMessageExists(preViolationMessageID, "Pre-violation message")

		l.Info().Msg("Sending message to be dropped once finality violation happens")
		event2, err := srcImpl.SendMessage(ctx, destSelector, newMessageFields(receiver, "toBeDropped message"), defaultMessageOptions, defaultMessageVersion)
		require.NoError(t, err)
		logSentMessage(event2, "Sending toBeDropped message")
		toBeDroppedMessageID := event2.MessageID

		l.Info().Msg("⚠️  Triggering finality violation by reverting to initial snapshot")
		revert(snapshotID)
		l.Info().Msg("✅ Reverted to initial snapshot (deep reorg past finalized blocks)")
		// Mine some blocks to give system opportunity to process (if it were working)
		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks after revert")
		advanceBlocks(verifier.ConfirmationDepth + 5)
		verifyMessageNotExists(toBeDroppedMessageID, "Post-violation message")

		l.Info().Msg("🔍 Verifying chain status in verifier's local storage...")

		require.Eventually(t, func() bool {
			statuses, err := chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{protocol.ChainSelector(srcSelector)})
			require.NoError(t, err, "should be able to read chain status from verifier's database")
			require.Len(t, statuses, 1, "should have one chain status for source chain")

			chainStatus := statuses[protocol.ChainSelector(srcSelector)]
			require.NotNil(t, chainStatus, "chain status should exist")
			require.True(t, chainStatus.Disabled, "chain should be marked as disabled after finality violation")
			require.Equal(t, uint64(0), chainStatus.FinalizedBlockHeight.Uint64(), "finalized block height should be 0 after finality violation")

			l.Info().Msg("✅ Chain status verified in verifier's local storage: chain is disabled with checkpoint 0")

			return true
		}, 3*time.Second, 100*time.Millisecond, "chain status should reflect disabled state after finality violation")

		l.Info().
			Msg("✨ Test completed: Finality violation detected and system stopped processing new messages")
	})

	// a utility test to enable the chain again in the database instead of creating a new env
	t.Run("enable chain", func(t *testing.T) {
		err := chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        protocol.ChainSelector(srcSelector),
				FinalizedBlockHeight: big.NewInt(0),
				Disabled:             false,
			},
		})
		require.NoError(t, err, "should be able to enable chain in database")

		statuses, err := chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{protocol.ChainSelector(srcSelector)})
		require.NoError(t, err, "should be able to read chain status from database")
		require.Len(t, statuses, 1, "should have one chain status for source chain")

		chainStatus := statuses[protocol.ChainSelector(srcSelector)]
		require.NotNil(t, chainStatus, "chain status should exist")
		require.False(t, chainStatus.Disabled, "chain should be enabled")

		l.Info().Msg("✅ Source chain re-enabled in database after being disabled from finality violation")
	})
}

func curseSelector(t *testing.T, env *deployment.Environment, adapter fastcurse.CurseAdapter, chainSelector, subjectChainSelector uint64, globalCurse bool) {
	// re-set the bundle so it doesn't cache previous curses.
	bundle := operations.NewBundle(env.GetContext, env.Logger, operations.NewMemoryReporter())
	env.OperationsBundle = bundle

	curseCS := fastcurse.CurseChangeset(fastcurse.GetCurseRegistry(), changesets.GetRegistry())
	_, err := curseCS.Apply(*env, fastcurse.RMNCurseConfig{
		CurseActions: []fastcurse.CurseActionInput{
			{
				ChainSelector:        chainSelector,
				SubjectChainSelector: subjectChainSelector,
				Version:              semver.MustParse("1.6.0"),
				IsGlobalCurse:        globalCurse,
			},
		},
	})
	require.NoError(t, err)

	// Verify the curse is applied
	if subjectChainSelector != 0 {
		isCursed, err := adapter.IsSubjectCursedOnChain(*env, chainSelector, fastcurse.GenericSelectorToSubject(subjectChainSelector))
		require.NoError(t, err)
		require.True(t, isCursed, "subject should be cursed on chain")
	}
	if globalCurse {
		isCursed, err := adapter.IsSubjectCursedOnChain(*env, chainSelector, fastcurse.GlobalCurseSubject())
		require.NoError(t, err)
		require.True(t, isCursed, "global curse should be active on chain")
	}

	// Wait for the verifier to detect the curse.
	// The verifier is hardcoded to poll every 2 seconds, wait for 3 seconds to be sure.
	time.Sleep(3 * time.Second)
}

func uncurseSelector(t *testing.T, env *deployment.Environment, adapter fastcurse.CurseAdapter, chainSelector, subjectChainSelector uint64, globalCurse bool) {
	// re-set the bundle so it doesn't cache previous uncurses.
	bundle := operations.NewBundle(env.GetContext, env.Logger, operations.NewMemoryReporter())
	env.OperationsBundle = bundle

	uncurseCS := fastcurse.UncurseChangeset(fastcurse.GetCurseRegistry(), changesets.GetRegistry())
	_, err := uncurseCS.Apply(*env, fastcurse.RMNCurseConfig{
		CurseActions: []fastcurse.CurseActionInput{
			{
				ChainSelector:        chainSelector,
				SubjectChainSelector: subjectChainSelector,
				Version:              semver.MustParse("1.6.0"),
				IsGlobalCurse:        globalCurse,
			},
		},
	})
	require.NoError(t, err)

	// Verify the curse is lifted
	if subjectChainSelector != 0 {
		isCursed, err := adapter.IsSubjectCursedOnChain(*env, chainSelector, fastcurse.GenericSelectorToSubject(subjectChainSelector))
		require.NoError(t, err)
		require.False(t, isCursed, "subject should not be cursed on chain")
	}
	if globalCurse {
		isCursed, err := adapter.IsSubjectCursedOnChain(*env, chainSelector, fastcurse.GlobalCurseSubject())
		require.NoError(t, err)
		require.False(t, isCursed, "global curse should not be active on chain")
	}

	// Wait for the verifier to detect the uncurse.
	// The verifier is hardcoded to poll every 2 seconds, wait for 3 seconds to be sure.
	time.Sleep(3 * time.Second)
}
