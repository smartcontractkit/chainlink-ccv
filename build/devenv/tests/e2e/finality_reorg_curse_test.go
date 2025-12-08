package e2e

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// TestE2EReorg tests that messages sent in different orders
// before and after a reorg are correctly verified after finality is reached.
// IMPORTANT: Need to run this test against an env that has source chain with auto mining.
// Run `just rebuild-all "env.toml,env-src-auto-mine.toml"` before running this test.
func TestE2EReorg(t *testing.T) {
	ctx := ccv.Plog.WithContext(context.Background())
	l := zerolog.Ctx(ctx)
	lib, err := ccv.NewLib(l, "../../env-out.toml")
	require.NoError(t, err)

	// TODO: put LoadOutput behind the lib.
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 3, "expected 3 chains for this test in the environment")

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	defaultAggregatorAddr := fmt.Sprintf("127.0.0.1:%d", defaultAggregatorPort(in))

	defaultAggregatorClient, err := ccv.NewAggregatorClient(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		defaultAggregatorAddr)
	require.NoError(t, err)
	require.NotNil(t, defaultAggregatorClient)
	t.Cleanup(func() {
		defaultAggregatorClient.Close()
	})

	// Create authenticated aggregator client for reading chain status
	// Using the same API key/secret as the verifier (configured in env.toml)
	authenticatedAggregatorClient, err := ccv.NewAuthenticatedAggregatorClient(
		zerolog.Ctx(ctx).With().Str("component", "authenticated-aggregator-client").Logger(),
		defaultAggregatorAddr,
		"dev-api-key-verifier-1",
		"dev-secret-verifier-1",
	)
	require.NoError(t, err, "should be able to create authenticated aggregator client")
	t.Cleanup(func() {
		authenticatedAggregatorClient.Close()
	})

	// Get the source and destination chain selectors
	srcImpl := chains[0]
	destImpl := chains[1]
	dest2Impl := chains[2]

	srcSelector := srcImpl.Details.ChainSelector
	destSelector := destImpl.Details.ChainSelector
	destSelector2 := dest2Impl.Details.ChainSelector

	// Get eth client for source chain using HTTP URL
	srcHTTPURL := in.Blockchains[0].Out.Nodes[0].ExternalHTTPUrl
	ethClient, err := ethclient.Dial(srcHTTPURL)
	require.NoError(t, err)

	anvilHelper := NewAnvilRPCHelper(ethClient, *l)

	// Assert that the source chain has auto-mining enabled (instant mining)
	// This test requires auto-mining/instant-mining (no blocks produced periodically without txs) to properly test reorg behavior
	automine, err := anvilHelper.GetAutomine(ctx)
	require.NoError(t, err, "failed to get automine status from source chain")
	require.True(t, automine, "source chain must have auto-mining enabled (instant mining). Run with env-src-auto-mine.toml configuration")
	l.Info().Bool("automine", automine).Msg("✅ Verified source chain has auto-mining enabled")

	receiver := mustGetEOAReceiverAddress(t, destImpl, destSelector)

	executorAddr := getContractAddress(t, in, srcSelector,
		datastore.ContractType(executor.ContractType),
		executor.Deploy.Version(),
		"",
		"executor")

	ccvAddr := getContractAddress(t, in, srcSelector,
		datastore.ContractType(committee_verifier.ResolverProxyType),
		committee_verifier.Deploy.Version(),
		evm.DefaultCommitteeVerifierQualifier,
		"committee verifier proxy")

	// Get receiver for destSelector2 (chain2)
	receiver2 := mustGetEOAReceiverAddress(t, dest2Impl, destSelector2)

	// Default message options for sending CCIP messages
	defaultMessageOptions := cciptestinterfaces.MessageOptions{
		Version:  3,
		Executor: executorAddr,
		CCVs: []protocol.CCV{
			{
				CCVAddress: ccvAddr,
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
	}

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
			Str("messageID", fmt.Sprintf("%x", event.MessageID)).
			Int("seqNumber", int(event.SequenceNumber)).
			Msgf("📨 %s", description)
	}

	// Helper function to verify a message exists in aggregator (with polling)
	verifyMessageExists := func(messageID [32]byte, description string) {
		waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
		defer waitCancel()
		result, err := defaultAggregatorClient.WaitForVerifierResultForMessage(waitCtx, messageID, 500*time.Millisecond)
		require.NoError(t, err, "%s should be found after finality", description)
		l.Info().
			Str("messageID", fmt.Sprintf("%x", messageID)).
			Str("verifierResult", fmt.Sprintf("%x", result)).
			Msgf("✅ %s verified in aggregator after finality", description)
	}

	// Helper function to verify a message does NOT exist in aggregator
	verifyMessageNotExists := func(messageID [32]byte, description string) {
		_, err := defaultAggregatorClient.GetVerifierResultForMessage(ctx, messageID)
		require.Error(t, err, "%s should not be found in aggregator", description)
	}

	//// chainSelectorToSubject converts a chain selector to a bytes16 curse subject.
	chainSelectorToSubject := func(chainSel uint64) [16]byte {
		var result [16]byte
		// Convert the uint64 to bytes and place it in the last 8 bytes of the array
		binary.BigEndian.PutUint64(result[8:], chainSel)
		return result
	}

	// globalCurseSubject returns the global curse constant from RMN specification.
	// If this subject is present in cursed subjects, all lanes involving this chain are cursed.
	globalCurseSubject := func() [16]byte {
		return [16]byte{0: 0x01, 15: 0x01}
	}

	t.Run("simple reorg with message ordering", func(t *testing.T) {
		// 1/5 Blocks
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)
		snapshotID, err := anvilHelper.Snapshot(ctx)
		require.NoError(t, err)
		l.Info().Msg("💾 Snapshot created (2 blocks before messages)")
		// 2/5 Blocks
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)

		event1, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 1"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message 1")
		msg1IDBeforeReorg := event1.MessageID

		event2, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 2"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event2, "Sending message 2")
		msg2IDBeforeReorg := event2.MessageID

		// 3/5 Blocks + 2 (for above messages to be mined)
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)

		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot")
		err = anvilHelper.Revert(ctx, snapshotID)
		require.NoError(t, err)

		anvilHelper.MustMine(ctx, 1)

		event3, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 2"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event3, "Sending message 2 first (swapped order)")
		msg2IDAfterReorg := event3.MessageID

		event4, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 1"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event4, "Sending message 1 second (swapped order)")
		msg1IDAfterReorg := event4.MessageID

		event5, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 3"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event5, "Sending a new msg that wasn't sent pre reorg")
		msg3ID := event5.MessageID

		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks to cross finality threshold")
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)

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

		event1, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 1"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message 1")
		msg1ID := event1.MessageID

		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)

		l.Info().Msg("Applying lane curse between chain0 and chain1 (before message gets picked up by verifier)")
		// normally it's bidirectional, for the sake of the test we only curse one direction
		err = srcImpl.Curse(ctx, srcSelector, [][16]byte{chainSelectorToSubject(destSelector)})
		require.NoError(t, err)

		l.Info().Msg("🔍 Asserting message reached verifier but was dropped due to curse")
		assertCtx, assertCancel := context.WithTimeout(ctx, 100*time.Second)
		defer assertCancel()

		_, err = logAssert.WaitForStage(assertCtx, msg1ID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message should be dropped in verifier due to curse")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1ID)).
			Msg("✅ Confirmed message was dropped in verifier after curse")

		// Verify the message is NOT in the aggregator (it was dropped, not processed)
		verifyMessageNotExists(msg1ID, "Cursed message should not be in aggregator")

		_, err = srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "cursed lane message"), defaultMessageOptions)
		require.Error(t, err, "should not be able to send message on cursed lane")

		// Verify uncursed lane still works (srcSelector -> destSelector2)
		l.Info().Msg("🔍 Verifying uncursed lane (chain0 -> chain2) still works")
		event2, err := srcImpl.SendMessage(ctx, srcSelector, destSelector2, newMessageFields(receiver2, "uncursed lane message"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event2, "Verifying uncursed lane (to chain2)")

		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
		verifyMessageExists(event2.MessageID, "Uncursed lane message")
		l.Info().Msg("✅ Confirmed uncursed lane still works")

		// Uncurse the lane
		l.Info().Msg("🔓 Uncursing the cursed lane")
		err = srcImpl.Uncurse(ctx, srcSelector, [][16]byte{chainSelectorToSubject(destSelector)})
		require.NoError(t, err)

		// Send a message again on the previously cursed lane to verify it works now
		event3, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "message 2 after uncurse"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event3, "Sending message 2 after uncurse")

		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
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
		event1, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "global curse test msg to chain1"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event1, "Sending message to chain1")
		msg1ID := event1.MessageID

		// Message to destSelector2 (chain2)
		event2, err := srcImpl.SendMessage(ctx, srcSelector, destSelector2, newMessageFields(receiver2, "global curse test msg to chain2"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event2, "Sending message to chain2")
		msg2ID := event2.MessageID

		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)

		l.Info().Msg("🌐 Applying GLOBAL curse to source chain (affects ALL lanes from this chain)")
		err = srcImpl.Curse(ctx, srcSelector, [][16]byte{globalCurseSubject()})
		require.NoError(t, err)

		l.Info().Msg("🔍 Asserting BOTH messages are dropped due to global curse")
		assertCtx, assertCancel := context.WithTimeout(ctx, 100*time.Second)
		defer assertCancel()

		// Verify message to chain1 is dropped
		_, err = logAssert.WaitForStage(assertCtx, msg1ID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message to chain1 should be dropped due to global curse")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1ID)).
			Msg("✅ Confirmed message to chain1 was dropped due to global curse")

		// Verify message to chain2 is dropped
		_, err = logAssert.WaitForStage(assertCtx, msg2ID, logasserter.MessageDroppedInVerifier())
		require.NoError(t, err, "message to chain2 should be dropped due to global curse")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg2ID)).
			Msg("✅ Confirmed message to chain2 was dropped due to global curse")

		// Verify BOTH messages are NOT in the aggregator
		verifyMessageNotExists(msg1ID, "Globally cursed message to chain1 should not be in aggregator")
		verifyMessageNotExists(msg2ID, "Globally cursed message to chain2 should not be in aggregator")

		// Uncurse the chain
		l.Info().Msg("🔓 Removing global curse from source chain")
		err = srcImpl.Uncurse(ctx, srcSelector, [][16]byte{globalCurseSubject()})
		require.NoError(t, err)

		// Send new messages after uncurse to verify both lanes work
		l.Info().Msg("📨 Sending messages after global uncurse to verify lanes work")
		event3, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "post-global-uncurse msg to chain1"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event3, "Sending message to chain1 after uncurse")

		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
		verifyMessageExists(event3.MessageID, "Message to chain1 after global uncurse")

		event4, err := srcImpl.SendMessage(ctx, srcSelector, destSelector2, newMessageFields(receiver2, "post-global-uncurse msg to chain2"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event4, "Sending message to chain2 after uncurse")

		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
		verifyMessageExists(event4.MessageID, "Message to chain2 after global uncurse")

		l.Info().Msg("✨ Test completed: Global curse verified - both lanes blocked, then unblocked after uncurse")
	})

	t.Run("finality violation", func(t *testing.T) {
		// Log the source chain selector for verification
		l.Info().Uint64("srcSelector", srcSelector).Msg("Source chain selector for finality violation test")

		l.Info().Msg("💾 Creating initial snapshot before mining blocks")
		snapshotID, err := anvilHelper.Snapshot(ctx)
		require.NoError(t, err)
		l.Info().Str("snapshotID", snapshotID).Msg("✅ Initial snapshot created")

		l.Info().Msg("📨 Sending pre-violation message")
		event1, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "pre-violation message"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event1, "Sending pre-violation message")
		preViolationMessageID := event1.MessageID

		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks to establish finalized state")
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
		l.Info().Msg("✅ Finalized state established")

		// Wait for message to be processed and appear in aggregator
		verifyMessageExists(preViolationMessageID, "Pre-violation message")

		l.Info().Msg("Sending message to be dropped once finality violation happens")
		event2, err := srcImpl.SendMessage(ctx, srcSelector, destSelector, newMessageFields(receiver, "toBeDropped message"), defaultMessageOptions)
		require.NoError(t, err)
		logSentMessage(event2, "Sending toBeDropped message")
		toBeDroppedMessageID := event2.MessageID

		l.Info().Msg("⚠️  Triggering finality violation by reverting to initial snapshot")
		err = anvilHelper.Revert(ctx, snapshotID)
		require.NoError(t, err)
		l.Info().Msg("✅ Reverted to initial snapshot (deep reorg past finalized blocks)")
		// Mine some blocks to give system opportunity to process (if it were working)
		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks after revert")
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
		verifyMessageNotExists(toBeDroppedMessageID, "Post-violation message")

		l.Info().Msg("🔍 Verifying chain status in aggregator...")

		require.Eventually(t, func() bool {
			chainStatusResp, err := authenticatedAggregatorClient.ReadChainStatus(ctx, []uint64{srcSelector})
			require.NoError(t, err, "should be able to read chain status from aggregator")
			require.Len(t, chainStatusResp.Statuses, 1, "should have one chain status for source chain")

			chainStatus := chainStatusResp.Statuses[0]
			require.Equal(t, srcSelector, chainStatus.ChainSelector, "chain selector should match")
			require.True(t, chainStatus.Disabled, "chain should be marked as disabled after finality violation")
			require.Equal(t, uint64(0), chainStatus.FinalizedBlockHeight, "finalized block height should be 0 after finality violation")

			l.Info().Msg("✅ Chain status verified in aggregator: chain is disabled with checkpoint 0")

			return true
		}, 3*time.Second, 100*time.Millisecond, "chain status should reflect disabled state after finality violation")

		l.Info().
			Msg("✨ Test completed: Finality violation detected and system stopped processing new messages")
	})

	// a utility test to enable the chain again in the aggregator instead of creating a new env
	t.Run("enable chain", func(t *testing.T) {
		resp, err := authenticatedAggregatorClient.WriteChainStatus(ctx, []*pb.ChainStatus{
			{
				ChainSelector:        srcSelector,
				FinalizedBlockHeight: 0,
				Disabled:             false,
			},
		})

		require.NoError(t, err, "should be able to enable chain in aggregator")
		require.NotNil(t, resp, "response should not be nil when enabling chain")

		chainStatusResp, err := authenticatedAggregatorClient.ReadChainStatus(ctx, []uint64{srcSelector})
		require.NoError(t, err, "should be able to read chain status from aggregator")
		require.Len(t, chainStatusResp.Statuses, 1, "should have one chain status for source chain")

		chainStatus := chainStatusResp.Statuses[0]
		require.Equal(t, srcSelector, chainStatus.ChainSelector, "chain selector should match")
		require.False(t, chainStatus.Disabled, "chain should be enabled")

		l.Info().Msg("✅ Source chain re-enabled in aggregator after being disabled from finality violation")
	})
}
