package e2e

import (
	"context"
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
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
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
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(context.Background())
	l := zerolog.Ctx(ctx)

	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	require.Len(t, selectors, 3, "expected 3 chains for this test in the environment")

	c, err := evm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

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
	srcSelector := selectors[0]
	destSelector := selectors[1]

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

	receiver := mustGetEOAReceiverAddress(t, c, destSelector)

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

	// Helper function to send a message with logging
	sendMessageWithLogging := func(data, logPrefix string) [32]byte {
		l.Info().Str("data", data).Msgf("📨 %s", logPrefix)

		event, err := c.SendMessage(ctx, srcSelector, destSelector,
			cciptestinterfaces.MessageFields{
				Receiver: receiver,
				Data:     []byte(data),
			},
			cciptestinterfaces.MessageOptions{
				Version:  3,
				Executor: executorAddr,
				CCVs: []protocol.CCV{
					{
						CCVAddress: ccvAddr,
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			})
		require.NoError(t, err)

		l.Info().
			Str("messageID", fmt.Sprintf("%x", event.MessageID)).
			Str("data", data).
			Int("seqNumber", int(event.SequenceNumber)).
			Msgf("✅ %s", logPrefix)

		return event.MessageID
	}

	// Helper function to verify a message exists in aggregator
	verifyMessageExists := func(messageID [32]byte, description string) {
		result, err := defaultAggregatorClient.GetVerifierResultForMessage(ctx, messageID)
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

	t.Run("simple reorg with message ordering", func(t *testing.T) {
		// 1/5 Blocks
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)
		snapshotID, err := anvilHelper.Snapshot(ctx)
		require.NoError(t, err)
		l.Info().Msg("💾 Snapshot created (2 blocks before messages)")
		// 2/5 Blocks
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)

		msg1IDBeforeReorg := sendMessageWithLogging("message 1", "Sending message 1")
		msg2IDBeforeReorg := sendMessageWithLogging("message 2", "Sending message 2")
		// 3/5 Blocks + 2 (for above messages to be mined)
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth/5)

		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot")
		err = anvilHelper.Revert(ctx, snapshotID)
		require.NoError(t, err)

		anvilHelper.MustMine(ctx, 1)

		msg2IDAfterReorg := sendMessageWithLogging("message 2", "Sending message 2 first (swapped order)")
		msg1IDAfterReorg := sendMessageWithLogging("message 1", "Sending message 1 second (swapped order)")
		msg3ID := sendMessageWithLogging("message 3", "Sending a new msg that wasn't sent pre reorg")

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

	t.Run("finality violation", func(t *testing.T) {
		// Log the source chain selector for verification
		l.Info().Uint64("srcSelector", srcSelector).Msg("Source chain selector for finality violation test")

		l.Info().Msg("💾 Creating initial snapshot before mining blocks")
		snapshotID, err := anvilHelper.Snapshot(ctx)
		require.NoError(t, err)
		l.Info().Str("snapshotID", snapshotID).Msg("✅ Initial snapshot created")

		l.Info().Msg("📨 Sending pre-violation message")
		preViolationMessageID := sendMessageWithLogging("pre-violation message", "Sending pre-violation message")

		l.Info().Int("blocks", verifier.ConfirmationDepth+5).Msg("⛏️  Mining blocks to establish finalized state")
		anvilHelper.MustMine(ctx, verifier.ConfirmationDepth+5)
		l.Info().Msg("✅ Finalized state established")

		// Wait for message to be processed and appear in aggregator
		verifyMessageExists(preViolationMessageID, "Pre-violation message")

		l.Info().Msg("Sending message to be dropped once finality violation happens")
		toBeDroppedMessageID := sendMessageWithLogging("toBeDropped message", "Sending toBeDropped message")

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

//// chainSelectorToSubject converts a chain selector to a bytes16 curse subject.
//func chainSelectorToSubject(chainSel uint64) [16]byte {
//	var result [16]byte
//	// Convert the uint64 to bytes and place it in the last 8 bytes of the array
//	binary.BigEndian.PutUint64(result[8:], chainSel)
//	return result
//}

//// globalCurseSubject returns the global curse constant.
//func globalCurseSubject() [16]byte {
//	return globals.GlobalCurseSubject()
//}

// ============================================================================
// RMN Curse Tests
// ============================================================================
//
//func TestRMNCurseLaneVerifierSide(t *testing.T) {
//	testCtx, selectors := NewDefaultTestingContext(t, "../../env-out.toml", 3)
//	c := testCtx.Impl
//	ctx := testCtx.Ctx
//	l := zerolog.Ctx(ctx)
//
//	var err error
//	chain0, chain1, chain2 := selectors[0], selectors[1], selectors[2]
//	receiver := mustGetEOAReceiverAddress(t, c, chain1)
//
//	sentEvt := testCtx.MustSendMessage(chain0, chain1, receiver, 150) // Use custom finality to slow down picking for verification
//	messageID := sentEvt.MessageID
//
//	l.Info().Msg("Applying lane curse between chain0 and chain1 (before message gets picked up by verifier)")
//	// normally it's bidirectional, for the sake of the test we only curse one direction
//	err = c.ApplyCurse(ctx, chain0, [][16]byte{chainSelectorToSubject(chain1)})
//	require.NoError(t, err)
//
//	l.Info().Msg("Asserting baseline message reaches verifier but gets dropped due to curse")
//	testCtx.AssertMessageReachedAndDroppedInVerifier(messageID, 100*time.Second)
//
//	// TODO: On-chain has a bug where on-ramp doesn't check for curses - once it's fixed we should add this back
//	//  on-chain ticket where it'll be fixed https://smartcontract-it.atlassian.net/browse/CCIP-7956
//	// testCtx.MustFailSend(chain0, chain1, receiver, 0, "BadARMSignal")
//
//	l.Info().Msg("Verifying uncursed lane (chain0 -> chain2) still works")
//	receiver2 := mustGetEOAReceiverAddress(t, c, chain2)
//	testCtx.MustExecuteMessage(chain0, chain2, receiver2, 0) // finality=0
//	l.Info().Msg("Confirmed: uncursed lane still works")
//
//	l.Info().Msg("Uncursing the cursed lane")
//	err = c.ApplyUncurse(ctx, chain0, [][16]byte{chainSelectorToSubject(chain1)})
//	require.NoError(t, err)
//
//	// We sleep here because in reality we'll need to replay events in case of curses to pick up the dropped tasks
//	// Increased wait time for CI environments where services may need more time to catch up
//	time.Sleep(15 * time.Second)
//
//	testCtx.MustExecuteMessage(chain0, chain1, receiver, 0) // finality=0
//
//	l.Info().Msg("Test completed successfully: lane curse and uncurse work as expected")
//}
//
//func TestRMNGlobalCurseVerifierSide(t *testing.T) {
//	testCtx, selectors := NewDefaultTestingContext(t, "../../env-out.toml", 3)
//	c := testCtx.Impl
//	ctx := testCtx.Ctx
//	l := zerolog.Ctx(ctx)
//
//	var err error
//	chain0, chain1, chain2 := selectors[0], selectors[1], selectors[2]
//
//	receiver01 := mustGetEOAReceiverAddress(t, c, chain1)
//	receiver02 := mustGetEOAReceiverAddress(t, c, chain2)
//
//	sentEvt01 := testCtx.MustSendMessage(chain0, chain1, receiver01, 150) // Use custom finality to slow down picking for verification
//	messageID01 := sentEvt01.MessageID
//
//	sentEvt02 := testCtx.MustSendMessage(chain0, chain2, receiver02, 150) // Use custom finality to slow down picking for verification
//	messageID02 := sentEvt02.MessageID
//
//	l.Info().Msg("Applying global curse to chain0 (before message gets picked up by verifier)")
//	// Apply global curse on chain0 itself
//	// usually all other chains will have a curse on chain0 as well, but for the sake of the test we only apply the global curse on chain0
//	err = c.ApplyCurse(ctx, chain0, [][16]byte{globalCurseSubject()})
//	require.NoError(t, err)
//
//	l.Info().Msg("Asserting baseline message reaches verifier but gets dropped due to global curse")
//	testCtx.AssertMessageReachedAndDroppedInVerifier(messageID01, 100*time.Second)
//	testCtx.AssertMessageReachedAndDroppedInVerifier(messageID02, 100*time.Second)
//
//	l.Info().Msg("Verifying all lanes involving chain0 as source are blocked")
//	testCtx.MustFailSend(chain0, chain1, receiver01, 0, "BadARMSignal")
//	testCtx.MustFailSend(chain0, chain2, receiver02, 0, "BadARMSignal")
//
//	l.Info().Msg("Verifying unrelated lane (chain1->chain2) still works")
//	receiver12 := mustGetEOAReceiverAddress(t, c, chain2)
//	testCtx.MustExecuteMessage(chain1, chain2, receiver12, 0) // finality=0
//	l.Info().Msg("Confirmed: unrelated lane chain1->chain2 still works")
//
//	// 8. Uncurse chain0
//	l.Info().Msg("Uncursing chain0")
//	err = c.ApplyUncurse(ctx, chain0, [][16]byte{globalCurseSubject()})
//	require.NoError(t, err)
//
//	// Increased wait time for CI environments where services may need more time to catch up after uncurse
//	time.Sleep(15 * time.Second)
//
//	testCtx.MustExecuteMessage(chain0, chain1, receiver01, 0) // finality=0
//	testCtx.MustExecuteMessage(chain0, chain2, receiver02, 0) // finality=0
//
//	l.Info().Msg("Test completed successfully: global curse and uncurse work as expected")
//}
