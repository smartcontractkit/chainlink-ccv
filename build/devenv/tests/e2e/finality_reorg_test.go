package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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

	// Create chain status manager to read from the verifier's SQLite database
	chainStatusLggr, err := logger.New()
	require.NoError(t, err)
	chainStatusManager, err := chainstatus.NewSQLiteChainStatusManager(filepath.Join(in.Verifier[0].ChainStatusDBHostDir, "chain-status.db"), chainStatusLggr)
	require.NoError(t, err, "should be able to create chain status manager for verifier's database")
	t.Cleanup(func() {
		chainStatusManager.Close()
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
}
