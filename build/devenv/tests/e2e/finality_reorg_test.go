package e2e

import (
	"context"
	"fmt"
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
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// TestSimpleReorgWithMessageOrdering tests that messages sent in different orders
// before and after a reorg are correctly verified after finality is reached.
// IMPORTANT: Need to run this test against an env that has source chain with auto mining.
// Run `just rebuild-all "env.toml,env-src-auto-mine.toml"` before running this test.
func TestSimpleReorgWithMessageOrdering(t *testing.T) {
	// TODO: Make this the regular env-out.toml
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

	// Get the source and destination chain selectors
	srcSelector := selectors[0]
	destSelector := selectors[1]

	// Get eth client for source chain using HTTP URL
	srcHTTPURL := in.Blockchains[0].Out.Nodes[0].ExternalHTTPUrl
	ethClient, err := ethclient.Dial(srcHTTPURL)
	require.NoError(t, err)

	anvilHelper := NewAnvilRPCHelper(ethClient, *l)

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

	mustSendMessageFunc := func(data string) [32]byte {
		event, err := c.SendMessage(ctx, srcSelector, destSelector,
			cciptestinterfaces.MessageFields{
				Receiver: receiver,
				Data:     []byte(data),
			},
			cciptestinterfaces.MessageOptions{
				Version:        3,
				Executor:       executorAddr,
				FinalityConfig: 10,
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
			Str("data", data).
			Int("seqNumber", int(event.SequenceNumber)).
			Msg("Sending message")

		return event.MessageID
	}

	t.Run("simple reorg with message ordering", func(t *testing.T) {
		err = anvilHelper.Mine(ctx, 3)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Block 3
		snapshotID, err := anvilHelper.Snapshot(ctx)
		require.NoError(t, err)

		snapshotBlock, err := ethClient.BlockByNumber(ctx, nil)
		require.NoError(t, err)
		l.Info().
			Str("snapshotID", snapshotID).
			Uint64("snapshotBlock", snapshotBlock.Number().Uint64()).
			Str("snapshotBlockHash", snapshotBlock.Hash().Hex()).
			Msg("💾 Snapshot created (2 blocks before messages)")

		// Block 5
		err = anvilHelper.Mine(ctx, 2)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Block 6
		l.Info().Msg("📨 Sending message 1")
		msg1IDBeforeReorg := mustSendMessageFunc("message 1")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1IDBeforeReorg)).
			Msg("✅ Message 1 sent")

		time.Sleep(2 * time.Second)

		// Block 7
		// Step 9: Send second message with data "message 2"
		l.Info().Msg("📨 Sending message 2")
		msg2IDBeforeReorg := mustSendMessageFunc("message 2")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg2IDBeforeReorg)).
			Msg("✅ Message 2 sent")

		// Block 10
		err = anvilHelper.Mine(ctx, 3)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		blockBeforeReorg, err := ethClient.BlockByNumber(ctx, nil)
		require.NoError(t, err)
		l.Info().
			Uint64("blockBeforeReorg", blockBeforeReorg.Number().Uint64()).
			Str("blockBeforeReorgHash", blockBeforeReorg.Hash().Hex()).
			Msg("⏱️  Block number before reorg (below finality threshold)")

		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot")
		// Block 3
		err = anvilHelper.Revert(ctx, snapshotID)
		require.NoError(t, err)

		// Block 4
		err = anvilHelper.Mine(ctx, 1)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		blockAfterRevert, err := ethClient.BlockByNumber(ctx, nil)
		require.NoError(t, err)
		l.Info().
			Uint64("blockAfterRevert", blockAfterRevert.Number().Uint64()).
			Str("blockAfterRevertHash", blockAfterRevert.Hash().Hex()).
			Uint64("reorgDepth", blockBeforeReorg.Number().Uint64()-blockAfterRevert.Number().Uint64()).
			Msg("⏪ Reverted to snapshot")

		l.Info().Msg("📨 Sending message 2 first (swapped order)")
		msg2IDAfterReorg := mustSendMessageFunc("message 2")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg2IDAfterReorg)).
			Msg("✅ Message 2 sent (swapped order)")

		time.Sleep(5 * time.Second)

		// Step 15: Send message 1 second (swapped order)
		l.Info().Msg("📨 Sending message 1 second (swapped order)")
		msg1IDAfterReorg := mustSendMessageFunc("message 1")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1IDAfterReorg)).
			Msg("✅ Message 1 sent (swapped order)")

		l.Info().Msg("Sending a new msg that wasn't sent pre reorg")
		msg3ID := mustSendMessageFunc("message 3")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg3ID)).
			Msg("✅ Message 3 sent (new message)")

		// Step 16: Mine 11 blocks to cross finality threshold
		l.Info().Msg("⛏️  Mining 11 blocks to cross finality threshold")
		err = anvilHelper.Mine(ctx, 11)
		require.NoError(t, err)

		time.Sleep(5 * time.Second)

		finalBlock, err := ethClient.BlockByNumber(ctx, nil)
		require.NoError(t, err)
		l.Info().
			Uint64("finalBlock", finalBlock.Number().Uint64()).
			Str("finalBlockHash", finalBlock.Hash().Hex()).
			Msg("✅ Crossed finality threshold")

		// Step 17: Verify both messages are found in aggregator
		l.Info().Msg("🔍 Verifying messages are in aggregator (after finality)")

		result2, err := defaultAggregatorClient.GetVerifierResultForMessage(ctx, msg2IDAfterReorg)
		require.NoError(t, err, "Message 2 should be found after finality")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg2IDAfterReorg)).
			Str("verifierResult", fmt.Sprintf("%x", result2)).
			Msg("✅ Message 2 verified in aggregator after finality")

		result1, err := defaultAggregatorClient.GetVerifierResultForMessage(ctx, msg1IDAfterReorg)
		require.NoError(t, err, "Message 1 should be found after finality")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg1IDAfterReorg)).
			Str("verifierResult", fmt.Sprintf("%x", result1)).
			Msg("✅ Message 1 verified in aggregator after finality")

		result3, err := defaultAggregatorClient.GetVerifierResultForMessage(ctx, msg3ID)
		require.NoError(t, err, "Message 3 should be found after finality")
		l.Info().
			Str("messageID", fmt.Sprintf("%x", msg3ID)).
			Str("verifierResult", fmt.Sprintf("%x", result3)).
			Msg("✅ Message 3 verified in aggregator after finality")

		l.Info().Msg("🔍 Checking messages are NOT in aggregator (below finality)")
		_, err = defaultAggregatorClient.GetVerifierResultForMessage(ctx, msg1IDBeforeReorg)
		require.Error(t, err, "Message 1 before reorg should not be found in aggregator")

		_, err = defaultAggregatorClient.GetVerifierResultForMessage(ctx, msg2IDBeforeReorg)
		require.Error(t, err, "Message 2 should not be found in aggregator")

		l.Info().Msg("✅ Confirmed messages not in aggregator")

		l.Info().
			Uint64("reorgDepth", blockBeforeReorg.Number().Uint64()-blockAfterRevert.Number().Uint64()).
			Msg("✨ Test completed: Messages sent in swapped order after reorg and verified after finality")
	})
}
