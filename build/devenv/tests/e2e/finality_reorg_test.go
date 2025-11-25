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

	// Helper function to send a message with logging
	sendMessageWithLogging := func(data, logPrefix string) [32]byte {
		l.Info().Str("data", data).Msgf("📨 %s", logPrefix)

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
		anvilHelper.MustMine(ctx, 3)
		time.Sleep(3 * time.Second)
		// Block 3
		snapshotID, err := anvilHelper.Snapshot(ctx)
		require.NoError(t, err)
		l.Info().Msg("💾 Snapshot created (2 blocks before messages)")
		// Block 5
		anvilHelper.MustMine(ctx, 2)
		time.Sleep(3 * time.Second)

		// Block 6
		msg1IDBeforeReorg := sendMessageWithLogging("message 1", "Sending message 1")
		time.Sleep(3 * time.Second)
		// Block 7
		msg2IDBeforeReorg := sendMessageWithLogging("message 2", "Sending message 2")
		// Block 10
		anvilHelper.MustMine(ctx, 3)
		time.Sleep(3 * time.Second)

		l.Info().Msg("🔄 Triggering reorg by reverting to snapshot")
		// Back to Block 3
		err = anvilHelper.Revert(ctx, snapshotID)
		require.NoError(t, err)

		// Block 4
		anvilHelper.MustMine(ctx, 1)

		time.Sleep(3 * time.Second)

		msg2IDAfterReorg := sendMessageWithLogging("message 2", "Sending message 2 first (swapped order)")
		msg1IDAfterReorg := sendMessageWithLogging("message 1", "Sending message 1 second (swapped order)")
		msg3ID := sendMessageWithLogging("message 3", "Sending a new msg that wasn't sent pre reorg")

		// Mine 11 blocks to cross finality threshold
		l.Info().Msg("⛏️  Mining 11 blocks to cross finality threshold")
		anvilHelper.MustMine(ctx, 11)

		time.Sleep(5 * time.Second)

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
}
