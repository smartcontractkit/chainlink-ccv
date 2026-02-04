package stellar

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/stellar"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	// Test timeouts for Stellar to EVM flow
	stellarSentTimeout = 30 * time.Second
)

// Start the environment required for this test using:
// CTF_CONFIGS=env-stellar-evm.toml go run ./cmd/ccv
// from the build/devenv directory.
func TestStellarToEVMSourceReader(t *testing.T) {
	configPath := "../../../env-stellar-evm-out.toml"
	in, err := ccv.LoadOutput[ccv.Cfg](configPath)
	require.NoError(t, err)

	// Find Stellar chain
	var stellarChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeStellar {
			stellarChain = bc
			break
		}
	}
	require.NotNil(t, stellarChain, "need at least one stellar chain for this test")

	// Find EVM chain
	var evmChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeAnvil {
			evmChain = bc
			break
		}
	}
	require.NotNil(t, evmChain, "need at least one evm chain for this test")

	// Use custom helper since chain-selectors doesn't support Stellar lookups yet
	stellarDetails, err := stellar.GetChainDetailsByChainIDForStellar(stellarChain.ChainID)
	require.NoError(t, err)

	evmDetails, err := chain_selectors.GetChainDetailsByChainIDAndFamily(evmChain.ChainID, chain_selectors.FamilyEVM)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	// Load EVM chain for destination interactions
	lib, err := ccv.NewLib(l, configPath, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.ChainsMap(ctx)
	require.NoError(t, err)
	destChain := chains[evmDetails.ChainSelector]
	require.NotNil(t, destChain)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	// Set up aggregator client
	var indexerMonitor *ccv.IndexerMonitor
	indexerClient, err := lib.Indexer()
	require.NoError(t, err)
	indexerMonitor, err = ccv.NewIndexerMonitor(
		zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
		indexerClient)
	require.NoError(t, err)
	require.NotNil(t, indexerMonitor)

	aggregatorClients := make(map[string]*ccv.AggregatorClient)
	for qualifier := range in.AggregatorEndpoints {
		client, err := in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("aggregator-client-%s", qualifier)).Logger(),
			qualifier)
		require.NoError(t, err)
		require.NotNil(t, client)
		aggregatorClients[qualifier] = client
		t.Cleanup(func() {
			client.Close()
		})
	}
	defaultAggregatorClient := aggregatorClients[devenvcommon.DefaultCommitteeVerifierQualifier]

	t.Run("basic_stellar_to_evm_message", func(t *testing.T) {
		// Get receiver address on EVM
		evmReceiver, err := destChain.GetEOAReceiverAddress()
		require.NoError(t, err)
		l.Info().Str("evmReceiver", evmReceiver.String()).Msg("Using EVM receiver address")

		// TODO: Once Stellar impl is fully integrated, use the Stellar chain from lib
		// For now, we'll construct a test message manually similar to Canton test

		// Create a test message from Stellar to EVM
		seqNr := int64(1)
		msg := newStellarToEVMMessage(
			t,
			protocol.ChainSelector(stellarDetails.ChainSelector),
			protocol.ChainSelector(evmDetails.ChainSelector),
			seqNr,
			evmReceiver,
		)

		l.Info().
			Str("messageID", hex.EncodeToString(msg.MustMessageID()[:])).
			Int64("sequenceNumber", seqNr).
			Msg("Created test message from Stellar to EVM")

		// Wait for verification through the aggregator
		testCtx := e2e.NewTestingContext(t, t.Context(), chains, defaultAggregatorClient, indexerMonitor)
		result, err := testCtx.AssertMessage(msg.MustMessageID(), e2e.AssertMessageOptions{
			TickInterval:            1 * time.Second,
			ExpectedVerifierResults: 1, // just committee verifier
			Timeout:                 tests.WaitTimeout(t),
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		})
		require.NoError(t, err)
		require.NotNil(t, result.AggregatedResult)
		require.Len(t, result.IndexedVerifications.Results, 1)

		// Wait for execution on EVM
		ev, err := destChain.WaitOneExecEventBySeqNo(t.Context(), stellarDetails.ChainSelector, uint64(seqNr), tests.WaitTimeout(t))
		require.NoError(t, err)
		require.Equalf(
			t,
			cciptestinterfaces.ExecutionStateSuccess,
			ev.State,
			"message %d should have been successfully executed, return data: %x",
			seqNr,
			ev.ReturnData,
		)

		l.Info().
			Str("messageID", hex.EncodeToString(msg.MustMessageID()[:])).
			Msg("Message executed successfully on EVM")
	})
}

// newStellarToEVMMessage creates a test CCIP message from Stellar to EVM.
func newStellarToEVMMessage(
	t *testing.T,
	sourceSelector,
	destSelector protocol.ChainSelector,
	seqNr int64,
	evmReceiver protocol.UnknownAddress,
) protocol.Message {
	// For testing, we use placeholder addresses
	// In production, these would come from deployed contracts
	stellarOnRamp := protocol.UnknownAddress(make([]byte, 32))  // Stellar addresses are 32 bytes
	evmOffRamp := protocol.UnknownAddress(make([]byte, 20))     // EVM addresses are 20 bytes
	stellarSender := protocol.UnknownAddress(make([]byte, 32))

	// Placeholder CCV and executor addresses
	ccvAddresses := []protocol.UnknownAddress{
		protocol.UnknownAddress(make([]byte, 32)), // Stellar CCV address
	}
	executorAddress := protocol.UnknownAddress(make([]byte, 32))

	// Compute the CCV and executor hash for validation
	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
	require.NoError(t, err)

	msg, err := protocol.NewMessage(
		sourceSelector,
		destSelector,
		protocol.SequenceNumber(seqNr),
		stellarOnRamp,
		evmOffRamp,
		1,                  // finality
		200_000,            // execution gas limit
		100_000,            // ccip receive gas limit
		ccvAndExecutorHash, // ccv and executor hash
		stellarSender,
		evmReceiver,
		[]byte{},                       // dest blob, not required for EVM
		[]byte("message from stellar"), // message data
		nil,                            // token transfer
	)
	require.NoError(t, err)

	return *msg
}
