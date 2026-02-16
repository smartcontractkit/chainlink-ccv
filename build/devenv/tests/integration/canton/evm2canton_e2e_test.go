package canton

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-canton/contracts"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	devenvcanton "github.com/smartcontractkit/chainlink-ccv/devenv/canton"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestEVM2Canton_Basic(t *testing.T) {
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	configPath := "../../../env-canton-evm-out.toml"
	in, err := ccv.LoadOutput[ccv.Cfg](configPath)
	require.NoError(t, err)

	var cantonChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeCanton {
			cantonChain = bc
			break
		}
	}
	require.NotNil(t, cantonChain, "need at least one canton chain for this test")

	var evmChain *blockchain.Input
	for _, bc := range in.Blockchains {
		if bc.Type == blockchain.TypeAnvil {
			evmChain = bc
			break
		}
	}
	require.NotNil(t, evmChain, "need at least one evm chain for this test")

	cantonDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(cantonChain.ChainID, chainsel.FamilyCanton)
	require.NoError(t, err)

	evmDetails, err := chainsel.GetChainDetailsByChainIDAndFamily(evmChain.ChainID, chainsel.FamilyEVM)
	require.NoError(t, err)

	_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	b := ccv.NewDefaultCLDFBundle(e)
	e.OperationsBundle = b

	lib, err := ccv.NewLib(l, configPath, chainsel.FamilyEVM, chainsel.FamilyCanton)
	require.NoError(t, err)
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	srcSelector := evmDetails.ChainSelector
	srcChain := chainMap[srcSelector]
	require.NotNil(t, srcChain)
	dstSelector := cantonDetails.ChainSelector
	dstChain := chainMap[dstSelector]
	require.NotNil(t, dstChain)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	grpcURL := cantonChain.Out.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL
	require.NotEmpty(t, grpcURL)
	jwt := cantonChain.Out.NetworkSpecificData.CantonEndpoints.Participants[0].JWT
	require.NotEmpty(t, jwt)

	helper, err := devenvcanton.NewHelperFromBlockchainInput(ctx, grpcURL, jwt)
	require.NoError(t, err)
	ts := newTestSetup(helper)

	// Assert that the parties were created and are known to the ledger.
	knownParties, err := ts.helper.ListKnownParties(t.Context())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(knownParties), 1)
	// Find the party that corresponds to the JWT token that we have
	var party string
	for _, theParty := range knownParties {
		if strings.HasPrefix(theParty.GetParty(), partyName) {
			party = theParty.GetParty()
			break
		}
	}
	require.NotEmpty(t, party)
	t.Logf("found party: %s", party)

	// Hash receiver party
	receiver := contracts.HashedPartyFromString(party)
	t.Logf("Message receiver: %s", receiver.Hex())

	// Get EVM CCV
	ref, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			evmDetails.ChainSelector,
			datastore.ContractType(committee_verifier.ResolverType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			common.DefaultCommitteeVerifierQualifier,
		),
	)
	require.NoError(t, err, "failed to get EVM committee verifier address from datastore")
	defaultCCVAddress := protocol.UnknownAddress(gethcommon.HexToAddress(ref.Address).Bytes())

	// No-execution tag
	executorAddress := protocol.UnknownAddress(gethcommon.HexToAddress("0xEBa517d200000000000000000000000000000000").Bytes())

	// Send message
	seqNo, err := srcChain.GetExpectedNextSequenceNumber(ctx, dstSelector)
	require.NoError(t, err)
	l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
	sendMessageResult, err := srcChain.SendMessage(ctx, dstSelector, cciptestinterfaces.MessageFields{
		Receiver:    receiver.Bytes(),
		Data:        []byte("Hello from EVM!"),
		TokenAmount: cciptestinterfaces.TokenAmount{},
		FeeToken:    nil,
	}, cciptestinterfaces.MessageOptions{
		Version:             3,
		ExecutionGasLimit:   100_000,
		OutOfOrderExecution: false,
		CCVs: []protocol.CCV{
			{
				CCVAddress: defaultCCVAddress,
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		FinalityConfig: 0,
		Executor:       executorAddress,
		ExecutorArgs:   nil,
		TokenArgs:      nil,
	})
	require.NoError(t, err, "failed to send message from EVM chain")
	require.Lenf(t, sendMessageResult.ReceiptIssuers, 3, "expected 3 receipt issuers for the message")
	sentEvent, err := srcChain.WaitOneSentEventBySeqNo(ctx, dstSelector, seqNo, time.Second*10)
	require.NoError(t, err)
	messageID := sentEvent.MessageID
	t.Logf("Message sent with ID: %s", hexutil.Encode(messageID[:]))

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
	defaultAggregatorClient := aggregatorClients[common.DefaultCommitteeVerifierQualifier]

	testCtx := e2e.NewTestingContext(t, t.Context(), chainMap, defaultAggregatorClient, indexerMonitor)
	result, err := testCtx.AssertMessage(messageID, e2e.AssertMessageOptions{
		TickInterval:            time.Second,
		Timeout:                 tests.WaitTimeout(t),
		ExpectedVerifierResults: 1,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	require.NoError(t, err)
	require.NotNil(t, result.AggregatedResult)
	require.Len(t, result.IndexedVerifications.Results, 1)

	message := result.IndexedVerifications.Results[0].VerifierResult.Message

	// Manually execute
	executionStateChangedEvent, err := dstChain.ManuallyExecuteMessage(ctx, message, 0, []protocol.UnknownAddress{result.IndexedVerifications.Results[0].VerifierResult.VerifierDestAddress}, [][]byte{result.IndexedVerifications.Results[0].VerifierResult.CCVData})
	require.NoError(t, err, "failed to manually execute message on Canton chain")
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, executionStateChangedEvent.State, "expected message execution to succeed")
	require.EqualValues(t, srcSelector, executionStateChangedEvent.SourceChainSelector, "expected source chain selector to match")
	require.Equal(t, messageID, executionStateChangedEvent.MessageID, "expected message ID to match")
	require.Equal(t, seqNo, executionStateChangedEvent.MessageNumber, "expected message number to match")
	require.Equal(t, []byte{}, executionStateChangedEvent.ReturnData, "expected empty return data from message execution")
}
