package canton

import (
	"fmt"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	canton_committee_verifier "github.com/smartcontractkit/chainlink-canton/deployment/operations/ccip/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestCanton2EVM_Basic(t *testing.T) {
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

	srcSelector := cantonDetails.ChainSelector
	srcChain := chainMap[srcSelector]
	require.NotNil(t, srcChain)
	dstSelector := evmDetails.ChainSelector
	dstChain := chainMap[dstSelector]
	require.NotNil(t, dstChain)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	// Get EVM receiver address (EOA)
	receiver, err := dstChain.GetEOAReceiverAddress()
	require.NoError(t, err, "failed to get EVM receiver address")
	t.Logf("Message receiver: %s", hexutil.Encode(receiver.Bytes()))

	// Get Canton CCV
	ref, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			cantonDetails.ChainSelector,
			datastore.ContractType(canton_committee_verifier.ContractType),
			canton_committee_verifier.Version,
			common.DefaultCommitteeVerifierQualifier,
		),
	)
	require.NoError(t, err, "failed to get Canton committee verifier address from datastore")

	// Parse Canton CCV address from datastore
	// Canton addresses are stored as hex strings in the Address field
	cantonCCVAddress := protocol.UnknownAddress(gethcommon.HexToAddress(ref.Address).Bytes())

	// Get EVM executor address
	executorRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			evmDetails.ChainSelector,
			datastore.ContractType(executor.ProxyType),
			semver.MustParse(executor.DeployProxy.Version()),
			common.DefaultExecutorQualifier,
		),
	)
	require.NoError(t, err, "failed to get EVM executor address from datastore")
	executorAddress := protocol.UnknownAddress(gethcommon.HexToAddress(executorRef.Address).Bytes())

	// Send message from Canton to EVM
	sendMessageResult, err := srcChain.SendMessage(ctx, dstSelector, cciptestinterfaces.MessageFields{
		Receiver:    receiver,
		Data:        []byte("Hello from Canton!"),
		TokenAmount: cciptestinterfaces.TokenAmount{},
		FeeToken:    nil,
	}, cciptestinterfaces.MessageOptions{
		Version:             3,
		ExecutionGasLimit:   100_000,
		OutOfOrderExecution: false,
		CCVs: []protocol.CCV{
			{
				CCVAddress: cantonCCVAddress,
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		FinalityConfig: 0,
		Executor:       executorAddress,
		ExecutorArgs:   nil,
		TokenArgs:      nil,
	})
	require.NoError(t, err, "failed to send message from Canton chain")
	// TODO: Canton SendMessage and WaitOneSentEventBySeqNo implementations need to extract receipts from CCIPMessageSent event
	// For now, receipts will be empty until these methods are fully implemented
	fmt.Println("SendMessageResult: ", sendMessageResult)
	if len(sendMessageResult.ReceiptIssuers) == 0 {
		t.Logf("WARNING: ReceiptIssuers is empty - Canton SendMessage/WaitOneSentEventBySeqNo need to extract receipts from CCIPMessageSent event")
	}

	// Use the actual sequence number from the sent message instead of calling GetExpectedNextSequenceNumber separately
	// This avoids race conditions where the router state might change between calls
	require.NotNil(t, sendMessageResult.Message, "SendMessage result must include Message")
	seqNo := uint64(sendMessageResult.Message.SequenceNumber)
	l.Info().Uint64("SeqNo", seqNo).Msg("Using sequence number from sent message")

	sentEvent, err := srcChain.WaitOneSentEventBySeqNo(ctx, dstSelector, seqNo, time.Second*10)
	require.NoError(t, err)
	messageID := sentEvent.MessageID
	t.Logf("Message sent with ID: %s", hexutil.Encode(messageID[:]))

	// Setup indexer and aggregator clients
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

	// Wait for verification and get message
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

	// Wait for automatic execution on EVM or manually execute
	executionStateChangedEvent, err := dstChain.WaitOneExecEventBySeqNo(ctx, srcSelector, seqNo, tests.WaitTimeout(t))
	if err != nil {
		// If automatic execution didn't happen, manually execute
		t.Logf("Automatic execution not detected, manually executing message")
		executionStateChangedEvent, err = dstChain.ManuallyExecuteMessage(
			ctx,
			message,
			0,
			[]protocol.UnknownAddress{result.IndexedVerifications.Results[0].VerifierResult.VerifierDestAddress},
			[][]byte{result.IndexedVerifications.Results[0].VerifierResult.CCVData},
		)
		require.NoError(t, err, "failed to execute message on EVM chain")
	}

	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, executionStateChangedEvent.State, "expected message execution to succeed")
	require.EqualValues(t, srcSelector, executionStateChangedEvent.SourceChainSelector, "expected source chain selector to match")
	require.Equal(t, messageID, executionStateChangedEvent.MessageID, "expected message ID to match")
	require.Equal(t, seqNo, executionStateChangedEvent.MessageNumber, "expected message number to match")
	t.Logf("Message executed successfully on EVM chain")
}
