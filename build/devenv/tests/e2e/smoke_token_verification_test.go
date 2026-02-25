package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/cctp_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

type tokenVerifierTestCase struct {
	name                    string
	finalityConfig          uint16
	executionGasLimit       uint32
	transferAmount          *big.Int
	receiver                protocol.UnknownAddress
	shouldCheckAggregator   bool
	shouldRevert            bool
	expectedReceiptIssuers  int
	expectedVerifierResults int
}

func TestE2ESmoke_TokenVerification(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	// Only load EVM chains for now, as more chains become supported we can add them.
	lib, err := ccv.NewLib(l, smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	aggregatorClients := SetupAggregatorClients(t, ctx, in)
	defaultAggregatorClient := aggregatorClients[common.DefaultCommitteeVerifierQualifier]
	indexerMonitor := SetupIndexerMonitor(t, ctx, lib)

	sel0, sel1 := chains[0].Details.ChainSelector, chains[1].Details.ChainSelector

	t.Run("USDC v3 token transfer", func(t *testing.T) {
		var (
			sourceSelector   = sel0
			sourceChain      = chainMap[sourceSelector]
			destSelector     = sel1
			destChain        = chainMap[destSelector]
			cctpOnlyReceiver = getContractAddress(
				t,
				in,
				destSelector,
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				common.CCTPPrimaryReceiverQualifier,
				"",
			)
			cctpAndCommitteeReceiver = getContractAddress(
				t,
				in,
				destSelector,
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				common.CCTPSecondaryReceiverQualifier,
				"",
			)
		)

		tcs := []tokenVerifierTestCase{
			{
				name:                    "USDC transfer to EOA receiver with chain finality",
				finalityConfig:          0,
				transferAmount:          big.NewInt(100),
				receiver:                mustGetEOAReceiverAddress(t, destChain),
				expectedReceiptIssuers:  4, // CCTP CCV, token pool, executor, network fee
				expectedVerifierResults: 1,
				shouldCheckAggregator:   false,
			},
			{
				name:                    "USDC transfer to EOA receiver with fast finality",
				finalityConfig:          1,
				transferAmount:          big.NewInt(500),
				receiver:                mustGetEOAReceiverAddress(t, destChain),
				expectedReceiptIssuers:  4, // CCTP CCV, token pool, executor, network fee
				expectedVerifierResults: 1,
				shouldCheckAggregator:   false,
			},
			{
				name:              "USDC transfer to receiver contract but only CCTP verifier is required on dest",
				finalityConfig:    0,
				transferAmount:    big.NewInt(2),
				receiver:          cctpOnlyReceiver,
				executionGasLimit: 200_000,
				// Onramp does include default CCV even if not required when either execGas or data is not empty
				expectedReceiptIssuers:  5, // default ccv, CCTP ccv, token pool, executor, network fee
				expectedVerifierResults: 2, // default ccv, CCTP ccv
				shouldCheckAggregator:   true,
			},
			{
				name:                    "USDC transfer to receiver contract but commit and CCTP verifiers are required on dest",
				finalityConfig:          1,
				transferAmount:          big.NewInt(10),
				receiver:                cctpAndCommitteeReceiver,
				executionGasLimit:       200_000,
				expectedReceiptIssuers:  5, // default ccv, CCTP ccv, token pool, executor, network fee
				expectedVerifierResults: 2, // default ccv, CCTP ccv
				shouldCheckAggregator:   true,
			},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				runUSDCTestCase(t, ctx, l, in, sourceChain, destChain, sourceSelector, destSelector, chainMap, defaultAggregatorClient, indexerMonitor, tc)
			})
		}
	})

	t.Run("Lombard V3 token transfer", func(t *testing.T) {
		var (
			sourceSelector   = sel0
			sourceChain      = chainMap[sourceSelector]
			destSelector     = sel1
			destChain        = chainMap[destSelector]
			contractReceiver = getContractAddress(
				t,
				in,
				destSelector,
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				common.LombardPrimaryReceiverQualifier,
				"",
			)
		)

		tcs := []tokenVerifierTestCase{
			{
				name:                    "Lombard transfer to EOA receiver with chain finality",
				transferAmount:          big.NewInt(100),
				receiver:                mustGetEOAReceiverAddress(t, destChain),
				finalityConfig:          0,
				expectedReceiptIssuers:  5, // default ccv, token pool, executor, network fee
				expectedVerifierResults: 2, // default ccv, Lombard ccv
			},
			{
				name:           "Lombard transfer to EOA fails with custom finality config",
				transferAmount: big.NewInt(100),
				receiver:       mustGetEOAReceiverAddress(t, destChain),
				finalityConfig: 1,
				shouldRevert:   true,
			},
			{
				name:                    "Lombard transfer to contract receiver with chain finality",
				transferAmount:          big.NewInt(200),
				receiver:                contractReceiver,
				executionGasLimit:       200_000,
				expectedReceiptIssuers:  5, // default ccv, token pool, executor, network fee
				expectedVerifierResults: 2, // default ccv, Lombard ccv
			},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				runLombardTestCase(t, ctx, l, in, sourceChain, destChain, sourceSelector, destSelector, chainMap, defaultAggregatorClient, indexerMonitor, tc)
			})
		}
	})
}

func runUSDCTestCase(
	t *testing.T,
	ctx context.Context,
	l *zerolog.Logger,
	in *ccv.Cfg,
	sourceChain, destChain cciptestinterfaces.CCIP17,
	sourceSelector, destSelector uint64,
	chainMap map[uint64]cciptestinterfaces.CCIP17,
	defaultAggregatorClient *ccv.AggregatorClient,
	indexerMonitor *ccv.IndexerMonitor,
	tc tokenVerifierTestCase,
) {
	sender := mustGetSenderAddress(t, sourceChain)

	srcToken := getTokenAddress(t, in, sourceSelector, common.CCTPContractsQualifier)
	destToken := getTokenAddress(t, in, destSelector, common.CCTPContractsQualifier)

	startBal, err := destChain.GetTokenBalance(ctx, tc.receiver, destToken)
	require.NoError(t, err)
	l.Info().Str("Receiver", tc.receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", common.CCTPContractsQualifier).Msg("receiver start balance")

	srcStartBal, err := sourceChain.GetTokenBalance(ctx, sender, srcToken)
	require.NoError(t, err)
	l.Info().Str("Sender", sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", common.CCTPContractsQualifier).Msg("sender start balance")

	seqNo, err := sourceChain.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	l.Info().Uint64("SeqNo", seqNo).Str("Token", common.CCTPContractsQualifier).Msg("expecting sequence number")

	messageOptions := cciptestinterfaces.MessageOptions{
		Version:           3,
		FinalityConfig:    tc.finalityConfig,
		ExecutionGasLimit: tc.executionGasLimit,
		Executor:          getContractAddress(t, in, sourceSelector, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor"),
	}

	sendRes, err := sourceChain.SendMessage(
		ctx, destSelector,
		cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       tc.transferAmount,
				TokenAddress: srcToken,
			},
		},
		messageOptions,
	)
	require.NoError(t, err)
	require.NotNil(t, sendRes)
	require.Len(t, sendRes.ReceiptIssuers, tc.expectedReceiptIssuers, "expected %d receipt issuers for %s token", tc.expectedReceiptIssuers, common.CCTPContractsQualifier)

	sentEvt, err := sourceChain.WaitOneSentEventBySeqNo(ctx, destSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)
	msgID := sentEvt.MessageID

	// Register CCTP attestation response with the fake service
	cctpMessageSender := getContractAddress(
		t,
		in,
		sourceSelector,
		datastore.ContractType(cctp_verifier.ContractType),
		cctp_verifier.Deploy.Version(),
		common.CCTPContractsQualifier,
		"",
	)
	registerCCTPAttestation(t, in.Fake.Out.ExternalHTTPURL, msgID, cctpMessageSender, tc.receiver, "complete")
	l.Info().Str("MessageID", hex.EncodeToString(msgID[:])).Msg("Registered CCTP attestation")

	var aggregatorClient *ccv.AggregatorClient
	if tc.shouldCheckAggregator {
		aggregatorClient = defaultAggregatorClient
	}

	testCtx := NewTestingContext(t, ctx, chainMap, aggregatorClient, indexerMonitor)
	res, err := testCtx.AssertMessage(msgID, AssertMessageOptions{
		TickInterval:            1 * time.Second,
		Timeout:                 45 * time.Second,
		ExpectedVerifierResults: tc.expectedVerifierResults,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})

	require.NoError(t, err)
	if tc.shouldCheckAggregator {
		require.NotNil(t, res.AggregatedResult)
	}

	execEvt, err := destChain.WaitOneExecEventBySeqNo(ctx, sourceSelector, seqNo, 45*time.Second)
	require.NoError(t, err)
	require.NotNil(t, execEvt)
	require.Equalf(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State, "unexpected state, return data: %x", execEvt.ReturnData)

	endBal, err := destChain.GetTokenBalance(ctx, tc.receiver, destToken)
	require.NoError(t, err)

	// We always mint 1 tiny coin on a dest from CCTPTokenMessenger
	require.Equal(t, new(big.Int).Add(new(big.Int).Set(startBal), big.NewInt(1)), endBal)
	l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", common.CCTPContractsQualifier).Msg("receiver end balance")

	srcEndBal, err := sourceChain.GetTokenBalance(ctx, sender, srcToken)
	require.NoError(t, err)
	require.Equal(t, new(big.Int).Sub(new(big.Int).Set(srcStartBal), tc.transferAmount), srcEndBal)
	l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", common.CCTPContractsQualifier).Msg("sender end balance")
}

func runLombardTestCase(
	t *testing.T,
	ctx context.Context,
	l *zerolog.Logger,
	in *ccv.Cfg,
	sourceChain, destChain cciptestinterfaces.CCIP17,
	sourceSelector, destSelector uint64,
	chainMap map[uint64]cciptestinterfaces.CCIP17,
	defaultAggregatorClient *ccv.AggregatorClient,
	indexerMonitor *ccv.IndexerMonitor,
	tc tokenVerifierTestCase,
) {
	sender := mustGetSenderAddress(t, sourceChain)

	srcToken := getTokenAddress(t, in, sourceSelector, common.LombardContractsQualifier)
	destToken := getTokenAddress(t, in, destSelector, common.LombardContractsQualifier)

	startBal, err := destChain.GetTokenBalance(ctx, tc.receiver, destToken)
	require.NoError(t, err)
	l.Info().Str("Receiver", tc.receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", common.LombardContractsQualifier).Msg("receiver start balance")

	srcStartBal, err := sourceChain.GetTokenBalance(ctx, sender, srcToken)
	require.NoError(t, err)
	l.Info().Str("Sender", sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", common.LombardContractsQualifier).Msg("sender start balance")

	seqNo, err := sourceChain.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	l.Info().Uint64("SeqNo", seqNo).Str("Token", common.LombardContractsQualifier).Msg("expecting sequence number")

	messageOptions := cciptestinterfaces.MessageOptions{
		Version:           3,
		FinalityConfig:    tc.finalityConfig,
		ExecutionGasLimit: tc.executionGasLimit,
		Executor:          getContractAddress(t, in, sourceSelector, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), common.DefaultExecutorQualifier, "executor"),
	}

	sendRes, err := sourceChain.SendMessage(
		ctx, destSelector,
		cciptestinterfaces.MessageFields{
			Receiver: tc.receiver,
			TokenAmount: cciptestinterfaces.TokenAmount{
				Amount:       tc.transferAmount,
				TokenAddress: srcToken,
			},
		},
		messageOptions,
	)
	if tc.shouldRevert {
		require.Error(t, err)
		return
	}

	require.NoError(t, err)
	require.NotNil(t, sendRes)
	require.Len(t, sendRes.ReceiptIssuers, tc.expectedReceiptIssuers, "expected %d receipt issuers for %s token", tc.expectedReceiptIssuers, common.CCTPContractsQualifier)

	sentEvt, err := sourceChain.WaitOneSentEventBySeqNo(ctx, destSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)

	msgID := sentEvt.MessageID

	messageHash := sentEvt.Message.TokenTransfer.ExtraData
	attestation := buildLombardAttestation(msgID)
	registerLombardAttestation(t, in.Fake.Out.ExternalHTTPURL, messageHash, attestation, "NOTARIZATION_STATUS_SESSION_APPROVED")
	l.Info().Str("MessageHash", messageHash.String()).Str("MessageID", hex.EncodeToString(msgID[:])).Msg("Registered Lombard attestation")

	testCtx := NewTestingContext(t, ctx, chainMap, defaultAggregatorClient, indexerMonitor)
	res, err := testCtx.AssertMessage(msgID, AssertMessageOptions{
		TickInterval:            1 * time.Second,
		Timeout:                 45 * time.Second,
		ExpectedVerifierResults: tc.expectedVerifierResults,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})

	require.NoError(t, err)
	require.NotNil(t, res.AggregatedResult)

	execEvt, err := destChain.WaitOneExecEventBySeqNo(ctx, sourceSelector, seqNo, 45*time.Second)
	require.NoError(t, err)
	require.NotNil(t, execEvt)
	require.Equalf(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State, "unexpected state, return data: %x", execEvt.ReturnData)

	// FIXME: MockLombardMailbox doesn't mint anything on the dest. Therefore we can rely only on
	// balance change on the source side to confirm the transfer happened. We also check the ExecutionStateChange event.
	// We should update the mock to mint on dest as well and then we can re-enable balance check on dest.
	// endBal, err := destChain.GetTokenBalance(ctx, tc.receiver, destToken)
	// require.NoError(t, err)
	//
	// require.Equal(t, new(big.Int).Add(new(big.Int).Set(startBal), tc.transferAmount), endBal)
	// l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", common.LombardContractsQualifier).Msg("receiver end balance")

	srcEndBal, err := sourceChain.GetTokenBalance(ctx, sender, srcToken)
	require.NoError(t, err)
	require.Equal(t, new(big.Int).Sub(new(big.Int).Set(srcStartBal), tc.transferAmount), srcEndBal)
	l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", common.LombardContractsQualifier).Msg("sender end balance")
}
