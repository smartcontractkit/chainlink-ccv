package e2e

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/burn_mint_erc20_with_drip"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	defaultSentTimeout = 10 * time.Second
	defaultExecTimeout = 40 * time.Second
)

type tokenTransfer struct {
	tokenAmount  cciptestinterfaces.TokenAmount
	destTokenRef datastore.AddressRef
}

// v3TestCase is for tests that use ExtraArgsV3.
type v3TestCase struct {
	name                     string
	srcSelector              uint64
	dstSelector              uint64
	finality                 uint16
	receiver                 protocol.UnknownAddress
	ccvs                     []protocol.CCV
	msgData                  []byte
	expectFail               bool
	tokenTransfer            *tokenTransfer
	numExpectedReceipts      int
	numExpectedVerifications int
	executor                 protocol.UnknownAddress
	aggregatorQualifier      string // which aggregator to query (default, secondary, tertiary)
}

// v2TestCase is for tests that use ExtraArgsV2.
type v2TestCase struct {
	name                     string
	fromSelector             uint64
	toSelector               uint64
	receiver                 protocol.UnknownAddress
	expectFail               bool
	assertExecuted           bool
	numExpectedVerifications int
}

func TestE2ESmoke(t *testing.T) {
	smokeTestConfig := os.Getenv("SMOKE_TEST_CONFIG")
	if smokeTestConfig == "" {
		smokeTestConfig = "../../env-out.toml"
	}
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	lib, err := ccv.NewLib(l, smokeTestConfig)
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
	defaultAggregatorClient := aggregatorClients[evm.DefaultCommitteeVerifierQualifier]

	var indexerClient *ccv.IndexerClient
	if in.IndexerEndpoint != "" {
		indexerClient = ccv.NewIndexerClient(
			zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
			in.IndexerEndpoint)
		require.NotNil(t, indexerClient)
	}

	sel0, sel1, sel2 := chains[0].Details.ChainSelector,
		chains[1].Details.ChainSelector,
		chains[2].Details.ChainSelector

	t.Run("extra args v2", func(t *testing.T) {
		tcs := []v2TestCase{
			{
				name:                     "src->dst msg execution eoa receiver",
				fromSelector:             sel0,
				toSelector:               sel1,
				receiver:                 mustGetEOAReceiverAddress(t, chainMap[sel1]),
				expectFail:               false,
				numExpectedVerifications: 1,
			},
			{
				name:                     "dst->src msg execution eoa receiver",
				fromSelector:             sel1,
				toSelector:               sel0,
				receiver:                 mustGetEOAReceiverAddress(t, chainMap[sel0]),
				expectFail:               false,
				numExpectedVerifications: 1,
			},
			{
				name:                     "1337->3337 msg execution mock receiver",
				fromSelector:             sel0,
				toSelector:               sel2,
				receiver:                 getContractAddress(t, in, sel2, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), evm.DefaultReceiverQualifier, "mock receiver"),
				expectFail:               false,
				numExpectedVerifications: 1,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				runV2TestCase(t, tc, chainMap, defaultAggregatorClient, indexerClient, AssertMessageOptions{
					TickInterval:            1 * time.Second,
					Timeout:                 defaultExecTimeout,
					ExpectedVerifierResults: tc.numExpectedVerifications,
					AssertVerifierLogs:      false,
					AssertExecutorLogs:      false,
				})
			})
		}
	})

	t.Run("extra args v3 messaging", func(t *testing.T) {
		var tcs []v3TestCase
		src, dest := chains[0].Details.ChainSelector, chains[1].Details.ChainSelector
		mvtcsSrcToDest := multiVerifierTestCases(t, src, dest, in, chainMap)
		tcs = append(tcs, mvtcsSrcToDest...)
		// add one test case the other way around (dest->src) to test the reverse lane.
		mvtcsDestToSrc := multiVerifierTestCases(t, dest, src, in, chainMap)
		tcs = append(tcs, mvtcsDestToSrc[0])
		tcs = append(tcs, dataSizeTestCases(t, src, dest, in, chainMap)...)
		tcs = append(tcs, customExecutorTestCase(t, src, dest, in))
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				var receiverStartBalance *big.Int
				var destTokenAddress protocol.UnknownAddress
				var tokenAmount cciptestinterfaces.TokenAmount
				if tc.tokenTransfer != nil {
					tokenAmount = tc.tokenTransfer.tokenAmount
					destTokenAddress = getContractAddress(t, in, tc.dstSelector, tc.tokenTransfer.destTokenRef.Type, tc.tokenTransfer.destTokenRef.Version.String(), tc.tokenTransfer.destTokenRef.Qualifier, "token on destination chain")
					receiverStartBalance, err = chainMap[tc.dstSelector].GetTokenBalance(ctx, tc.receiver, destTokenAddress)
					require.NoError(t, err)
					l.Info().Str("Receiver", tc.receiver.String()).Str("Token", destTokenAddress.String()).Uint64("StartBalance", receiverStartBalance.Uint64()).Msg("Receiver start balance")
				}
				seqNo, err := chainMap[tc.srcSelector].GetExpectedNextSequenceNumber(ctx, tc.dstSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				sendMessageResult, err := chainMap[tc.srcSelector].SendMessage(
					ctx, tc.dstSelector, cciptestinterfaces.MessageFields{
						Receiver:    tc.receiver,
						Data:        tc.msgData,
						TokenAmount: tokenAmount,
					}, cciptestinterfaces.MessageOptions{
						Version:           3,
						ExecutionGasLimit: 200_000,
						FinalityConfig:    tc.finality,
						Executor:          tc.executor,
						CCVs:              tc.ccvs,
					})
				require.NoError(t, err)
				require.Lenf(t, sendMessageResult.ReceiptIssuers, tc.numExpectedReceipts, "expected %d receipt issuers, got %d", tc.numExpectedReceipts, len(sendMessageResult.ReceiptIssuers))
				sentEvent, err := chainMap[tc.srcSelector].WaitOneSentEventBySeqNo(ctx, tc.dstSelector, seqNo, defaultSentTimeout)
				require.NoError(t, err)
				messageID := sentEvent.MessageID

				// Select the appropriate aggregator client based on the test case's aggregatorQualifier
				aggregatorClient := defaultAggregatorClient
				if tc.aggregatorQualifier != "" && tc.aggregatorQualifier != evm.DefaultCommitteeVerifierQualifier {
					if client, ok := aggregatorClients[tc.aggregatorQualifier]; ok {
						aggregatorClient = client
					}
				}
				testCtx := NewTestingContext(t, t.Context(), chainMap, aggregatorClient, indexerClient)
				result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
					TickInterval:            1 * time.Second,
					ExpectedVerifierResults: tc.numExpectedVerifications,
					Timeout:                 defaultExecTimeout,
					AssertVerifierLogs:      false,
					AssertExecutorLogs:      false,
				})
				require.NoError(t, err)
				require.NotNil(t, result.AggregatedResult)
				require.Len(t, result.IndexedVerifications.Results, tc.numExpectedVerifications)

				e, err := chainMap[tc.dstSelector].WaitOneExecEventBySeqNo(ctx, tc.srcSelector, seqNo, defaultExecTimeout)
				require.NoError(t, err)
				require.NotNil(t, e)
				if tc.expectFail {
					require.Equal(t, cciptestinterfaces.ExecutionStateFailure, e.State)
				} else {
					require.Equalf(t, cciptestinterfaces.ExecutionStateSuccess, e.State, "unexpected state, return data: %x", e.ReturnData)
				}
				if receiverStartBalance != nil {
					receiverEndBalance, err := chainMap[tc.dstSelector].GetTokenBalance(ctx, tc.receiver, destTokenAddress)
					require.NoError(t, err)
					require.Equal(t, receiverStartBalance.Add(receiverStartBalance, tc.tokenTransfer.tokenAmount.Amount), receiverEndBalance)
					l.Info().Str("Receiver", tc.receiver.String()).Str("Token", destTokenAddress.String()).Uint64("EndBalance", receiverEndBalance.Uint64()).Msg("t")
				}
			})
		}
	})

	t.Run("extra args v3 token transfer", func(t *testing.T) {
		var (
			sourceSelector = sel0
			sourceChain    = chainMap[sourceSelector]
			destSelector   = sel1
			destChain      = chainMap[destSelector]
		)
		runTokenTransferTestCase := func(t *testing.T, combo evm.TokenCombination, finalityConfig uint16, receiver protocol.UnknownAddress) {
			sender := mustGetSenderAddress(t, sourceChain)

			srcToken := getTokenAddress(t, in, sourceSelector, combo.SourcePoolAddressRef().Qualifier)
			destToken := getTokenAddress(t, in, destSelector, combo.DestPoolAddressRef().Qualifier)

			startBal, err := destChain.GetTokenBalance(ctx, receiver, destToken)
			require.NoError(t, err)
			l.Info().Str("Receiver", receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", combo.DestPoolAddressRef().Qualifier).Msg("receiver start balance")

			srcStartBal, err := sourceChain.GetTokenBalance(ctx, sender, srcToken)
			require.NoError(t, err)
			l.Info().Str("Sender", sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("sender start balance")

			seqNo, err := sourceChain.GetExpectedNextSequenceNumber(ctx, destSelector)
			require.NoError(t, err)
			l.Info().Uint64("SeqNo", seqNo).Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("expecting sequence number")

			messageOptions := cciptestinterfaces.MessageOptions{
				Version:           3,
				ExecutionGasLimit: 200_000,
				FinalityConfig:    finalityConfig,
				Executor:          getContractAddress(t, in, sel0, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
			}

			sendRes, err := sourceChain.SendMessage(
				ctx, destSelector,
				cciptestinterfaces.MessageFields{
					Receiver: receiver,
					TokenAmount: cciptestinterfaces.TokenAmount{
						Amount:       big.NewInt(1000),
						TokenAddress: srcToken,
					},
				},
				messageOptions,
			)
			require.NoError(t, err)
			require.NotNil(t, sendRes)
			require.Len(t, sendRes.ReceiptIssuers, combo.ExpectedReceiptIssuers(), "expected %d receipt issuers for %s token", combo.ExpectedReceiptIssuers(), combo.SourcePoolAddressRef().Qualifier)

			sentEvt, err := sourceChain.WaitOneSentEventBySeqNo(ctx, destSelector, seqNo, defaultSentTimeout)
			require.NoError(t, err)
			msgID := sentEvt.MessageID

			testCtx := NewTestingContext(t, ctx, chainMap, defaultAggregatorClient, indexerClient)

			res, err := testCtx.AssertMessage(msgID, AssertMessageOptions{
				TickInterval:            1 * time.Second,
				Timeout:                 45 * time.Second,
				ExpectedVerifierResults: combo.ExpectedVerifierResults(),
				AssertVerifierLogs:      false,
				AssertExecutorLogs:      false,
			})

			require.NoError(t, err)
			require.NotNil(t, res.AggregatedResult)

			execEvt, err := destChain.WaitOneExecEventBySeqNo(ctx, sourceSelector, seqNo, 45*time.Second)
			require.NoError(t, err)
			require.NotNil(t, execEvt)
			require.Equalf(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State, "unexpected state, return data: %x", execEvt.ReturnData)

			endBal, err := destChain.GetTokenBalance(ctx, receiver, destToken)
			require.NoError(t, err)
			require.Equal(t, new(big.Int).Add(new(big.Int).Set(startBal), big.NewInt(1000)), endBal)
			l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", combo.DestPoolAddressRef().Qualifier).Msg("receiver end balance")

			srcEndBal, err := sourceChain.GetTokenBalance(ctx, sender, srcToken)
			require.NoError(t, err)
			require.Equal(t, new(big.Int).Sub(new(big.Int).Set(srcStartBal), big.NewInt(1000)), srcEndBal)
			l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("sender end balance")
		}
		for _, combo := range evm.AllTokenCombinations() {
			receiver := mustGetEOAReceiverAddress(t, destChain)
			t.Run(fmt.Sprintf("src_dst msg execution with EOA receiver and token transfer (%s)", combo.SourcePoolAddressRef().Qualifier), func(t *testing.T) {
				runTokenTransferTestCase(t, combo, combo.FinalityConfig(), receiver)
			})
		}

		t.Run("USDC", func(t *testing.T) {
			usdcCombo := evm.USDCTokenPoolCombination()
			receiver := mustGetEOAReceiverAddress(t, destChain)
			runTokenTransferTestCase(t, usdcCombo, usdcCombo.FinalityConfig(), receiver)
		})

		for _, combo := range evm.All17TokenCombinations() {
			receiver := mustGetEOAReceiverAddress(t, destChain)
			mockReceiver := getContractAddress(
				t,
				in,
				destSelector,
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				evm.DefaultReceiverQualifier,
				"default mock receiver",
			)
			t.Run(fmt.Sprintf("src_dst msg execution with EOA receiver and token transfer 1.7.0 (%s) default finality", combo.SourcePoolAddressRef().Qualifier), func(t *testing.T) {
				runTokenTransferTestCase(t, combo, 0, receiver)
			})
			t.Run(fmt.Sprintf("src_dst msg execution with mock receiver and token transfer 1.7.0 (%s) default finality", combo.SourcePoolAddressRef().Qualifier), func(t *testing.T) {
				runTokenTransferTestCase(t, combo, 0, mockReceiver)
			})
		}
	})
}

func runV2TestCase(
	t *testing.T,
	tc v2TestCase,
	chainMap map[uint64]cciptestinterfaces.CCIP17,
	defaultAggregatorClient *ccv.AggregatorClient,
	indexerClient *ccv.IndexerClient,
	assertMessageOptions AssertMessageOptions,
) {
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	seqNo, err := chainMap[tc.fromSelector].GetExpectedNextSequenceNumber(ctx, tc.toSelector)
	require.NoError(t, err)
	l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
	_, err = chainMap[tc.fromSelector].SendMessage(ctx, tc.toSelector, cciptestinterfaces.MessageFields{
		Receiver: tc.receiver,
		Data:     []byte{},
	}, cciptestinterfaces.MessageOptions{
		Version:             2,
		ExecutionGasLimit:   200_000,
		OutOfOrderExecution: true,
	})
	require.NoError(t, err)

	sentEvent, err := chainMap[tc.fromSelector].WaitOneSentEventBySeqNo(ctx, tc.toSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)
	messageID := sentEvent.MessageID

	testCtx := NewTestingContext(t, ctx, chainMap, defaultAggregatorClient, indexerClient)
	result, err := testCtx.AssertMessage(messageID, assertMessageOptions)
	require.NoError(t, err)
	require.NotNil(t, result.AggregatedResult)
	require.Len(t, result.IndexedVerifications.Results, tc.numExpectedVerifications)

	if tc.assertExecuted {
		e, err := chainMap[tc.toSelector].WaitOneExecEventBySeqNo(ctx, tc.fromSelector, seqNo, defaultExecTimeout)
		require.NoError(t, err)
		require.NotNil(t, e)

		if tc.expectFail {
			require.Equalf(t,
				cciptestinterfaces.ExecutionStateFailure,
				e.State,
				"unexpected state, return data: %x",
				e.ReturnData)
		} else {
			require.Equalf(t,
				cciptestinterfaces.ExecutionStateSuccess,
				e.State,
				"unexpected state, return data: %x",
				e.ReturnData)
		}
	}
}

func mustGetEOAReceiverAddress(t *testing.T, c cciptestinterfaces.CCIP17) protocol.UnknownAddress {
	receiver, err := c.GetEOAReceiverAddress()
	require.NoError(t, err)
	return receiver
}

func mustGetSenderAddress(t *testing.T, c cciptestinterfaces.CCIP17) protocol.UnknownAddress {
	sender, err := c.GetSenderAddress()
	require.NoError(t, err)
	return sender
}

func getContractAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) protocol.UnknownAddress {
	ref, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	require.NoErrorf(t, err, "failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s",
		contractName, chainSelector, contractType, version)
	return protocol.UnknownAddress(common.HexToAddress(ref.Address).Bytes())
}

func getTokenAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64, qualifier string) protocol.UnknownAddress {
	return getContractAddress(t, ccvCfg, chainSelector,
		datastore.ContractType(burn_mint_erc20_with_drip.ContractType),
		burn_mint_erc20_with_drip.Deploy.Version(),
		qualifier,
		"burn mint erc677")
}

func customExecutorTestCase(t *testing.T, src, dest uint64, in *ccv.Cfg) v3TestCase {
	return v3TestCase{
		name:        "custom executor",
		srcSelector: src,
		dstSelector: dest,
		finality:    1,
		receiver: getContractAddress(
			t,
			in,
			dest,
			datastore.ContractType(mock_receiver.ContractType),
			mock_receiver.Deploy.Version(),
			evm.DefaultReceiverQualifier,
			"default mock receiver",
		),
		msgData: []byte("custom executor test"),
		ccvs: []protocol.CCV{
			{
				CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ResolverType), committee_verifier.Deploy.Version(), evm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
		numExpectedReceipts:      3,
		expectFail:               false,
		numExpectedVerifications: 1,
		executor:                 getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.CustomExecutorQualifier, "executor"),
	}
}

func dataSizeTestCases(t *testing.T, src, dest uint64, in *ccv.Cfg, c map[uint64]cciptestinterfaces.CCIP17) []v3TestCase {
	maxDataBytes, err := c[dest].GetMaxDataBytes(t.Context(), dest)
	require.NoError(t, err)
	return []v3TestCase{
		{
			name:        "max data size",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver: getContractAddress(
				t,
				in,
				dest,
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				evm.DefaultReceiverQualifier,
				"default mock receiver",
			),
			msgData: bytes.Repeat([]byte("a"), int(maxDataBytes)),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ResolverType), committee_verifier.Deploy.Version(), evm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
					Args:       []byte{},
					ArgsLen:    0,
				},
			},
			numExpectedReceipts:      3,
			expectFail:               false,
			numExpectedVerifications: 1,
			executor:                 getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
		},
	}
}

// multiVerifierTestCases returns a list of test cases for testing multi-verifier scenarios.
func multiVerifierTestCases(t *testing.T, src, dest uint64, in *ccv.Cfg, c map[uint64]cciptestinterfaces.CCIP17) []v3TestCase {
	return []v3TestCase{
		{
			name:        "EOA receiver and default committee verifier",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    mustGetEOAReceiverAddress(t, c[dest]),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.DefaultCommitteeVerifierQualifier,
						"committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
			},
			// default verifier
			numExpectedVerifications: 1,
			// default executor and default committee verifier
			numExpectedReceipts: 3,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
		},
		{
			name:        "EOA receiver and secondary committee verifier",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    mustGetEOAReceiverAddress(t, c[dest]),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
				// still include default verifier, because the default aggregator client gets queried in this test.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
			},
			// default and secondary verifiers will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default and secondary committee verifiers, network fee.
			numExpectedReceipts: 4,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
		},
		{
			name:        "receiver w/ secondary verifier required",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver: getContractAddress(
				t,
				in,
				dest,
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				evm.SecondaryReceiverQualifier,
				"secondary mock receiver",
			),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
			},
			// default verifier and secondary verifier will verify so should be two verifications.
			// default verifies because its the message discovery mechanism, despite there being no onchain
			// receipt for the default verifier.
			numExpectedVerifications: 2,
			// default executor and secondary committee verifier and network fee.
			numExpectedReceipts: 3,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
			aggregatorQualifier: evm.SecondaryCommitteeVerifierQualifier,
		},
		{
			name:        "receiver w/ secondary required and tertiary optional threshold=1",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), evm.SecondaryReceiverQualifier, "secondary mock receiver"),
			ccvs: []protocol.CCV{
				// secondary is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
				// tertiary is optional with threshold=1 on the dest, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
			},
			// default, secondary and tertiary verifiers will verify so should be three verifications.
			// default verifies because its the message discovery mechanism, despite there being no onchain
			// receipt for the default verifier.
			numExpectedVerifications: 3,
			// default executor, secondary and tertiary committee verifiers, and network fee.
			numExpectedReceipts: 4,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
			aggregatorQualifier: evm.SecondaryCommitteeVerifierQualifier,
		},
		{
			name:        "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies all three",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), evm.QuaternaryReceiverQualifier, "quaternary mock receiver"),
			ccvs: []protocol.CCV{
				// default is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
				// secondary and tertiary are optional with threshold=1 on the dest, so one of them should be retrieved.
				// We specify both here, but one may not end up getting included in the message execution on the dest.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
				},
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
					),
				},
			},
			// default, secondary and tertiary verifiers will verify so should be three verifications.
			numExpectedVerifications: 3,
			// default executor and default, secondary and tertiary committee verifiers, and network fee.
			numExpectedReceipts: 5,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
		},
		{
			name:        "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and secondary",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), evm.QuaternaryReceiverQualifier, "quaternary mock receiver"),
			ccvs: []protocol.CCV{
				// default is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
				// secondary and tertiary are optional with threshold=1 on the dest, so one of them should be retrieved.
				// We specify only secondary here, which should be enough since threshold=1 (out of 2).
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
				},
			},
			// default and secondary verifiers will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default and secondary committee verifiers, and network fee.
			numExpectedReceipts: 4,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
		},
		{
			name:        "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and tertiary",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), evm.QuaternaryReceiverQualifier, "quaternary mock receiver"),
			ccvs: []protocol.CCV{
				// default is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
				// secondary and tertiary are optional with threshold=1 on the dest, so one of them should be retrieved.
				// We specify only tertiary here, which should be enough since threshold=1 (out of 2).
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverType),
						committee_verifier.Deploy.Version(),
						evm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
					),
				},
			},
			// default and tertiary verifiers will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default and tertiary committee verifiers, and network fee.
			numExpectedReceipts: 4,
			executor:            getContractAddress(t, in, src, datastore.ContractType(executor.ProxyType), executor.DeployProxy.Version(), evm.DefaultExecutorQualifier, "executor"),
		},
	}
}
