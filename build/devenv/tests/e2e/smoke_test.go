package e2e

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc677"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/globals"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/devenv/evm"
)

const (
	defaultSentTimeout = 10 * time.Second
	defaultExecTimeout = 40 * time.Second
)

func defaultAggregatorPort(in *ccv.Cfg) int {
	for _, aggregator := range in.Aggregator {
		if aggregator.CommitteeName == "default" {
			return aggregator.HostPort
		}
	}
	panic(fmt.Sprintf("default aggregator not found, expected to find a default aggregator in the configuration, got: %+v", in.Aggregator))
}

type tokenTransfer struct {
	tokenAmount  cciptestinterfaces.TokenAmount
	destTokenRef datastore.AddressRef
}

type testcase struct {
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
}

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	require.Len(t, selectors, 3, "expected 3 chains for this test in the environment")

	c, err := ccvEvm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	indexerURL := fmt.Sprintf("http://127.0.0.1:%d", in.Indexer.Port)
	defaultAggregatorAddr := fmt.Sprintf("127.0.0.1:%d", defaultAggregatorPort(in))

	defaultAggregatorClient, err := ccv.NewAggregatorClient(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		defaultAggregatorAddr)
	require.NoError(t, err)
	require.NotNil(t, defaultAggregatorClient)
	t.Cleanup(func() {
		defaultAggregatorClient.Close()
	})

	indexerClient := ccv.NewIndexerClient(
		zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
		indexerURL)
	require.NotNil(t, indexerClient)

	t.Run("extra args v2", func(t *testing.T) {
		tcs := []struct {
			name                     string
			fromSelector             uint64
			toSelector               uint64
			receiver                 protocol.UnknownAddress
			expectFail               bool
			numExpectedVerifications int
		}{
			{
				name:                     "src->dst msg execution eoa receiver",
				fromSelector:             selectors[0],
				toSelector:               selectors[1],
				receiver:                 mustGetEOAReceiverAddress(t, c, selectors[1]),
				expectFail:               false,
				numExpectedVerifications: 1,
			},
			{
				name:                     "dst->src msg execution eoa receiver",
				fromSelector:             selectors[1],
				toSelector:               selectors[0],
				receiver:                 mustGetEOAReceiverAddress(t, c, selectors[0]),
				expectFail:               false,
				numExpectedVerifications: 1,
			},
			{
				name:                     "1337->3337 msg execution mock receiver",
				fromSelector:             selectors[0],
				toSelector:               selectors[2],
				receiver:                 getContractAddress(t, in, selectors[2], datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.DefaultReceiverQualifier, "mock receiver"),
				expectFail:               false,
				numExpectedVerifications: 1,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := c.GetExpectedNextSequenceNumber(ctx, tc.fromSelector, tc.toSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				_, err = c.SendMessage(ctx, tc.fromSelector, tc.toSelector, cciptestinterfaces.MessageFields{
					Receiver: tc.receiver,
					Data:     []byte{},
				}, cciptestinterfaces.MessageOptions{
					Version:             2,
					GasLimit:            200_000,
					OutOfOrderExecution: true,
				})
				require.NoError(t, err)

				sentEvent, err := c.WaitOneSentEventBySeqNo(ctx, tc.fromSelector, tc.toSelector, seqNo, defaultSentTimeout)
				require.NoError(t, err)
				messageID := sentEvent.MessageID

				testCtx := NewTestingContext(t, ctx, c, defaultAggregatorClient, indexerClient)
				result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
					TickInterval:            1 * time.Second,
					Timeout:                 defaultExecTimeout,
					ExpectedVerifierResults: tc.numExpectedVerifications,
					AssertVerifierLogs:      false,
					AssertExecutorLogs:      false,
				})
				require.NoError(t, err)
				require.NotNil(t, result.AggregatedResult)
				require.Len(t, result.IndexedVerifications.VerifierResults, tc.numExpectedVerifications)

				e, err := c.WaitOneExecEventBySeqNo(ctx, tc.fromSelector, tc.toSelector, seqNo, defaultExecTimeout)
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
			})
		}
	})

	t.Run("extra args v3 messaging", func(t *testing.T) {
		var tcs []testcase
		src, dest := selectors[0], selectors[1]
		mvtcsSrcToDest := multiVerifierTestCases(t, src, dest, in, c)
		tcs = append(tcs, mvtcsSrcToDest...)
		// add one test case the other way around (dest->src) to test the reverse lane.
		mvtcsDestToSrc := multiVerifierTestCases(t, dest, src, in, c)
		tcs = append(tcs, mvtcsDestToSrc[0])
		tcs = append(tcs, dataSizeTestCases(t, src, dest, in, c)...)
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				var receiverStartBalance *big.Int
				var destTokenAddress protocol.UnknownAddress
				var tokenAmounts []cciptestinterfaces.TokenAmount
				if tc.tokenTransfer != nil {
					tokenAmounts = append(tokenAmounts, tc.tokenTransfer.tokenAmount)
					destTokenAddress = getContractAddress(t, in, tc.dstSelector, tc.tokenTransfer.destTokenRef.Type, tc.tokenTransfer.destTokenRef.Version.String(), tc.tokenTransfer.destTokenRef.Qualifier, "token on destination chain")
					receiverStartBalance, err = c.GetTokenBalance(ctx, tc.dstSelector, tc.receiver, destTokenAddress)
					require.NoError(t, err)
					l.Info().Str("Receiver", tc.receiver.String()).Str("Token", destTokenAddress.String()).Uint64("StartBalance", receiverStartBalance.Uint64()).Msg("Receiver start balance")
				}
				seqNo, err := c.GetExpectedNextSequenceNumber(ctx, tc.srcSelector, tc.dstSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				sendMessageResult, err := c.SendMessage(
					ctx, tc.srcSelector, tc.dstSelector, cciptestinterfaces.MessageFields{
						Receiver:     tc.receiver,
						Data:         tc.msgData,
						TokenAmounts: tokenAmounts,
					}, cciptestinterfaces.MessageOptions{
						Version:        3,
						GasLimit:       200_000,
						FinalityConfig: tc.finality,
						Executor:       getContractAddress(t, in, tc.srcSelector, datastore.ContractType(executor.ContractType), executor.Deploy.Version(), "", "executor"),
						CCVs:           tc.ccvs,
					})
				require.NoError(t, err)
				require.Lenf(t, sendMessageResult.ReceiptIssuers, tc.numExpectedReceipts, "expected %d receipt issuers, got %d", tc.numExpectedReceipts, len(sendMessageResult.ReceiptIssuers))
				sentEvent, err := c.WaitOneSentEventBySeqNo(ctx, tc.srcSelector, tc.dstSelector, seqNo, defaultSentTimeout)
				require.NoError(t, err)
				messageID := sentEvent.MessageID

				testCtx := NewTestingContext(t, t.Context(), c, defaultAggregatorClient, indexerClient)
				result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
					TickInterval:            1 * time.Second,
					ExpectedVerifierResults: tc.numExpectedVerifications,
					Timeout:                 defaultExecTimeout,
					AssertVerifierLogs:      false,
					AssertExecutorLogs:      false,
				})
				require.NoError(t, err)
				require.NotNil(t, result.AggregatedResult)
				require.Len(t, result.IndexedVerifications.VerifierResults, tc.numExpectedVerifications)

				e, err := c.WaitOneExecEventBySeqNo(ctx, tc.srcSelector, tc.dstSelector, seqNo, defaultExecTimeout)
				require.NoError(t, err)
				require.NotNil(t, e)
				if tc.expectFail {
					require.Equal(t, cciptestinterfaces.ExecutionStateFailure, e.State)
				} else {
					require.Equalf(t, cciptestinterfaces.ExecutionStateSuccess, e.State, "unexpected state, return data: %x", e.ReturnData)
				}
				if receiverStartBalance != nil {
					receiverEndBalance, err := c.GetTokenBalance(ctx, tc.dstSelector, tc.receiver, destTokenAddress)
					require.NoError(t, err)
					require.Equal(t, receiverStartBalance.Add(receiverStartBalance, tc.tokenTransfer.tokenAmount.Amount), receiverEndBalance)
					l.Info().Str("Receiver", tc.receiver.String()).Str("Token", destTokenAddress.String()).Uint64("EndBalance", receiverEndBalance.Uint64()).Msg("t")
				}
			})
		}
	})

	t.Run("extra args v3 token transfer", func(t *testing.T) {
		runTokenTransferTestCase := func(t *testing.T, combo ccvEvm.TokenCombination, finalityConfig uint16, receiver protocol.UnknownAddress) {
			sender := mustGetSenderAddress(t, c, selectors[0])

			srcToken := getTokenAddress(t, in, selectors[0], combo.SourcePoolAddressRef().Qualifier)
			destToken := getTokenAddress(t, in, selectors[1], combo.DestPoolAddressRef().Qualifier)

			startBal, err := c.GetTokenBalance(ctx, selectors[1], receiver, destToken)
			require.NoError(t, err)
			l.Info().Str("Receiver", receiver.String()).Uint64("StartBalance", startBal.Uint64()).Str("Token", combo.DestPoolAddressRef().Qualifier).Msg("receiver start balance")

			srcStartBal, err := c.GetTokenBalance(ctx, selectors[0], sender, srcToken)
			require.NoError(t, err)
			l.Info().Str("Sender", sender.String()).Uint64("SrcStartBalance", srcStartBal.Uint64()).Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("sender start balance")

			seqNo, err := c.GetExpectedNextSequenceNumber(ctx, selectors[0], selectors[1])
			require.NoError(t, err)
			l.Info().Uint64("SeqNo", seqNo).Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("expecting sequence number")

			messageOptions := cciptestinterfaces.MessageOptions{
				Version:        3,
				GasLimit:       200_000,
				FinalityConfig: finalityConfig,
				Executor:       getContractAddress(t, in, selectors[0], datastore.ContractType(executor.ContractType), executor.Deploy.Version(), "", "executor"),
			}

			sendRes, err := c.SendMessage(
				ctx, selectors[0], selectors[1],
				cciptestinterfaces.MessageFields{
					Receiver: receiver,
					TokenAmounts: []cciptestinterfaces.TokenAmount{{
						Amount:       big.NewInt(1000),
						TokenAddress: srcToken,
					}},
				},
				messageOptions,
			)
			require.NoError(t, err)
			require.NotNil(t, sendRes)
			require.Len(t, sendRes.ReceiptIssuers, combo.ExpectedReceiptIssuers(), "expected %d receipt issuers for %s token", combo.ExpectedReceiptIssuers(), combo.SourcePoolAddressRef().Qualifier)

			sentEvt, err := c.WaitOneSentEventBySeqNo(ctx, selectors[0], selectors[1], seqNo, defaultSentTimeout)
			require.NoError(t, err)
			msgID := sentEvt.MessageID

			testCtx := NewTestingContext(t, ctx, c, defaultAggregatorClient, indexerClient)

			res, err := testCtx.AssertMessage(msgID, AssertMessageOptions{
				TickInterval:            1 * time.Second,
				Timeout:                 45 * time.Second,
				ExpectedVerifierResults: combo.ExpectedVerifierResults(),
				AssertVerifierLogs:      false,
				AssertExecutorLogs:      false,
			})

			require.NoError(t, err)
			require.NotNil(t, res.AggregatedResult)

			execEvt, err := c.WaitOneExecEventBySeqNo(ctx, selectors[0], selectors[1], seqNo, 45*time.Second)
			require.NoError(t, err)
			require.NotNil(t, execEvt)
			require.Equalf(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State, "unexpected state, return data: %x", execEvt.ReturnData)

			endBal, err := c.GetTokenBalance(ctx, selectors[1], receiver, destToken)
			require.NoError(t, err)
			require.Equal(t, new(big.Int).Add(new(big.Int).Set(startBal), big.NewInt(1000)), endBal)
			l.Info().Uint64("EndBalance", endBal.Uint64()).Str("Token", combo.DestPoolAddressRef().Qualifier).Msg("receiver end balance")

			srcEndBal, err := c.GetTokenBalance(ctx, selectors[0], sender, srcToken)
			require.NoError(t, err)
			require.Equal(t, new(big.Int).Sub(new(big.Int).Set(srcStartBal), big.NewInt(1000)), srcEndBal)
			l.Info().Uint64("SrcEndBalance", srcEndBal.Uint64()).Str("Token", combo.SourcePoolAddressRef().Qualifier).Msg("sender end balance")
		}
		for _, combo := range ccvEvm.AllTokenCombinations() {
			receiver := mustGetEOAReceiverAddress(t, c, selectors[1])
			t.Run(fmt.Sprintf("src_dst msg execution with EOA receiver and token transfer (%s)", combo.SourcePoolAddressRef().Qualifier), func(t *testing.T) {
				runTokenTransferTestCase(t, combo, combo.FinalityConfig(), receiver)
			})
		}
		for _, combo := range ccvEvm.All17TokenCombinations() {
			receiver := mustGetEOAReceiverAddress(t, c, selectors[1])
			mockReceiver := getContractAddress(
				t,
				in,
				selectors[1],
				datastore.ContractType(mock_receiver.ContractType),
				mock_receiver.Deploy.Version(),
				ccvEvm.DefaultReceiverQualifier,
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

func mustGetEOAReceiverAddress(t *testing.T, c *ccvEvm.CCIP17EVM, chainSelector uint64) protocol.UnknownAddress {
	receiver, err := c.GetEOAReceiverAddress(chainSelector)
	require.NoError(t, err)
	return receiver
}

func mustGetSenderAddress(t *testing.T, c *ccvEvm.CCIP17EVM, chainSelector uint64) protocol.UnknownAddress {
	sender, err := c.GetSenderAddress(chainSelector)
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
		datastore.ContractType(burn_mint_erc677.ContractType),
		burn_mint_erc677.Deploy.Version(),
		qualifier,
		"burn mint erc677")
}

func dataSizeTestCases(t *testing.T, src, dest uint64, in *ccv.Cfg, c *ccvEvm.CCIP17EVM) []testcase {
	maxDataBytes, err := c.GetMaxDataBytes(t.Context(), dest)
	require.NoError(t, err)
	return []testcase{
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
				ccvEvm.DefaultReceiverQualifier,
				"default mock receiver",
			),
			msgData: bytes.Repeat([]byte("a"), int(maxDataBytes)),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ResolverProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
					Args:       []byte{},
					ArgsLen:    0,
				},
			},
			numExpectedReceipts:      2,
			expectFail:               false,
			numExpectedVerifications: 1,
		},
	}
}

// multiVerifierTestCases returns a list of test cases for testing multi-verifier scenarios.
func multiVerifierTestCases(t *testing.T, src, dest uint64, in *ccv.Cfg, c *ccvEvm.CCIP17EVM) []testcase {
	return []testcase{
		{
			name:        "EOA receiver and default committee verifier",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    mustGetEOAReceiverAddress(t, c, dest),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ResolverProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
					Args:       []byte{},
					ArgsLen:    0,
				},
			},
			// default verifier
			numExpectedVerifications: 1,
			// default executor and default committee verifier
			numExpectedReceipts: 2,
		},
		{
			name:        "EOA receiver and secondary committee verifier",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    mustGetEOAReceiverAddress(t, c, dest),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier,
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
			},
			// default verifier and secondary verifier will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default verifier and secondary committee verifier.
			numExpectedReceipts: 3,
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
				ccvEvm.SecondaryReceiverQualifier,
				"secondary mock receiver",
			),
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier,
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
			},
			// default verifier and secondary verifier will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default verifier and secondary committee verifier.
			numExpectedReceipts: 3,
		},
		{
			name:        "receiver w/ secondary required and tertiary optional threshold=1",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.SecondaryReceiverQualifier, "secondary mock receiver"),
			ccvs: []protocol.CCV{
				// secondary is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier, "secondary committee verifier proxy",
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.DefaultCommitteeVerifierQualifier,
						"default committee verifier proxy",
					),
				},
			},
			// default, secondary and tertiary verifiers will verify so should be three verifications.
			numExpectedVerifications: 3,
			// default executor, default verifier, secondary and tertiary committee verifiers.
			numExpectedReceipts: 4,
		},
		{
			name:        "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies all three",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.QuaternaryReceiverQualifier, "quaternary mock receiver"),
			ccvs: []protocol.CCV{
				// default is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.DefaultCommitteeVerifierQualifier,
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
				},
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
					),
				},
			},
			// default, secondary and tertiary verifiers will verify so should be three verifications.
			numExpectedVerifications: 3,
			// default executor and default, secondary and tertiary committee verifiers
			numExpectedReceipts: 4,
		},
		{
			name:        "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and secondary",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.QuaternaryReceiverQualifier, "quaternary mock receiver"),
			ccvs: []protocol.CCV{
				// default is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.DefaultCommitteeVerifierQualifier,
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
				},
			},
			// default and secondary verifiers will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default and secondary committee verifiers
			numExpectedReceipts: 3,
		},
		{
			name:        "receiver w/ default required, secondary and tertiary optional, threshold=1, message specifies default and tertiary",
			srcSelector: src,
			dstSelector: dest,
			finality:    1,
			receiver:    getContractAddress(t, in, dest, datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.QuaternaryReceiverQualifier, "quaternary mock receiver"),
			ccvs: []protocol.CCV{
				// default is required, so it should be retrieved.
				{
					CCVAddress: getContractAddress(
						t,
						in,
						src,
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.DefaultCommitteeVerifierQualifier,
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
						datastore.ContractType(committee_verifier.ResolverProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
					),
				},
			},
			// default and tertiary verifiers will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor, default and tertiary committee verifiers
			numExpectedReceipts: 3,
		},
	}
}

// ============================================================================
// RMN Curse Helper Functions
// ============================================================================

// chainSelectorToSubject converts a chain selector to a bytes16 curse subject.
func chainSelectorToSubject(chainSel uint64) [16]byte {
	var result [16]byte
	// Convert the uint64 to bytes and place it in the last 8 bytes of the array
	binary.BigEndian.PutUint64(result[8:], chainSel)
	return result
}

// globalCurseSubject returns the global curse constant.
func globalCurseSubject() [16]byte {
	return globals.GlobalCurseSubject()
}

// ============================================================================
// RMN Curse Tests
// ============================================================================

func TestRMNCurseLane(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	require.Len(t, selectors, 3, "expected 3 chains for this test in the environment")

	c, err := ccvEvm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

	chain0, chain1, chain2 := selectors[0], selectors[1], selectors[2]
	receiver := mustGetEOAReceiverAddress(t, c, chain1)

	// 1. Send baseline message (chain0 -> chain1) to verify lane works
	l.Info().Msg("Step 1: Sending baseline message from chain0 to chain1")
	seqNo, err := c.GetExpectedNextSequenceNumber(ctx, chain0, chain1)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain1, cciptestinterfaces.MessageFields{
		Receiver: receiver,
		Data:     []byte("baseline message"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)

	execEvt, err := c.WaitOneExecEventBySeqNo(ctx, chain0, chain1, seqNo, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State, "baseline message should succeed")
	l.Info().Msg("Baseline message executed successfully")

	// 2. Apply bidirectional lane curse (chain0 <-> chain1)
	l.Info().Msg("Step 2: Applying bidirectional lane curse between chain0 and chain1")
	err = c.ApplyCurse(ctx, chain0, [][16]byte{chainSelectorToSubject(chain1)})
	require.NoError(t, err)
	err = c.ApplyCurse(ctx, chain1, [][16]byte{chainSelectorToSubject(chain0)})
	require.NoError(t, err)

	// 3. Wait for curse detector to poll and detect curses
	l.Info().Msg("Step 3: Waiting 5 seconds for curse detector to detect curses")
	time.Sleep(5 * time.Second)

	// 4. Verify curse state
	l.Info().Msg("Step 4: Verifying curse state")
	isCursed, err := c.VerifyCurseState(ctx, chain0, chainSelectorToSubject(chain1))
	require.NoError(t, err)
	require.True(t, isCursed, "chain1 should be cursed on chain0")

	isCursed, err = c.VerifyCurseState(ctx, chain1, chainSelectorToSubject(chain0))
	require.NoError(t, err)
	require.True(t, isCursed, "chain0 should be cursed on chain1")

	// 5. Attempt to send message chain0 -> chain1 (should fail/timeout)
	l.Info().Msg("Step 5: Attempting to send message on cursed lane (should not execute)")
	seqNo, err = c.GetExpectedNextSequenceNumber(ctx, chain0, chain1)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain1, cciptestinterfaces.MessageFields{
		Receiver: receiver,
		Data:     []byte("cursed message"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)

	// Wait a bit and verify message does NOT get executed
	time.Sleep(10 * time.Second)
	// Try to get execution event with short timeout - should timeout/fail
	execEvt, err = c.WaitOneExecEventBySeqNo(ctx, chain0, chain1, seqNo, 5*time.Second)
	if err == nil {
		require.NotEqual(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State,
			"message on cursed lane should not execute successfully")
	}
	l.Info().Msg("Confirmed: message on cursed lane was not executed")

	// 6. Verify chain0 -> chain2 still works (uncursed lane)
	l.Info().Msg("Step 6: Verifying uncursed lane (chain0 -> chain2) still works")
	receiver2 := mustGetEOAReceiverAddress(t, c, chain2)
	seqNo2, err := c.GetExpectedNextSequenceNumber(ctx, chain0, chain2)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain2, cciptestinterfaces.MessageFields{
		Receiver: receiver2,
		Data:     []byte("uncursed lane message"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)

	execEvt2, err := c.WaitOneExecEventBySeqNo(ctx, chain0, chain2, seqNo2, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt2.State,
		"message on uncursed lane should succeed")
	l.Info().Msg("Confirmed: uncursed lane still works")

	// 7. Uncurse the lane
	l.Info().Msg("Step 7: Uncursing the lane")
	err = c.ApplyUncurse(ctx, chain0, [][16]byte{chainSelectorToSubject(chain1)})
	require.NoError(t, err)
	err = c.ApplyUncurse(ctx, chain1, [][16]byte{chainSelectorToSubject(chain0)})
	require.NoError(t, err)

	// 8. Wait for curse detector to detect uncurse
	l.Info().Msg("Step 8: Waiting 5 seconds for curse detector to detect uncurse")
	time.Sleep(5 * time.Second)

	// 9. Verify curse cleared
	l.Info().Msg("Step 9: Verifying curse state cleared")
	isCursed, err = c.VerifyCurseState(ctx, chain0, chainSelectorToSubject(chain1))
	require.NoError(t, err)
	require.False(t, isCursed, "chain1 should no longer be cursed on chain0")

	isCursed, err = c.VerifyCurseState(ctx, chain1, chainSelectorToSubject(chain0))
	require.NoError(t, err)
	require.False(t, isCursed, "chain0 should no longer be cursed on chain1")

	// 10. Send message again and verify it executes successfully
	l.Info().Msg("Step 10: Sending message on uncursed lane")
	seqNo3, err := c.GetExpectedNextSequenceNumber(ctx, chain0, chain1)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain1, cciptestinterfaces.MessageFields{
		Receiver: receiver,
		Data:     []byte("post-uncurse message"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)

	execEvt3, err := c.WaitOneExecEventBySeqNo(ctx, chain0, chain1, seqNo3, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt3.State,
		"message after uncurse should succeed")
	l.Info().Msg("Test completed successfully: lane curse and uncurse work as expected")
}

func TestRMNGlobalCurse(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	require.Len(t, selectors, 3, "expected 3 chains for this test in the environment")

	c, err := ccvEvm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

	chain0, chain1, chain2 := selectors[0], selectors[1], selectors[2]

	// 1. Send baseline messages to verify all lanes work
	l.Info().Msg("Step 1: Sending baseline messages to verify all lanes work")

	receiver01 := mustGetEOAReceiverAddress(t, c, chain1)
	seqNo01, err := c.GetExpectedNextSequenceNumber(ctx, chain0, chain1)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain1, cciptestinterfaces.MessageFields{
		Receiver: receiver01,
		Data:     []byte("baseline 0->1"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	execEvt01, err := c.WaitOneExecEventBySeqNo(ctx, chain0, chain1, seqNo01, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt01.State)
	l.Info().Msg("Baseline message 0->1 executed successfully")

	receiver12 := mustGetEOAReceiverAddress(t, c, chain2)
	seqNo12, err := c.GetExpectedNextSequenceNumber(ctx, chain1, chain2)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain1, chain2, cciptestinterfaces.MessageFields{
		Receiver: receiver12,
		Data:     []byte("baseline 1->2"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	execEvt12, err := c.WaitOneExecEventBySeqNo(ctx, chain1, chain2, seqNo12, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt12.State)
	l.Info().Msg("Baseline message 1->2 executed successfully")

	// 2. Apply global curse to chain0
	l.Info().Msg("Step 2: Applying global curse to chain0")
	// Apply global curse on chain0 itself
	err = c.ApplyCurse(ctx, chain0, [][16]byte{globalCurseSubject()})
	require.NoError(t, err)
	// Apply chain0 curse on all other chains
	err = c.ApplyCurse(ctx, chain1, [][16]byte{chainSelectorToSubject(chain0)})
	require.NoError(t, err)
	err = c.ApplyCurse(ctx, chain2, [][16]byte{chainSelectorToSubject(chain0)})
	require.NoError(t, err)

	// 3. Wait for curse detector
	l.Info().Msg("Step 3: Waiting 5 seconds for curse detector to detect curses")
	time.Sleep(5 * time.Second)

	// 4. Verify curse state
	l.Info().Msg("Step 4: Verifying curse state")
	isCursed, err := c.VerifyCurseState(ctx, chain0, globalCurseSubject())
	require.NoError(t, err)
	require.True(t, isCursed, "chain0 should have global curse")

	isCursed, err = c.VerifyCurseState(ctx, chain1, chainSelectorToSubject(chain0))
	require.NoError(t, err)
	require.True(t, isCursed, "chain0 should be cursed on chain1")

	isCursed, err = c.VerifyCurseState(ctx, chain2, chainSelectorToSubject(chain0))
	require.NoError(t, err)
	require.True(t, isCursed, "chain0 should be cursed on chain2")

	// 5. Verify all lanes involving chain0 are blocked
	l.Info().Msg("Step 5: Verifying all lanes involving chain0 are blocked")

	// Try chain0 -> chain1 (should fail)
	seqNo, err := c.GetExpectedNextSequenceNumber(ctx, chain0, chain1)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain1, cciptestinterfaces.MessageFields{
		Receiver: receiver01,
		Data:     []byte("cursed 0->1"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	time.Sleep(10 * time.Second)
	execEvt, err := c.WaitOneExecEventBySeqNo(ctx, chain0, chain1, seqNo, 5*time.Second)
	if err == nil {
		require.NotEqual(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State,
			"message 0->1 on globally cursed chain should not execute")
	}
	l.Info().Msg("Confirmed: chain0->chain1 is blocked")

	// Try chain1 -> chain0 (should fail)
	receiver10 := mustGetEOAReceiverAddress(t, c, chain0)
	seqNo10, err := c.GetExpectedNextSequenceNumber(ctx, chain1, chain0)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain1, chain0, cciptestinterfaces.MessageFields{
		Receiver: receiver10,
		Data:     []byte("cursed 1->0"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	time.Sleep(10 * time.Second)
	execEvt10, err := c.WaitOneExecEventBySeqNo(ctx, chain1, chain0, seqNo10, 5*time.Second)
	if err == nil {
		require.NotEqual(t, cciptestinterfaces.ExecutionStateSuccess, execEvt10.State,
			"message 1->0 to globally cursed chain should not execute")
	}
	l.Info().Msg("Confirmed: chain1->chain0 is blocked")

	// Try chain0 -> chain2 (should fail)
	receiver02 := mustGetEOAReceiverAddress(t, c, chain2)
	seqNo02, err := c.GetExpectedNextSequenceNumber(ctx, chain0, chain2)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain2, cciptestinterfaces.MessageFields{
		Receiver: receiver02,
		Data:     []byte("cursed 0->2"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	time.Sleep(10 * time.Second)
	execEvt02, err := c.WaitOneExecEventBySeqNo(ctx, chain0, chain2, seqNo02, 5*time.Second)
	if err == nil {
		require.NotEqual(t, cciptestinterfaces.ExecutionStateSuccess, execEvt02.State,
			"message 0->2 from globally cursed chain should not execute")
	}
	l.Info().Msg("Confirmed: chain0->chain2 is blocked")

	// 6. Verify unrelated lane still works (chain1 -> chain2)
	l.Info().Msg("Step 6: Verifying unrelated lane (chain1->chain2) still works")
	seqNo, err = c.GetExpectedNextSequenceNumber(ctx, chain1, chain2)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain1, chain2, cciptestinterfaces.MessageFields{
		Receiver: receiver12,
		Data:     []byte("uncursed 1->2"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	execEvt, err = c.WaitOneExecEventBySeqNo(ctx, chain1, chain2, seqNo, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State,
		"unrelated lane should still work")
	l.Info().Msg("Confirmed: unrelated lane chain1->chain2 still works")

	// 7. Uncurse chain0
	l.Info().Msg("Step 7: Uncursing chain0")
	err = c.ApplyUncurse(ctx, chain0, [][16]byte{globalCurseSubject()})
	require.NoError(t, err)
	err = c.ApplyUncurse(ctx, chain1, [][16]byte{chainSelectorToSubject(chain0)})
	require.NoError(t, err)
	err = c.ApplyUncurse(ctx, chain2, [][16]byte{chainSelectorToSubject(chain0)})
	require.NoError(t, err)

	// 8. Wait for curse detector
	l.Info().Msg("Step 8: Waiting 5 seconds for curse detector to detect uncurse")
	time.Sleep(5 * time.Second)

	// 9. Verify curse cleared
	l.Info().Msg("Step 9: Verifying curse state cleared on all chains")
	isCursed, err = c.VerifyCurseState(ctx, chain0, globalCurseSubject())
	require.NoError(t, err)
	require.False(t, isCursed, "chain0 should no longer have global curse")

	isCursed, err = c.VerifyCurseState(ctx, chain1, chainSelectorToSubject(chain0))
	require.NoError(t, err)
	require.False(t, isCursed, "chain0 should no longer be cursed on chain1")

	isCursed, err = c.VerifyCurseState(ctx, chain2, chainSelectorToSubject(chain0))
	require.NoError(t, err)
	require.False(t, isCursed, "chain0 should no longer be cursed on chain2")

	// 10. Verify all lanes work again
	l.Info().Msg("Step 10: Verifying all lanes work after uncurse")
	seqNo, err = c.GetExpectedNextSequenceNumber(ctx, chain0, chain1)
	require.NoError(t, err)
	_, err = c.SendMessage(ctx, chain0, chain1, cciptestinterfaces.MessageFields{
		Receiver: receiver01,
		Data:     []byte("post-uncurse 0->1"),
	}, cciptestinterfaces.MessageOptions{
		Version:  2,
		GasLimit: 200_000,
	})
	require.NoError(t, err)
	execEvt, err = c.WaitOneExecEventBySeqNo(ctx, chain0, chain1, seqNo, defaultExecTimeout)
	require.NoError(t, err)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, execEvt.State,
		"lane should work after uncurse")
	l.Info().Msg("Test completed successfully: global curse and uncurse work as expected")
}
