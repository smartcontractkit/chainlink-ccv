package e2e

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc677"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"

	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
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

	t.Run("extra args v3", func(t *testing.T) {
		var tcs []testcase
		src, dest := selectors[0], selectors[1]
		mvtcsSrcToDest := multiVerifierTestCases(t, src, dest, in, c)
		tcs = append(tcs, mvtcsSrcToDest...)
		// add one test case the other way around (dest->src) to test the reverse lane.
		mvtcsDestToSrc := multiVerifierTestCases(t, dest, src, in, c)
		tcs = append(tcs, mvtcsDestToSrc[0])
		tcs = append(tcs, dataSizeTestCases(t, src, dest, in, c)...)
		tcs = append(tcs, []testcase{
			{
				name:        "EOA receiver and default committee verifier with token transfer",
				srcSelector: src,
				dstSelector: dest,
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, dest),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				tokenTransfer: &tokenTransfer{
					tokenAmount: cciptestinterfaces.TokenAmount{
						Amount:       big.NewInt(1000),
						TokenAddress: getContractAddress(t, in, src, datastore.ContractType(burn_mint_erc677.ContractType), burn_mint_erc677.Deploy.Version(), "TEST", "burn mint erc677"),
					},
					destTokenRef: datastore.AddressRef{
						Type:      datastore.ContractType(burn_mint_erc677.ContractType),
						Version:   semver.MustParse(burn_mint_erc677.Deploy.Version()),
						Qualifier: "TEST",
					},
				},
				// default verifier
				numExpectedVerifications: 1,
				// default executor, default committee verifier and the token contract
				numExpectedReceipts: 3,
			},
		}...)
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
}

func mustGetEOAReceiverAddress(t *testing.T, c *ccvEvm.CCIP17EVM, chainSelector uint64) protocol.UnknownAddress {
	receiver, err := c.GetEOAReceiverAddress(chainSelector)
	require.NoError(t, err)
	return receiver
}

func getContractAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) protocol.UnknownAddress {
	ref, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	require.NoErrorf(t, err, "failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s",
		contractName, chainSelector, contractType, version)
	return protocol.UnknownAddress(common.HexToAddress(ref.Address).Bytes())
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
			msgData: bytes.Repeat([]byte("a"), int(maxDataBytes)), //nolint:gosec
			ccvs: []protocol.CCV{
				{
					CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
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
					CCVAddress: getContractAddress(t, in, src, datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
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
						datastore.ContractType(committee_verifier.ProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
			},
			// default verifier and secondary verifier will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor and secondary committee verifier
			// default verifier does NOT show up onchain because it is only a default and not lane mandated.
			numExpectedReceipts: 2,
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
						datastore.ContractType(committee_verifier.ProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.SecondaryCommitteeVerifierQualifier,
						"secondary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
			},
			// default verifier and secondary verifier will verify so should be two verifications.
			numExpectedVerifications: 2,
			// default executor and secondary committee verifier
			// default verifier does NOT show up onchain because it is only a default and not lane mandated.
			numExpectedReceipts: 2,
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
						committee_verifier.Deploy.Version(),
						ccvEvm.TertiaryCommitteeVerifierQualifier,
						"tertiary committee verifier proxy",
					),
					Args:    []byte{},
					ArgsLen: 0,
				},
			},
			// default, secondary and tertiary verifiers will verify so should be three verifications.
			numExpectedVerifications: 3,
			// default executor and secondary and tertiary committee verifiers
			// default verifier does NOT show up onchain because it is only a default and not lane mandated.
			numExpectedReceipts: 3,
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
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
						datastore.ContractType(committee_verifier.ProxyType),
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
