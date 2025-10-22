package e2e

import (
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
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"

	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

const (
	// See Internal.sol for the full enum values.
	MessageExecutionStateSuccess uint8 = 2
	MessageExecutionStateFailed  uint8 = 3

	defaultSentTimeout = 10 * time.Second
	defaultExecTimeout = 40 * time.Second
)

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
	aggregatorAddr := fmt.Sprintf("127.0.0.1:%d", in.Aggregator.Port)

	aggregatorClient, err := ccv.NewAggregatorClient(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		aggregatorAddr)
	require.NoError(t, err)
	require.NotNil(t, aggregatorClient)
	t.Cleanup(func() {
		aggregatorClient.Close()
	})

	indexerClient := ccv.NewIndexerClient(
		zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
		indexerURL)
	require.NotNil(t, indexerClient)

	t.Run("test extra args v2 messages", func(t *testing.T) {
		type testcase struct {
			name                     string
			fromSelector             uint64
			toSelector               uint64
			receiver                 protocol.UnknownAddress
			expectFail               bool
			numExpectedVerifications int
		}

		tcs := []testcase{
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
				// TODO: maybe this method should just return a message ID for now,
				// its currently being used in an EVM-specific way.
				sentEvent, err := c.WaitOneSentEventBySeqNo(ctx, tc.fromSelector, tc.toSelector, seqNo, defaultSentTimeout)
				require.NoError(t, err)
				messageID := sentEvent.(*onramp.OnRampCCIPMessageSent).MessageId

				testCtx := NewTestingContext(t, ctx, c, aggregatorClient, indexerClient)
				result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
					TickInterval: 1 * time.Second,
					Timeout:      defaultExecTimeout,
				})
				require.NoError(t, err)
				require.NotNil(t, result.AggregatedResult)
				require.Len(t, result.IndexedVerifications.VerifierResults, tc.numExpectedVerifications)

				e, err := c.WaitOneExecEventBySeqNo(ctx, tc.fromSelector, tc.toSelector, seqNo, defaultExecTimeout)
				require.NoError(t, err)
				require.NotNil(t, e)

				if tc.expectFail {
					require.Equalf(t,
						MessageExecutionStateFailed,
						e.(*offramp.OffRampExecutionStateChanged).State,
						"unexpected state, return data: %x",
						e.(*offramp.OffRampExecutionStateChanged).ReturnData)
				} else {
					require.Equalf(t,
						MessageExecutionStateSuccess,
						e.(*offramp.OffRampExecutionStateChanged).State,
						"unexpected state, return data: %x",
						e.(*offramp.OffRampExecutionStateChanged).ReturnData)
				}
			})
		}
	})

	t.Run("test extra args v3 messages", func(t *testing.T) {
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
			expectFail               bool
			tokenTransfer            *tokenTransfer
			numExpectedVerifications int
		}

		tcs := []testcase{
			{
				name:        "src_dest msg execution with EOA receiver and secondary committee verifier",
				srcSelector: selectors[0],
				dstSelector: selectors[1],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[1]),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.SecondaryCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				numExpectedVerifications: 1,
			},
			{
				name:        "src_dst msg execution with EOA receiver",
				srcSelector: selectors[0],
				dstSelector: selectors[1],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[1]),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				numExpectedVerifications: 1,
			},
			{
				name:        "dst_src msg execution with EOA receiver",
				srcSelector: selectors[1],
				dstSelector: selectors[0],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[0]),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[1], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				numExpectedVerifications: 1,
			},
			{
				name:        "1337->3337 msg execution with EOA receiver",
				srcSelector: selectors[0],
				dstSelector: selectors[2],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[2]),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				numExpectedVerifications: 1,
			},

			{
				name:        "src_dst msg execution with mock receiver",
				srcSelector: selectors[0],
				dstSelector: selectors[1],
				finality:    1,
				receiver:    getContractAddress(t, in, selectors[1], datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.DefaultReceiverQualifier, "mock receiver"),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				expectFail:               false,
				numExpectedVerifications: 1,
			},
			{
				name:        "dst_src msg execution with mock receiver",
				srcSelector: selectors[1],
				dstSelector: selectors[0],
				finality:    1,
				receiver:    getContractAddress(t, in, selectors[0], datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), ccvEvm.DefaultReceiverQualifier, "mock receiver"),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[1], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				expectFail:               false,
				numExpectedVerifications: 1,
			},
			{
				name:        "src_dst msg execution with EOA receiver and token transfer",
				srcSelector: selectors[0],
				dstSelector: selectors[1],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[1]),
				ccvs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ProxyType), committee_verifier.Deploy.Version(), ccvEvm.DefaultCommitteeVerifierQualifier, "committee verifier proxy"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				tokenTransfer: &tokenTransfer{
					tokenAmount: cciptestinterfaces.TokenAmount{
						Amount:       big.NewInt(1000),
						TokenAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(burn_mint_erc677.ContractType), burn_mint_erc677.Deploy.Version(), "TEST", "burn mint erc677"),
					},
					destTokenRef: datastore.AddressRef{
						Type:      datastore.ContractType(burn_mint_erc677.ContractType),
						Version:   semver.MustParse(burn_mint_erc677.Deploy.Version()),
						Qualifier: "TEST",
					},
				},
				numExpectedVerifications: 1,
			},
		}
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
						Data:         []byte{},
						TokenAmounts: tokenAmounts,
					}, cciptestinterfaces.MessageOptions{
						Version:        3,
						FinalityConfig: tc.finality,
						Executor:       getContractAddress(t, in, tc.srcSelector, datastore.ContractType(executor.ContractType), executor.Deploy.Version(), "", "executor"),
						CCVs:           tc.ccvs,
					})
				require.NoError(t, err)
				t.Logf("receipt issuers: %+v", sendMessageResult.ReceiptIssuers)
				sentEvent, err := c.WaitOneSentEventBySeqNo(ctx, tc.srcSelector, tc.dstSelector, seqNo, defaultSentTimeout)
				require.NoError(t, err)
				messageID := sentEvent.(*onramp.OnRampCCIPMessageSent).MessageId

				testCtx := NewTestingContext(t, t.Context(), c, aggregatorClient, indexerClient)
				result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
					TickInterval: 1 * time.Second,
					Timeout:      defaultExecTimeout,
				})
				require.NoError(t, err)
				require.NotNil(t, result.AggregatedResult)
				require.Len(t, result.IndexedVerifications.VerifierResults, tc.numExpectedVerifications)

				e, err := c.WaitOneExecEventBySeqNo(ctx, tc.srcSelector, tc.dstSelector, seqNo, defaultExecTimeout)
				require.NoError(t, err)
				require.NotNil(t, e)
				if tc.expectFail {
					require.Equal(t, MessageExecutionStateFailed, e.(*offramp.OffRampExecutionStateChanged).State)
				} else {
					require.Equal(t, MessageExecutionStateSuccess, e.(*offramp.OffRampExecutionStateChanged).State)
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
