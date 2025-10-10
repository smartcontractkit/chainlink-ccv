package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	cciptestinterfaces "github.com/smartcontractkit/chainlink-ccv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"

	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

const (
	// TODO: should these be in another place that is easily accessible?
	MockReceiverContractType    = "MockReceiver"
	MockReceiverContractVersion = "1.7.0"

	CommitteeVerifierContractType    = "CommitOnRamp"
	CommitteeVerifierContractVersion = "1.7.0"

	ExecutorOnRampContractType    = "ExecutorOnRamp"
	ExecutorOnRampContractVersion = "1.7.0"

	// See Internal.sol for the full enum values
	MessageExecutionStateSuccess uint8 = 2
	MessageExecutionStateFailed  uint8 = 3
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

	c, err := ccvEvm.NewCCIP17EVM(ctx, e, chainIDs, wsURLs)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	t.Run("test extra args v2 messages", func(t *testing.T) {
		type testcase struct {
			name         string
			fromSelector uint64
			toSelector   uint64
			receiver     protocol.UnknownAddress
			expectFail   bool
		}

		tcs := []testcase{
			{
				name:         "src->dst msg execution eoa receiver",
				fromSelector: selectors[0],
				toSelector:   selectors[1],
				receiver:     mustGetEOAReceiverAddress(t, c, selectors[1]),
				expectFail:   false,
			},
			{
				name:         "dst->src msg execution eoa receiver",
				fromSelector: selectors[1],
				toSelector:   selectors[0],
				receiver:     mustGetEOAReceiverAddress(t, c, selectors[0]),
				expectFail:   false,
			},
			{
				name:         "1337->3337 msg execution mock receiver",
				fromSelector: selectors[0],
				toSelector:   selectors[2],
				receiver:     getMockReceiverAddress(t, in, selectors[2]),
				// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
				// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
				expectFail: true,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := c.GetExpectedNextSequenceNumber(ctx, tc.fromSelector, tc.toSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				err = c.SendMessage(ctx, tc.fromSelector, tc.toSelector, cciptestinterfaces.MessageFields{
					Receiver: tc.receiver,
					Data:     []byte{},
				}, cciptestinterfaces.MessageOptions{
					Version:             2,
					GasLimit:            200_000,
					OutOfOrderExecution: true,
				})
				require.NoError(t, err)
				_, err = c.WaitOneSentEventBySeqNo(ctx, tc.fromSelector, tc.toSelector, seqNo, 1*time.Minute)
				require.NoError(t, err)
				e, err := c.WaitOneExecEventBySeqNo(ctx, tc.fromSelector, tc.toSelector, seqNo, 5*time.Minute)
				require.NoError(t, err)
				require.NotNil(t, e)

				if tc.expectFail {
					require.Equal(t, MessageExecutionStateFailed, e.(*ccvAggregator.CCVAggregatorExecutionStateChanged).State)
				} else {
					require.Equal(t, MessageExecutionStateSuccess, e.(*ccvAggregator.CCVAggregatorExecutionStateChanged).State)
				}
			})
		}
	})

	t.Run("test extra args v3 messages", func(t *testing.T) {
		type testcase struct {
			name            string
			srcSelector     uint64
			dstSelector     uint64
			finality        uint16
			verifierAddress []byte
			receiver        protocol.UnknownAddress
			mandatoryCCVs   []protocol.CCV
			optionalCCVs    []protocol.CCV
			threshold       uint8
			expectFail      bool
		}

		tcs := []testcase{
			{
				name:        "src_dst msg execution with EOA receiver",
				srcSelector: selectors[0],
				dstSelector: selectors[1],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[1]),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getCommitteeVerifierAddress(t, in, selectors[0]),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},
			{
				name:        "dst_src msg execution with EOA receiver",
				srcSelector: selectors[1],
				dstSelector: selectors[0],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[0]),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getCommitteeVerifierAddress(t, in, selectors[1]),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},
			{
				name:        "1337->3337 msg execution with EOA receiver",
				srcSelector: selectors[0],
				dstSelector: selectors[2],
				finality:    1,
				receiver:    mustGetEOAReceiverAddress(t, c, selectors[2]),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getCommitteeVerifierAddress(t, in, selectors[0]),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},

			{
				name:        "src_dst msg execution with mock receiver",
				srcSelector: selectors[0],
				dstSelector: selectors[1],
				finality:    1,
				receiver:    getMockReceiverAddress(t, in, selectors[1]),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getCommitteeVerifierAddress(t, in, selectors[1]),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
				// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
				expectFail: true,
			},
			{
				name:        "dst_src msg execution with mock receiver",
				srcSelector: selectors[1],
				dstSelector: selectors[0],
				finality:    1,
				receiver:    getMockReceiverAddress(t, in, selectors[0]),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getCommitteeVerifierAddress(t, in, selectors[0]),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
				// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
				expectFail: true,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := c.GetExpectedNextSequenceNumber(ctx, tc.srcSelector, tc.dstSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				err = c.SendMessage(
					ctx, tc.srcSelector, tc.dstSelector, cciptestinterfaces.MessageFields{
						Receiver: tc.receiver,
						Data:     []byte{},
					}, cciptestinterfaces.MessageOptions{
						Version:           3,
						FinalityConfig:    uint16(tc.finality),
						Executor:          getExecOnRampAddress(t, in, tc.srcSelector),
						MandatoryCCVs:     tc.mandatoryCCVs,
						OptionalCCVs:      tc.optionalCCVs,
						OptionalThreshold: tc.threshold,
					})
				require.NoError(t, err)
				_, err = c.WaitOneSentEventBySeqNo(ctx, tc.srcSelector, tc.dstSelector, seqNo, 1*time.Minute)
				require.NoError(t, err)
				e, err := c.WaitOneExecEventBySeqNo(ctx, tc.srcSelector, tc.dstSelector, seqNo, 1*time.Minute)
				require.NoError(t, err)
				require.NotNil(t, e)
				if tc.expectFail {
					require.Equal(t, MessageExecutionStateFailed, e.(*ccvAggregator.CCVAggregatorExecutionStateChanged).State)
				} else {
					require.Equal(t, MessageExecutionStateSuccess, e.(*ccvAggregator.CCVAggregatorExecutionStateChanged).State)
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

func getMockReceiverAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64) protocol.UnknownAddress {
	mockReceiverRef, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, datastore.ContractType(MockReceiverContractType), semver.MustParse(MockReceiverContractVersion), ""),
	)
	require.NoErrorf(t, err, "failed to get mock receiver address for chain selector %d, ContractType: %s, ContractVersion: %s",
		chainSelector, MockReceiverContractType, MockReceiverContractVersion)
	return protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes())
}

func getExecOnRampAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64) protocol.UnknownAddress {

	executorOnRampRef, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, datastore.ContractType(ExecutorOnRampContractType), semver.MustParse(ExecutorOnRampContractVersion), ""),
	)
	require.NoErrorf(t, err, "failed to get executor on ramp address for chain selector %d, ContractType: %s, ContractVersion: %s",
		chainSelector, ExecutorOnRampContractType, ExecutorOnRampContractVersion)
	return protocol.UnknownAddress(common.HexToAddress(executorOnRampRef.Address).Bytes())
}

func getCommitteeVerifierAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64) protocol.UnknownAddress {
	committeeVerifierRef, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, datastore.ContractType(CommitteeVerifierContractType), semver.MustParse(CommitteeVerifierContractVersion), ""),
	)
	require.NoErrorf(t, err, "failed to get committee verifier address for chain selector %d, ContractType: %s, ContractVersion: %s",
		chainSelector, CommitteeVerifierContractType, CommitteeVerifierContractVersion)
	return protocol.UnknownAddress(common.HexToAddress(committeeVerifierRef.Address).Bytes())
}
