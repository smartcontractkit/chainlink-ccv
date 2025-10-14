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

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/executor_onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	offRamp "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/off_ramp"
	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

const (
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
				receiver:     getContractAddress(t, in, selectors[2], datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), "mock receiver"),
				// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
				// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
				expectFail: false,
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
					require.Equal(t, MessageExecutionStateFailed, e.(*offRamp.OffRampExecutionStateChanged).State)
				} else {
					require.Equal(t, MessageExecutionStateSuccess, e.(*offRamp.OffRampExecutionStateChanged).State)
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
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ContractType), committee_verifier.Deploy.Version(), "committee verifier"),
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
						CCVAddress: getContractAddress(t, in, selectors[1], datastore.ContractType(committee_verifier.ContractType), committee_verifier.Deploy.Version(), "committee verifier"),
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
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ContractType), committee_verifier.Deploy.Version(), "committee verifier"),
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
				receiver:    getContractAddress(t, in, selectors[1], datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), "mock receiver"),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[1], datastore.ContractType(committee_verifier.ContractType), committee_verifier.Deploy.Version(), "committee verifier"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
				// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
				expectFail: false,
			},
			{
				name:        "dst_src msg execution with mock receiver",
				srcSelector: selectors[1],
				dstSelector: selectors[0],
				finality:    1,
				receiver:    getContractAddress(t, in, selectors[0], datastore.ContractType(mock_receiver.ContractType), mock_receiver.Deploy.Version(), "mock receiver"),
				mandatoryCCVs: []protocol.CCV{
					{
						CCVAddress: getContractAddress(t, in, selectors[0], datastore.ContractType(committee_verifier.ContractType), committee_verifier.Deploy.Version(), "committee verifier"),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
				// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
				// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
				expectFail: false,
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
						Executor:          getContractAddress(t, in, tc.srcSelector, datastore.ContractType(executor_onramp.ContractType), executor_onramp.Deploy.Version(), "executor on-ramp"),
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
					require.Equal(t, MessageExecutionStateFailed, e.(*offRamp.OffRampExecutionStateChanged).State)
				} else {
					require.Equal(t, MessageExecutionStateSuccess, e.(*offRamp.OffRampExecutionStateChanged).State)
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

func getContractAddress(t *testing.T, ccvCfg *ccv.Cfg, chainSelector uint64, contractType datastore.ContractType, version, contractName string) protocol.UnknownAddress {
	ref, err := ccvCfg.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), ""),
	)
	require.NoErrorf(t, err, "failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s",
		contractName, chainSelector, contractType, version)
	return protocol.UnknownAddress(common.HexToAddress(ref.Address).Bytes())
}
