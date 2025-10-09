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
	MockReceiverContractType    = "MockReceiver"
	MockReceiverContractVersion = "1.7.0"
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

	t.Run("test argsv2 messages", func(t *testing.T) {
		type testcase struct {
			name         string
			fromSelector uint64
			toSelector   uint64
		}

		tcs := []testcase{
			{
				name:         "src->dst msg execution",
				fromSelector: selectors[0],
				toSelector:   selectors[1],
			},
			{
				name:         "dst->src msg execution",
				fromSelector: selectors[1],
				toSelector:   selectors[0],
			},
			{
				name:         "1337->3337 msg execution",
				fromSelector: selectors[0],
				toSelector:   selectors[2],
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := c.GetExpectedNextSequenceNumber(ctx, tc.fromSelector, tc.toSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				require.NotNil(t, in.CLDF)
				require.NotNil(t, in.CLDF.DataStore)
				require.NotNil(t, in.CLDF.DataStore.Addresses())
				mockReceiverRef, err := in.CLDF.DataStore.Addresses().Get(
					datastore.NewAddressRefKey(tc.toSelector, datastore.ContractType(MockReceiverContractType), semver.MustParse(MockReceiverContractVersion), ""),
				)
				require.NoError(t, err)
				t.Logf("mockReceiverRef: %s", mockReceiverRef.Address)
				err = c.SendMessage(ctx, tc.fromSelector, tc.toSelector, cciptestinterfaces.MessageFields{
					Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()),
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
				require.Equal(t, uint8(2), e.(*ccvAggregator.CCVAggregatorExecutionStateChanged).State)
			})
		}
	})

	t.Run("test argsv3 messages", func(t *testing.T) {
		type testcase struct {
			name            string
			srcSelector     uint64
			dstSelector     uint64
			finality        uint16
			verifierAddress []byte
			execOnRamp      string
			receiver        string
			mandatoryCCVs   []protocol.CCV
			optionalCCVs    []protocol.CCV
			threshold       uint8
		}

		verifierAddress := common.HexToAddress("0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1")
		execOnRamp := "0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE"
		//mockReceiver := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c"
		eoaReceiver := "0x3Aa5ebB10DC797CAC828524e59A333d0A371443b"
		mandatoryCCVs := []protocol.CCV{
			{
				CCVAddress: verifierAddress.Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		}
		tcs := []testcase{
			{
				name:          "src_dst msg execution with EOA receiver",
				srcSelector:   selectors[0],
				dstSelector:   selectors[1],
				finality:      1,
				execOnRamp:    execOnRamp,
				receiver:      eoaReceiver,
				mandatoryCCVs: mandatoryCCVs,
			},
			{
				name:          "dst_src msg execution with EOA receiver",
				srcSelector:   selectors[1],
				dstSelector:   selectors[0],
				finality:      1,
				execOnRamp:    execOnRamp,
				receiver:      eoaReceiver,
				mandatoryCCVs: mandatoryCCVs,
			},
			{
				name:          "1337->3337 msg execution with EOA receiver",
				srcSelector:   selectors[0],
				dstSelector:   selectors[2],
				finality:      1,
				execOnRamp:    execOnRamp,
				receiver:      eoaReceiver,
				mandatoryCCVs: mandatoryCCVs,
			},
			// TODO: Un skip these once the NOT_ENOUGH_GAS_FOR_CALL_SIG is fixed
			// 	https://smartcontract-it.atlassian.net/browse/CCIP-7351
			//{
			//	// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
			//	name:          "src_dst msg execution with mock receiver",
			//	srcSelector:   c.Chain1337Details.ChainSelector,
			//	dstSelector:   c.Chain2337Details.ChainSelector,
			//	finality:      1,
			//	execOnRamp:    execOnRamp,
			//	receiver:      mockReceiver,
			//	mandatoryCCVs: mandatoryCCVs,
			//},
			//{
			//	// This is expected to fail until on-chain fixes NOT_ENOUGH_GAS_FOR_CALL_SIG error on aggregator
			//	name:          "dst_src msg execution with mock receiver",
			//	srcSelector:   c.Chain2337Details.ChainSelector,
			//	dstSelector:   c.Chain1337Details.ChainSelector,
			//	finality:      1,
			//	execOnRamp:    execOnRamp,
			//	receiver:      mockReceiver,
			//	mandatoryCCVs: mandatoryCCVs,
			//},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := c.GetExpectedNextSequenceNumber(ctx, tc.srcSelector, tc.dstSelector)
				require.NoError(t, err)
				l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				err = c.SendMessage(
					ctx, tc.srcSelector, tc.dstSelector, cciptestinterfaces.MessageFields{
						Receiver: protocol.UnknownAddress(common.HexToAddress(tc.receiver).Bytes()),
						Data:     []byte{},
					}, cciptestinterfaces.MessageOptions{
						Version:           3,
						FinalityConfig:    uint16(tc.finality),
						Executor:          protocol.UnknownAddress(tc.execOnRamp),
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
				require.Equal(t, uint8(2), e.(*ccvAggregator.CCVAggregatorExecutionStateChanged).State)
			})
		}
	})
}
