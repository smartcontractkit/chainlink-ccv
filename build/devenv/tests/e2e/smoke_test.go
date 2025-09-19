package e2e

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"

	ccvAggregator "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_aggregator"
	ccvProxy "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/ccv_proxy"
)

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)

	c, err := NewContracts(in)
	require.NoError(t, err)

	t.Run("test argsv2 messages", func(t *testing.T) {
		type testcase struct {
			name        string
			proxy       *ccvProxy.CCVProxy
			agg         *ccvAggregator.CCVAggregator
			srcSelector uint64
			dstSelector uint64
		}

		tcs := []testcase{
			{
				name:        "src->dst msg execution",
				proxy:       c.proxySrc,
				agg:         c.aggDst,
				srcSelector: c.srcChainDetails.ChainSelector,
				dstSelector: c.dstChainDetails.ChainSelector,
			},
			{
				name:        "dst->src msg execution",
				proxy:       c.proxyDst,
				agg:         c.aggSrc,
				srcSelector: c.dstChainDetails.ChainSelector,
				dstSelector: c.srcChainDetails.ChainSelector,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := tc.proxy.GetExpectedNextSequenceNumber(&bind.CallOpts{}, tc.dstSelector)
				require.NoError(t, err)
				ccv.Plog.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				err = ccv.SendExampleArgsV2Message(in, tc.srcSelector, tc.dstSelector)
				require.NoError(t, err)
				_, err = FetchSentEventBySeqNo(tc.proxy, tc.dstSelector, seqNo, 1*time.Minute)
				require.NoError(t, err)
				e, err := FetchExecEventBySeqNo(tc.agg, tc.srcSelector, seqNo, 5*time.Minute)
				require.NoError(t, err)
				require.NotNil(t, e)
				require.Equal(t, uint8(2), e.State)
			})
		}
	})

	t.Run("test argsv3 messages", func(t *testing.T) {
		type testcase struct {
			name            string
			proxy           *ccvProxy.CCVProxy
			agg             *ccvAggregator.CCVAggregator
			srcSelector     uint64
			dstSelector     uint64
			finality        uint16
			verifierAddress []byte
			execOnRamp      common.Address
			mandatoryCCVs   []types.CCV
			optionalCCVs    []types.CCV
			threshold       uint8
		}

		verifierAddress := common.HexToAddress("0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1")
		execOnRamp := common.HexToAddress("0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE")

		tcs := []testcase{
			{
				name:        "src->dst msg execution",
				proxy:       c.proxySrc,
				agg:         c.aggDst,
				srcSelector: c.srcChainDetails.ChainSelector,
				dstSelector: c.dstChainDetails.ChainSelector,
				finality:    0,
				execOnRamp:  execOnRamp,
				mandatoryCCVs: []types.CCV{
					{
						CCVAddress: verifierAddress.Bytes(),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},
			{
				name:        "dst->src msg execution",
				proxy:       c.proxyDst,
				agg:         c.aggSrc,
				srcSelector: c.dstChainDetails.ChainSelector,
				dstSelector: c.srcChainDetails.ChainSelector,
				finality:    0,
				execOnRamp:  execOnRamp,
				mandatoryCCVs: []types.CCV{
					{
						CCVAddress: verifierAddress.Bytes(),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				seqNo, err := tc.proxy.GetExpectedNextSequenceNumber(&bind.CallOpts{}, tc.dstSelector)
				require.NoError(t, err)
				ccv.Plog.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
				err = ccv.SendExampleArgsV3Message(in, tc.srcSelector, tc.dstSelector, tc.finality, tc.execOnRamp, nil, nil,
					tc.mandatoryCCVs, tc.optionalCCVs, 0)
				require.NoError(t, err)
				_, err = FetchSentEventBySeqNo(tc.proxy, tc.dstSelector, seqNo, 1*time.Minute)
				require.NoError(t, err)
				e, err := FetchExecEventBySeqNo(tc.agg, tc.srcSelector, seqNo, 5*time.Minute)
				require.NoError(t, err)
				require.NotNil(t, e)
				require.Equal(t, uint8(2), e.State)
			})
		}
	})
}
