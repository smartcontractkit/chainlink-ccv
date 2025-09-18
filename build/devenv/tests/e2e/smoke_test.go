package e2e

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

func TestE2ESmoke(t *testing.T) {
	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	srcChain, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[0].ChainID, chainsel.FamilyEVM)
	require.NoError(t, err)
	dstChain, err := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[1].ChainID, chainsel.FamilyEVM)
	require.NoError(t, err)

	t.Run("test argsv2 messages", func(t *testing.T) {
		type testcase struct {
			name         string
			fromSelector uint64
			toSelector   uint64
		}

		tcs := []testcase{
			{
				name:         "src->dst msg execution",
				fromSelector: srcChain.ChainSelector,
				toSelector:   dstChain.ChainSelector,
			},
			{
				name:         "dst->src msg execution",
				fromSelector: dstChain.ChainSelector,
				toSelector:   srcChain.ChainSelector,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				err = ccv.SendExampleArgsV2Message(in, tc.fromSelector, tc.toSelector)
				require.NoError(t, err)
				// TODO: assert both contracts and receiver
			})
		}
	})

	t.Run("test argsv3 messages", func(t *testing.T) {
		type testcase struct {
			name            string
			fromSelector    uint64
			toSelector      uint64
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
				name:         "src->dst msg execution",
				fromSelector: srcChain.ChainSelector,
				toSelector:   dstChain.ChainSelector,
				finality:     0,
				execOnRamp:   execOnRamp,
				mandatoryCCVs: []types.CCV{
					{
						CCVAddress: verifierAddress.Bytes(),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			},
			{
				name:         "dst->src msg execution",
				fromSelector: dstChain.ChainSelector,
				toSelector:   srcChain.ChainSelector,
				finality:     0,
				execOnRamp:   execOnRamp,
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
				err = ccv.SendExampleArgsV3Message(in, tc.fromSelector, tc.toSelector, tc.finality, tc.execOnRamp, nil, nil,
					tc.mandatoryCCVs, tc.optionalCCVs, 0)
				require.NoError(t, err)
				// TODO: assert both contracts and receiver
			})
		}
	})

}
