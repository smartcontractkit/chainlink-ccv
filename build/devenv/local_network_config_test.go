package ccv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvevm "github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestEVMLocalNetworkOverlayLoadsWithStandardConfig(t *testing.T) {
	t.Parallel()

	cfg, err := Load[Cfg]([]string{"env.toml", "env-rpc-failover.toml"})
	require.NoError(t, err)
	require.NotNil(t, cfg.LocalNetworks)
	require.NotNil(t, cfg.LocalNetworks["evm"])

	input, err := util.OpaqueToConcreteStrict[devenvevm.LocalNetworkInput](cfg.LocalNetworks["evm"].Input)
	require.NoError(t, err)
	require.NotNil(t, input.RPCFailover)
	require.True(t, input.RPCFailover.Enabled)
}

func TestConfigureLocalNetworksRoutesOpaqueConfigByFamily(t *testing.T) {
	t.Parallel()

	const family = "local-network-routing-test"
	input := util.OpaqueConfig{"enabled": true}
	wantOutput := util.OpaqueConfig{"configured": true}
	var finalized bool
	require.NoError(t, chainreg.Register(family, chainreg.Registration{
		LocalNetworkConfigurator: func(
			_ context.Context,
			gotInput util.OpaqueConfig,
			outputs []*blockchain.Output,
		) (util.OpaqueConfig, chainreg.LocalNetworkFinalizer, error) {
			require.Equal(t, input, gotInput)
			require.Len(t, outputs, 1)
			require.Equal(t, family, outputs[0].Family)
			return wantOutput, func() { finalized = true }, nil
		},
	}))

	configs := map[string]*chainreg.LocalNetworkConfig{
		family: {Input: input},
	}
	finalizers, err := configureLocalNetworks(t.Context(), configs, []*blockchain.Output{
		{Family: family},
		{Family: "unrelated"},
	})
	require.NoError(t, err)
	require.Equal(t, wantOutput, configs[family].Output)
	require.False(t, finalized)

	finalizeLocalNetworks(finalizers)
	require.True(t, finalized)
}
