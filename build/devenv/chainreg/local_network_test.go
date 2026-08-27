package chainreg

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestConfigureLocalNetworksRoutesOpaqueConfigByFamily(t *testing.T) {
	const family = "local-network-routing-test"
	input := util.OpaqueConfig{"enabled": true}
	wantOutput := util.OpaqueConfig{"configured": true}
	var finalized bool
	require.NoError(t, Register(family, Registration{
		LocalNetworkConfigurator: func(
			_ context.Context,
			gotInput util.OpaqueConfig,
			outputs []*ctfblockchain.Output,
		) (util.OpaqueConfig, LocalNetworkFinalizer, error) {
			require.Equal(t, input, gotInput)
			require.Len(t, outputs, 1)
			require.Equal(t, family, outputs[0].Family)
			return wantOutput, func() { finalized = true }, nil
		},
	}))

	configs := map[string]*LocalNetworkConfig{
		family: {Input: input},
	}
	finalizers, err := ConfigureLocalNetworks(t.Context(), configs, []*ctfblockchain.Output{
		{Family: family},
		{Family: "unrelated"},
	})
	require.NoError(t, err)
	require.Equal(t, wantOutput, configs[family].Output)
	require.False(t, finalized)

	FinalizeLocalNetworks(finalizers)
	require.True(t, finalized)
}

func TestConfigureLocalNetworksRejectsFamilyWithoutMatchingChains(t *testing.T) {
	const family = "local-network-no-chains-test"
	require.NoError(t, Register(family, Registration{
		LocalNetworkConfigurator: func(
			context.Context,
			util.OpaqueConfig,
			[]*ctfblockchain.Output,
		) (util.OpaqueConfig, LocalNetworkFinalizer, error) {
			t.Fatal("configurator must not run for a family with no chains")
			return nil, nil, nil
		},
	}))

	_, err := ConfigureLocalNetworks(t.Context(), map[string]*LocalNetworkConfig{
		family: {Input: util.OpaqueConfig{"enabled": true}},
	}, []*ctfblockchain.Output{{Family: "unrelated"}})
	require.ErrorContains(t, err, "has no matching blockchains")
}

func TestConfigureLocalNetworksRejectsUnregisteredConfigurator(t *testing.T) {
	const family = "local-network-unregistered-test"
	require.NoError(t, Register(family, Registration{}))

	_, err := ConfigureLocalNetworks(t.Context(), map[string]*LocalNetworkConfig{
		family: {},
	}, []*ctfblockchain.Output{{Family: family}})
	require.ErrorContains(t, err, "is not registered")
}
