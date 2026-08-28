package ccv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/components/localnetworks"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/localnetwork"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
)

func TestEVMLocalNetworkOverlayLoadsWithStandardConfig(t *testing.T) {
	t.Parallel()

	cfg, err := Load[Cfg]([]string{"env.toml", "env-rpc-failover.toml"})
	require.NoError(t, err)
	require.NotNil(t, cfg.LocalNetworks)
	require.NotNil(t, cfg.LocalNetworks["evm"])

	input, err := util.OpaqueToConcreteStrict[localnetwork.Input](cfg.LocalNetworks["evm"].Input)
	require.NoError(t, err)
	require.NotNil(t, input.RPCFailover)
	require.True(t, input.RPCFailover.Enabled)
}

func TestEVMLocalNetworkOverlayLoadsWithPhasedConfig(t *testing.T) {
	t.Parallel()

	raw, err := loadRaw([]string{"env-phased.toml", "env-phased-rpc-failover.toml"})
	require.NoError(t, err)

	configs, err := localnetworks.Decode(raw[localnetworks.Key])
	require.NoError(t, err)
	require.Contains(t, configs, "evm")

	input, err := util.OpaqueToConcreteStrict[localnetwork.Input](configs["evm"].Input)
	require.NoError(t, err)
	require.NotNil(t, input.RPCFailover)
	require.True(t, input.RPCFailover.Enabled)
}
