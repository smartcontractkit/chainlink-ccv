package localnetworks

import (
	"context"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// rawSection parses a TOML document the way the phased runtime does and returns
// the [local_networks] value it would hand this component.
func rawSection(t *testing.T, doc string) any {
	t.Helper()
	var parsed map[string]any
	require.NoError(t, toml.Unmarshal([]byte(doc), &parsed))
	return parsed[Key]
}

func TestDecodeReturnsPerFamilyConfigs(t *testing.T) {
	t.Parallel()

	configs, err := Decode(rawSection(t, `
[local_networks]
version = 1

[local_networks.evm.input.rpc_failover]
enabled = true

[local_networks.solana.input.rpc_failover]
enabled = true
image = "nginx:1.27-alpine"
`))
	require.NoError(t, err)
	require.Len(t, configs, 2)
	require.Equal(t, util.OpaqueConfig{
		"rpc_failover": map[string]any{"enabled": true},
	}, configs["evm"].Input)
	require.Equal(t, util.OpaqueConfig{
		"rpc_failover": map[string]any{"enabled": true, "image": "nginx:1.27-alpine"},
	}, configs["solana"].Input)
}

func TestDecodeAbsentSection(t *testing.T) {
	t.Parallel()

	configs, err := Decode(nil)
	require.NoError(t, err)
	require.Empty(t, configs)
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	t.Parallel()

	_, err := Decode(rawSection(t, `
[local_networks.evm.input.rpc_failover]
enabled = true
`))
	require.ErrorContains(t, err, `missing "version"`)

	_, err = Decode(rawSection(t, `
[local_networks]
version = 99

[local_networks.evm.input.rpc_failover]
enabled = true
`))
	require.Error(t, err)
}

func TestValidateConfigRejectsFamilyWithoutConfigurator(t *testing.T) {
	t.Parallel()

	err := (&component{}).ValidateConfig(rawSection(t, `
[local_networks]
version = 1

[local_networks.not-a-chain-family.input.rpc_failover]
enabled = true
`))
	require.Error(t, err)
}

func TestConfigureAndFinalizeRoundTrip(t *testing.T) {
	const family = "localnetworks-component-test"
	var finalized bool
	require.NoError(t, chainreg.Register(family, chainreg.Registration{
		LocalNetworkConfigurator: func(
			_ context.Context,
			input util.OpaqueConfig,
			outputs []*blockchain.Output,
		) (util.OpaqueConfig, chainreg.LocalNetworkFinalizer, error) {
			require.Len(t, outputs, 1)
			return util.OpaqueConfig{"configured": true}, func() { finalized = true }, nil
		},
	}))

	globalConfig := map[string]any{
		Key: rawSection(t, `
[local_networks]
version = 1

[local_networks.`+family+`.input.rpc_failover]
enabled = true
`),
	}
	out, err := Configure(t.Context(), globalConfig, []*blockchain.Output{{Family: family}})
	require.NoError(t, err)

	configs, ok := out[Key].(map[string]*chainreg.LocalNetworkConfig)
	require.True(t, ok)
	require.Equal(t, util.OpaqueConfig{"configured": true}, configs[family].Output)
	require.False(t, finalized)

	Finalize(out)
	require.True(t, finalized)
	require.NotContains(t, out, FinalizersKey)
}

func TestConfigureIsANoOpWithoutSection(t *testing.T) {
	t.Parallel()

	out, err := Configure(t.Context(), map[string]any{}, nil)
	require.NoError(t, err)
	require.Nil(t, out)

	// Finalize must tolerate the output map of a run that configured nothing.
	Finalize(map[string]any{})
}
