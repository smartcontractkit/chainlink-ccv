package chainaccess_test

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// concreteChainInfo is used to verify that the re-encoded "any" value from
// GenericConfig.GetConcreteConfig can be decoded into a concrete type.
type concreteChainInfo struct {
	ChainID         string `toml:"ChainID"`
	Type            string `toml:"Type"`
	Family          string `toml:"Family"`
	UniqueChainName string `toml:"UniqueChainName"`
}

func TestGenericConfig_GetConcreteConfig(t *testing.T) {
	t.Run("round-trips any back to concrete type", func(t *testing.T) {
		rawCfg := `
[on_ramp_addresses]
"123" = "0xOnRamp"

[rmn_remote_addresses]
"123" = "0xRMN"

[blockchain_infos."123"]
ChainID = "1"
Type = "evm"
Family = "evm"
UniqueChainName = "ethereum-mainnet"
`
		var gc chainaccess.GenericConfig
		_, err := toml.Decode(rawCfg, &gc)
		require.NoError(t, err)

		// GetConcreteConfig should marshal the any value to a concrete type.
		var concrete concreteChainInfo
		err = gc.GetConcreteConfig(protocol.ChainSelector(123), &concrete)
		require.NoError(t, err)
		assert.Equal(t, "1", concrete.ChainID)
		assert.Equal(t, "evm", concrete.Type)
		assert.Equal(t, "evm", concrete.Family)
		assert.Equal(t, "ethereum-mainnet", concrete.UniqueChainName)
	})

	t.Run("round-trips nested fields", func(t *testing.T) {
		type nestedInfo struct {
			Name  string   `toml:"Name"`
			Nodes []string `toml:"Nodes"`
		}

		rawCfg := `
[blockchain_infos."456"]
Name = "stellar"
Nodes = ["node1.example.com", "node2.example.com"]
`
		var gc chainaccess.GenericConfig
		_, err := toml.Decode(rawCfg, &gc)
		require.NoError(t, err)

		var concrete nestedInfo
		err = gc.GetConcreteConfig(protocol.ChainSelector(456), &concrete)
		require.NoError(t, err)
		assert.Equal(t, "stellar", concrete.Name)
		assert.Equal(t, []string{"node1.example.com", "node2.example.com"}, concrete.Nodes)
	})

	t.Run("selector not found returns error", func(t *testing.T) {
		rawCfg := `
[blockchain_infos."123"]
ChainID = "1"
`
		var gc chainaccess.GenericConfig
		_, err := toml.Decode(rawCfg, &gc)
		require.NoError(t, err)

		err = gc.GetConcreteConfig(protocol.ChainSelector(999), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("empty blockchain_infos returns error", func(t *testing.T) {
		gc := chainaccess.GenericConfig{}
		err := gc.GetConcreteConfig(protocol.ChainSelector(1), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("marshal error when chain info contains un-marshalable value", func(t *testing.T) {
		// A channel cannot be represented in TOML, so toml.Marshal will return an error.
		gc := chainaccess.GenericConfig{
			ChainConfig: chainaccess.Infos[any]{
				"123": make(chan int),
			},
		}
		err := gc.GetConcreteConfig(protocol.ChainSelector(123), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal info")
	})

	t.Run("returns error when config contains fields unknown to the target type", func(t *testing.T) {
		gc := chainaccess.GenericConfig{
			ChainConfig: chainaccess.Infos[any]{
				"123": map[string]any{
					"KnownField":   "hello",
					"UnknownField": "surprise",
				},
			},
		}
		type strictTarget struct {
			KnownField string `toml:"KnownField"`
		}
		var target strictTarget
		err := gc.GetConcreteConfig(protocol.ChainSelector(123), &target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown fields")
	})

	t.Run("decode error when target type is incompatible with marshaled TOML", func(t *testing.T) {
		// Store an array value so the marshaled TOML contains an array field.
		// Decoding that array into an int target field causes a type-mismatch error.
		gc := chainaccess.GenericConfig{
			ChainConfig: chainaccess.Infos[any]{
				"123": map[string]any{
					"Items": []any{int64(1), int64(2), int64(3)},
				},
			},
		}
		type badTarget struct {
			Items int `toml:"Items"` // array cannot decode into int
		}
		var target badTarget
		err := gc.GetConcreteConfig(protocol.ChainSelector(123), &target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal info")
	})
}

// evmChainConfig holds EVM-specific fields — e.g. an HTTP RPC endpoint.
type evmChainConfig struct {
	RPCURL  string `toml:"RPCUrl"`
	ChainID int64  `toml:"ChainID"`
}

// solanaChainConfig holds Solana-specific fields — e.g. a WebSocket endpoint and cluster name.
type solanaChainConfig struct {
	WSEndpoint  string `toml:"WSEndpoint"`
	ClusterName string `toml:"ClusterName"`
}

func TestGenericConfig_GetAllConcreteConfig(t *testing.T) {
	evmSelector := protocol.ChainSelector(chainsel.ETHEREUM_MAINNET.Selector)
	solanaSelector := protocol.ChainSelector(chainsel.SOLANA_MAINNET.Selector)

	// Note: blockchain_infos keys are bare integers — no quotes.
	rawCfg := `
[blockchain_infos.` + evmSelector.String() + `]
RPCUrl = "https://mainnet.infura.io"
ChainID = 1

[blockchain_infos.` + solanaSelector.String() + `]
WSEndpoint = "wss://api.mainnet-beta.solana.com"
ClusterName = "mainnet-beta"
`
	var gc chainaccess.GenericConfig
	_, err := toml.Decode(rawCfg, &gc)
	require.NoError(t, err)

	t.Run("decodes EVM entries with EVM-specific shape", func(t *testing.T) {
		var result chainaccess.Infos[evmChainConfig]
		err := gc.GetAllConcreteConfig("evm", &result)
		require.NoError(t, err)

		require.Len(t, result, 1)
		info, ok := result[evmSelector.String()]
		require.True(t, ok, "expected evm selector to be present")
		assert.Equal(t, "https://mainnet.infura.io", info.RPCURL)
		assert.Equal(t, int64(1), info.ChainID)
	})

	t.Run("decodes Solana entries with Solana-specific shape", func(t *testing.T) {
		var result chainaccess.Infos[solanaChainConfig]
		err := gc.GetAllConcreteConfig("solana", &result)
		require.NoError(t, err)

		require.Len(t, result, 1)
		info, ok := result[solanaSelector.String()]
		require.True(t, ok, "expected solana selector to be present")
		assert.Equal(t, "wss://api.mainnet-beta.solana.com", info.WSEndpoint)
		assert.Equal(t, "mainnet-beta", info.ClusterName)
	})

	t.Run("returns empty map when no chains match the family", func(t *testing.T) {
		var result chainaccess.Infos[evmChainConfig]
		err := gc.GetAllConcreteConfig("aptos", &result)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("returns error when target is not a pointer to a map", func(t *testing.T) {
		var bad []evmChainConfig
		err := gc.GetAllConcreteConfig("evm", &bad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pointer to a map")
	})

	t.Run("returns error when target is not a pointer", func(t *testing.T) {
		bad := make(chainaccess.Infos[evmChainConfig])
		err := gc.GetAllConcreteConfig("evm", bad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pointer to a map")
	})

	t.Run("initialises a nil map automatically", func(t *testing.T) {
		var result chainaccess.Infos[evmChainConfig]
		err := gc.GetAllConcreteConfig("evm", &result)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result, 1)
	})

	t.Run("returns error when a selector key is not a recognised chain", func(t *testing.T) {
		// Selector 999999999999 is not in the chain-selectors library, so
		// GetSelectorFamily will fail, covering that error branch.
		gc := chainaccess.GenericConfig{
			ChainConfig: chainaccess.Infos[any]{
				"999999999999": map[string]any{"RPCUrl": "https://unknown"},
			},
		}
		var result chainaccess.Infos[evmChainConfig]
		err := gc.GetAllConcreteConfig("evm", &result)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get the chain selector family")
	})

	t.Run("returns error when a matched chain config cannot be decoded into the target type", func(t *testing.T) {
		// A channel value cannot be marshaled to TOML, so GetConcreteConfig will
		// return an error for the matching EVM chain, exercising that branch.
		gc := chainaccess.GenericConfig{
			ChainConfig: chainaccess.Infos[any]{
				evmSelector.String(): make(chan int),
			},
		}
		var result chainaccess.Infos[evmChainConfig]
		err := gc.GetAllConcreteConfig("evm", &result)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal info")
	})
}
