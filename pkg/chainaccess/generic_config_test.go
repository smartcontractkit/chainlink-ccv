package chainaccess_test

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
