package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

const blockchainInfoFragment = `
[blockchain_infos]
  [blockchain_infos.12922642891491394802]
    ChainID = "2337"
    Type = "anvil"
    Family = "evm"
    UniqueChainName = "blockchain-dst"

    [[blockchain_infos.12922642891491394802.Nodes]]
      ExternalHTTPUrl = "http://127.0.0.1:8555"
      InternalHTTPUrl = "http://blockchain-dst:8555"
      ExternalWSUrl = "ws://127.0.0.1:8555"
      InternalWSUrl = "ws://blockchain-dst:8555"
  [blockchain_infos.3379446385462418246]
    ChainID = "1337"
    Type = "anvil"
    Family = "evm"
    UniqueChainName = "blockchain-src"

    [[blockchain_infos.3379446385462418246.Nodes]]
      ExternalHTTPUrl = "http://127.0.0.1:8545"
      InternalHTTPUrl = "http://blockchain-src:8545"
      ExternalWSUrl = "ws://127.0.0.1:8545"
      InternalWSUrl = "ws://blockchain-src:8545"
  [blockchain_infos.4793464827907405086]
    ChainID = "3337"
    Type = "anvil"
    Family = "evm"
    UniqueChainName = "blockchain-3rd"

    [[blockchain_infos.4793464827907405086.Nodes]]
      ExternalHTTPUrl = "http://127.0.0.1:8565"
      InternalHTTPUrl = "http://blockchain-3rd:8565"
      ExternalWSUrl = "ws://127.0.0.1:8565"
      InternalWSUrl = "ws://blockchain-3rd:8565"
`

type testAppConfig struct {
	Name  string `toml:"name"`
	Value int    `toml:"value"`
}

func TestJobSpec_GetGenericConfig(t *testing.T) {
	t.Run("decodes known GenericConfig fields", func(t *testing.T) {
		js := JobSpec{
			AppConfig: `
[on_ramp_addresses]
"3379446385462418246" = "0xOnRamp"

[rmn_remote_addresses]
"3379446385462418246" = "0xRMN"
` + blockchainInfoFragment,
		}
		gcfg, err := js.GetGenericConfig()
		require.NoError(t, err)
		assert.Equal(t, "0xOnRamp", gcfg.OnRampAddresses["3379446385462418246"])
		assert.Equal(t, "0xRMN", gcfg.RMNRemoteAddresses["3379446385462418246"])
		assert.Contains(t, gcfg.ChainConfig, "3379446385462418246")
	})

	t.Run("ignores app-specific keys not in GenericConfig", func(t *testing.T) {
		js := JobSpec{
			AppConfig: `unknown_key = "ignored"` + "\n" + blockchainInfoFragment,
		}
		_, err := js.GetGenericConfig()
		require.NoError(t, err)
	})

	t.Run("returns error on invalid TOML", func(t *testing.T) {
		js := JobSpec{AppConfig: `not valid toml :::`}
		_, err := js.GetGenericConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding app config")
	})

	t.Run("empty app config decodes to empty GenericConfig", func(t *testing.T) {
		js := JobSpec{AppConfig: ``}
		gcfg, err := js.GetGenericConfig()
		require.NoError(t, err)
		assert.IsType(t, chainaccess.GenericConfig{}, gcfg)
	})
}

func TestJobSpec_GetAppConfig(t *testing.T) {
	t.Run("decodes valid TOML into target struct", func(t *testing.T) {
		js := JobSpec{
			AppConfig: `
name  = "my-service"
value = 42
` + blockchainInfoFragment,
		}
		var cfg testAppConfig
		err := js.GetAppConfig(&cfg)
		require.NoError(t, err)
		assert.Equal(t, "my-service", cfg.Name)
		assert.Equal(t, 42, cfg.Value)
	})

	t.Run("returns error on invalid TOML", func(t *testing.T) {
		js := JobSpec{
			AppConfig: `not valid toml :::`,
		}
		var cfg testAppConfig
		err := js.GetAppConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding app config")
	})

	t.Run("error if undecoded keys", func(t *testing.T) {
		js := JobSpec{
			AppConfig: `
name    = "svc"
value   = 7
truck = "El Toro Loco"
` + blockchainInfoFragment,
		}
		var cfg testAppConfig
		err := js.GetAppConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "undecoded keys: [truck]")
	})
}
