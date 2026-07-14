package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testAppConfig struct {
	Name  string `toml:"name"`
	Value int    `toml:"value"`
}

func TestJobSpec_GetAppConfig(t *testing.T) {
	t.Run("decodes valid TOML into target struct", func(t *testing.T) {
		js := JobSpec{AppConfig: `
name = "my-service"
value = 42
`}
		var cfg testAppConfig
		require.NoError(t, js.GetAppConfig(&cfg))
		assert.Equal(t, "my-service", cfg.Name)
		assert.Equal(t, 42, cfg.Value)
	})

	t.Run("allows bootstrap-owned monitoring config", func(t *testing.T) {
		js := JobSpec{AppConfig: `
name = "my-service"
value = 42

[Monitoring]
Enabled = true
`}
		var cfg testAppConfig
		require.NoError(t, js.GetAppConfig(&cfg))
	})

	t.Run("rejects blockchain infos", func(t *testing.T) {
		js := JobSpec{AppConfig: `
name = "my-service"
value = 42

[blockchain_infos.5009297550715157269]
chain_id = "1"
`}
		var cfg struct {
			testAppConfig
			Legacy map[string]any `toml:"blockchain_infos"`
		}
		err := js.GetAppConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "blockchain_infos")
	})

	t.Run("returns error on invalid TOML", func(t *testing.T) {
		js := JobSpec{AppConfig: `not valid toml :::`}
		var cfg testAppConfig
		err := js.GetAppConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding app config")
	})

	t.Run("returns error for other undecoded keys", func(t *testing.T) {
		js := JobSpec{AppConfig: `
name = "svc"
value = 7
truck = "El Toro Loco"
`}
		var cfg testAppConfig
		err := js.GetAppConfig(&cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "undecoded keys: [truck]")
	})
}
