package observability

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func validConfig() map[string]any {
	return map[string]any{
		"version":       int64(1),
		"pyroscope_url": "http://host.docker.internal:4040",
		"monitoring": map[string]any{
			"Enabled": true,
			"Type":    "beholder",
			"Beholder": map[string]any{
				"InsecureConnection":       true,
				"OtelExporterHTTPEndpoint": "host.docker.internal:4318",
			},
		},
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	c := &component{}
	require.NoError(t, c.ValidateConfig(validConfig()))
}

func TestValidateConfig_RejectsWrongVersion(t *testing.T) {
	cfg := validConfig()
	cfg["version"] = int64(2)
	c := &component{}
	err := c.ValidateConfig(cfg)
	require.Error(t, err)
}

func TestRunPhase1_PublishesObservability(t *testing.T) {
	c := &component{}
	out, effects, err := c.RunPhase1(context.Background(), nil, validConfig())
	require.NoError(t, err)
	require.Nil(t, effects)

	obs, ok := out[configKey].(*Observability)
	require.True(t, ok, "output %q should be *Observability", configKey)
	require.Equal(t, "http://host.docker.internal:4040", obs.PyroscopeURL)
	require.True(t, obs.Monitoring.Enabled)
	require.Equal(t, "host.docker.internal:4318", obs.Monitoring.Beholder.OtelExporterHTTPEndpoint)
}
