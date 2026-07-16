package observability

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func validConfig() map[string]any {
	return map[string]any{
		"version": int64(1),
		"monitoring": map[string]any{
			"LogLevel": "info",
			"Pyroscope": map[string]any{
				"Enabled": true,
				"URL":     "http://host.docker.internal:4040",
			},
			"Beholder": map[string]any{
				"Enabled":                  true,
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

	obs, ok := out[Key].(*Observability)
	require.True(t, ok, "output %q should be *Observability", Key)
	require.True(t, obs.Monitoring.Pyroscope.Enabled)
	require.Equal(t, "http://host.docker.internal:4040", obs.Monitoring.Pyroscope.URL)
	require.True(t, obs.Monitoring.Beholder.Enabled)
	require.Equal(t, "host.docker.internal:4318", obs.Monitoring.Beholder.OtelExporterHTTPEndpoint)
}
