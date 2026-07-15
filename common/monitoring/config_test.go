package monitoring

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestConfig_decodeNewBootstrapMonitoring(t *testing.T) {
	const newMonitoring = `
LogLevel = "info"

[Beholder]
Enabled = true
InsecureConnection = true
OtelExporterGRPCEndpoint = "localhost:4317"
LogStreamingEnabled = true
MetricReaderInterval = 5
TraceSampleRatio = 1.0
TraceBatchTimeout = 10
`
	var cfg Config
	_, err := toml.Decode(newMonitoring, &cfg)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.Beholder.Enabled)
}
