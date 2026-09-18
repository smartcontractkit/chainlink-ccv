package monitoring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// validBeholderConfig returns an enabled beholder config whose Validate() passes.
func validBeholderConfig() BeholderConfig {
	return BeholderConfig{
		Enabled:                  true,
		InsecureConnection:       true,
		OtelExporterGRPCEndpoint: "otel-collector:4317",
		MetricReaderInterval:     10,
		TraceSampleRatio:         1.0,
		TraceBatchTimeout:        5,
	}
}

func TestBeholderConfigValidate(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validBeholderConfig().Validate())
	})

	t.Run("chip ingress endpoint with gRPC exporter", func(t *testing.T) {
		t.Parallel()
		cfg := validBeholderConfig()
		cfg.ChipIngressEndpoint = "chip-ingress:9090"
		cfg.ChipIngressInsecureConnection = true
		require.NoError(t, cfg.Validate())
	})

	t.Run("chip ingress endpoint requires gRPC exporter", func(t *testing.T) {
		t.Parallel()
		cfg := validBeholderConfig()
		cfg.OtelExporterGRPCEndpoint = ""
		cfg.OtelExporterHTTPEndpoint = "otel-collector:4318"
		cfg.ChipIngressEndpoint = "chip-ingress:9090"
		require.ErrorContains(t, cfg.Validate(), "chip_ingress_endpoint requires otel_exporter_grpc_endpoint")
	})

	t.Run("invalid log streaming level", func(t *testing.T) {
		t.Parallel()
		cfg := validBeholderConfig()
		cfg.LogStreamingLevel = "not-a-level"
		require.ErrorContains(t, cfg.Validate(), "log_streaming_level")
	})

	t.Run("non-positive metric reader interval", func(t *testing.T) {
		t.Parallel()
		cfg := validBeholderConfig()
		cfg.MetricReaderInterval = 0
		require.ErrorContains(t, cfg.Validate(), "metric_reader_interval")
	})

	t.Run("trace sample ratio out of range", func(t *testing.T) {
		t.Parallel()
		cfg := validBeholderConfig()
		cfg.TraceSampleRatio = 1.5
		require.ErrorContains(t, cfg.Validate(), "trace_sample_ratio")
	})
}
