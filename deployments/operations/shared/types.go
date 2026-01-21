package shared

// NOPJobSpecs maps NOP alias -> job spec ID -> job spec content.
type NOPJobSpecs map[string]map[string]string

// MonitoringInput defines the monitoring configuration.
type MonitoringInput struct {
	// Enabled indicates whether monitoring is enabled.
	Enabled bool
	// Type specifies the monitoring backend type (e.g., "beholder").
	Type string
	// Beholder contains Beholder-specific monitoring settings.
	Beholder BeholderInput
}

// BeholderInput defines the Beholder monitoring configuration.
type BeholderInput struct {
	// InsecureConnection disables TLS verification when connecting to Beholder.
	InsecureConnection bool
	// CACertFile is the path to the CA certificate file for TLS verification.
	CACertFile string
	// OtelExporterGRPCEndpoint is the gRPC endpoint for OpenTelemetry export.
	OtelExporterGRPCEndpoint string
	// OtelExporterHTTPEndpoint is the HTTP endpoint for OpenTelemetry export.
	OtelExporterHTTPEndpoint string
	// LogStreamingEnabled enables streaming logs to Beholder.
	LogStreamingEnabled bool
	// MetricReaderInterval is the interval in seconds for reading metrics.
	MetricReaderInterval int64
	// TraceSampleRatio is the sampling ratio for traces (0.0-1.0).
	TraceSampleRatio float64
	// TraceBatchTimeout is the timeout in seconds for batching traces.
	TraceBatchTimeout int64
}
