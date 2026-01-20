package shared

type NOPJobSpecs map[string]map[string]string

type MonitoringInput struct {
	Enabled  bool
	Type     string
	Beholder BeholderInput
}

type BeholderInput struct {
	InsecureConnection       bool
	CACertFile               string
	OtelExporterGRPCEndpoint string
	OtelExporterHTTPEndpoint string
	LogStreamingEnabled      bool
	MetricReaderInterval     int64
	TraceSampleRatio         float64
	TraceBatchTimeout        int64
}
