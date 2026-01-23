package shared

import (
	"fmt"
	"strings"
)

type NOPAlias string

// NOPJobSpecs maps NOP alias -> job spec ID -> job spec content.
type NOPJobSpecs map[NOPAlias]map[JobID]string

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

type JobID string

type JobScope interface {
	// IsJobInScope returns a boolean value if the job is in the current scope.
	IsJobInScope(jobID JobID) bool
}

type ExecutorJobID struct {
	NOPAlias NOPAlias
	Scope    ExecutorJobScope
}

type ExecutorJobScope struct {
	ExecutorQualifier string
}

func NewExecutorJobID(nopAlias NOPAlias, scope ExecutorJobScope) ExecutorJobID {
	return ExecutorJobID{
		NOPAlias: nopAlias,
		Scope:    scope,
	}
}

func (id ExecutorJobID) ToJobID() JobID {
	return JobID(fmt.Sprintf("%s-%s-executor", string(id.NOPAlias), id.Scope.ExecutorQualifier))
}

func (id ExecutorJobID) GetExecutorID() string {
	return string(id.NOPAlias)
}

func (scope ExecutorJobScope) IsJobInScope(jobID JobID) bool {
	return strings.HasSuffix(string(jobID), fmt.Sprintf("-%s-executor", scope.ExecutorQualifier))
}

type VerifierJobScope struct {
	CommitteeQualifier string
}

type VerifierJobID struct {
	CommitteeQualifier string
	AggregatorName     string
}

func NewVerifierJobID(aggregatorName string, scope VerifierJobScope) VerifierJobID {
	return VerifierJobID{
		CommitteeQualifier: scope.CommitteeQualifier,
		AggregatorName:     aggregatorName,
	}
}

func (id VerifierJobID) GetVerifierID() string {
	return fmt.Sprintf("%s-%s-verifier", id.AggregatorName, id.CommitteeQualifier)
}

func (id VerifierJobID) ToJobID() JobID {
	return JobID(fmt.Sprintf("%s-%s-verifier", id.AggregatorName, id.CommitteeQualifier))
}

func (scope VerifierJobScope) IsJobInScope(jobID JobID) bool {
	return strings.HasSuffix(string(jobID), fmt.Sprintf("-%s-verifier", scope.CommitteeQualifier))
}

func ExtractJobIDFromJobSpecMap(jobSpecs NOPJobSpecs) []JobID {
	jobIDs := make([]JobID, 0)
	for _, jobSpec := range jobSpecs {
		for jobID := range jobSpec {
			jobIDs = append(jobIDs, jobID)
		}
	}
	return jobIDs
}

func ConvertNopAliasToString(aliases []NOPAlias) []string {
	str := make([]string, 0)
	for _, alias := range aliases {
		str = append(str, string(alias))
	}
	return str
}

func ConvertStringToNopAliases(strs []string) []NOPAlias {
	aliases := make([]NOPAlias, 0)
	for _, alias := range strs {
		aliases = append(aliases, NOPAlias(alias))
	}
	return aliases
}

func IsProductionEnvironment(env string) bool {
	return env == "mainnet"
}
